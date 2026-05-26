#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path

import requests


def upload_apk(server, api_key, apk_path):
    url = f"{server}/api/v1/upload"
    headers = {"Authorization": api_key}

    with open(apk_path, "rb") as f:
        files = {"file": (apk_path.name, f, "application/vnd.android.package-archive")}
        r = requests.post(url, headers=headers, files=files, timeout=120)

    r.raise_for_status()
    return r.json()


def scan_apk(server, api_key, file_hash, file_name, rescan=0):
    url = f"{server}/api/v1/scan"
    headers = {"Authorization": api_key}
    data = {
        "hash": file_hash,
        "scan_type": "apk",
        "file_name": file_name,
        "re_scan": str(rescan),
    }

    r = requests.post(url, headers=headers, data=data, timeout=600)
    r.raise_for_status()
    return r.json()


def get_json_report(server, api_key, file_hash):
    url = f"{server}/api/v1/report_json"
    headers = {"Authorization": api_key}
    data = {"hash": file_hash}

    r = requests.post(url, headers=headers, data=data, timeout=120)
    r.raise_for_status()
    return r.json()


def extract_simple_findings(mobsf_json):
    """
    把 MobSF 的大 JSON 粗略整理成 evaluation 方便看的格式。
    這裡先抓常見欄位，之後你可以依照實際 JSON 結構再補。
    """
    findings = []

    # 1. Permissions
    permissions = mobsf_json.get("permissions", {})
    if isinstance(permissions, dict):
        for perm, info in permissions.items():
            status = ""
            description = ""

            if isinstance(info, dict):
                status = str(info.get("status", ""))
                description = str(info.get("description", ""))
            else:
                description = str(info)

            if "dangerous" in status.lower():
                findings.append({
                    "category": "dangerous_permission",
                    "title": perm,
                    "severity": "medium",
                    "evidence": description,
                })

    # 2. Manifest analysis
    manifest_analysis = mobsf_json.get("manifest_analysis", {})
    if isinstance(manifest_analysis, dict):
        for key, value in manifest_analysis.items():
            findings.append({
                "category": "manifest",
                "title": str(key),
                "severity": "info",
                "evidence": str(value)[:500],
            })

    # 3. Code analysis
    code_analysis = mobsf_json.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        for rule_name, result in code_analysis.items():
            findings.append({
                "category": "code_analysis",
                "title": str(rule_name),
                "severity": "medium",
                "evidence": str(result)[:500],
            })

    # 4. Hardcoded secrets / Firebase / URLs 等可以之後再補
    urls = mobsf_json.get("urls", [])
    if isinstance(urls, list):
        for url in urls:
            findings.append({
                "category": "url",
                "title": "URL found",
                "severity": "low",
                "evidence": str(url),
            })

    return findings


def write_summary_md(apk_path, mobsf_json, findings, out_md):
    app_name = mobsf_json.get("app_name", apk_path.stem)
    package_name = mobsf_json.get("package_name", "unknown")
    score = mobsf_json.get("security_score", "N/A")

    lines = []
    lines.append(f"# MobSF Report Summary: {apk_path.name}")
    lines.append("")
    lines.append(f"- App name: `{app_name}`")
    lines.append(f"- Package: `{package_name}`")
    lines.append(f"- Security score: `{score}`")
    lines.append(f"- Total extracted findings: `{len(findings)}`")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Category | Title | Severity | Evidence |")
    lines.append("|---|---|---|---|")

    for f in findings:
        evidence = str(f.get("evidence", "")).replace("\n", " ").replace("|", "\\|")
        if len(evidence) > 160:
            evidence = evidence[:160] + "..."

        lines.append(
            f"| {f.get('category', '')} | {f.get('title', '')} | "
            f"{f.get('severity', '')} | {evidence} |"
        )

    out_md.write_text("\n".join(lines), encoding="utf-8")


def collect_apks(category, benchmark_root):
    benchmark_root = Path(benchmark_root)

    if category.upper() == "ALL":
        return sorted(benchmark_root.rglob("*.apk"))

    category_path = benchmark_root / category
    return sorted(category_path.rglob("*.apk"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("category", help="Benchmark category name or ALL")
    parser.add_argument("--benchmark-root", default="./benchmarks")
    parser.add_argument("--out-root", default="./reports/mobsf")
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--rescan", default="0")
    args = parser.parse_args()

    apks = collect_apks(args.category, args.benchmark_root)

    if not apks:
        raise SystemExit(f"[ERROR] No APK found for category: {args.category}")

    print(f"[INFO] Found {len(apks)} APK(s)")

    for apk_path in apks:
        apk_path = Path(apk_path)

        if args.category.upper() == "ALL":
            category_name = apk_path.parent.name
        else:
            category_name = args.category

        out_dir = Path(args.out_root) / category_name
        out_dir.mkdir(parents=True, exist_ok=True)

        out_json = out_dir / f"{apk_path.stem}_mobsf.json"
        out_findings = out_dir / f"{apk_path.stem}_mobsf_findings.json"
        out_md = out_dir / f"{apk_path.stem}_mobsf_summary.md"

        if out_json.exists() and args.rescan == "0":
            print(f"[SKIP] {apk_path.name} already scanned")
            continue

        print(f"[SCAN] {apk_path}")

        try:
            upload_result = upload_apk(args.server, args.api_key, apk_path)
            file_hash = upload_result.get("hash")

            if not file_hash:
                raise RuntimeError(f"MobSF upload response has no hash: {upload_result}")

            scan_result = scan_apk(
                args.server,
                args.api_key,
                file_hash,
                apk_path.name,
                rescan=args.rescan,
            )

            # 有時 scan response 已經是完整 report；保險起見再取一次 report_json
            time.sleep(1)
            report_json = get_json_report(args.server, args.api_key, file_hash)

            findings = extract_simple_findings(report_json)

            out_json.write_text(
                json.dumps(report_json, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            out_findings.write_text(
                json.dumps(findings, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            write_summary_md(apk_path, report_json, findings, out_md)

            print(f"[OK] Saved: {out_json}")

        except Exception as e:
            print(f"[ERROR] Failed to scan {apk_path}: {e}")


if __name__ == "__main__":
    main()