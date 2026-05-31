#!/usr/bin/env python3
"""
Normalize MobSF reports into our_scanner-like JSON.

Expected input files per APK:
    MASTG-TEST0007_mobsf.json
    MASTG-TEST0007_mobsf_findings.json
    MASTG-TEST0007_mobsf_summary.md

Priority:
    1. Prefer raw MobSF JSON: *_mobsf.json
    2. Use *_mobsf_findings.json only as fallback
    3. Use *_mobsf_summary.md only for package/app name fallback

Example:
    python normalize_mobsf.py \
      --input-dir ./reports/mobsf_raw/Platform \
      --out-dir ./reports/normalized/mobsf/Platform
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "warning": "Medium",
    "medium": "Medium",
    "info": "Low",
    "low": "Low",
    "secure": "Low",
}

SEVERITY_SCORE = {
    "Critical": 9,
    "High": 7,
    "Medium": 5,
    "Low": 2,
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def normalize_severity(value: Any) -> str:
    raw = safe_str(value).strip().lower()
    return SEVERITY_MAP.get(raw, "Low")


def severity_score(severity: str) -> int:
    return SEVERITY_SCORE.get(severity, 2)


def slugify(value: str) -> str:
    value = value.upper()
    value = re.sub(r"[^A-Z0-9]+", "_", value)
    return value.strip("_") or "UNKNOWN"


def clamp_score(value: int) -> int:
    return max(1, min(10, value))


def parse_possible_dict_string(value: Any) -> Any:
    """
    Some *_mobsf_findings.json stores evidence as a Python-dict-like string.
    Try to recover it. If it is truncated or invalid, return original string.
    """
    if not isinstance(value, str):
        return value

    text = value.strip()
    if not text:
        return value

    if not (
        text.startswith("{")
        or text.startswith("[")
        or text.startswith("(")
    ):
        return value

    try:
        return ast.literal_eval(text)
    except Exception:
        return value


def extract_md_field(md_text: str, field: str) -> str | None:
    pattern = rf"-\s*{re.escape(field)}:\s*`([^`]+)`"
    match = re.search(pattern, md_text)
    if match:
        return match.group(1).strip()
    return None


def infer_case_id(path: Path) -> str:
    name = path.name

    for suffix in (
        "_mobsf_findings.json",
        "_mobsf_summary.md",
        "_mobsf.json",
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)]

    return path.stem


# ---------------------------------------------------------------------------
# Normalized finding construction
# ---------------------------------------------------------------------------

def make_finding(
    *,
    pattern_id: str,
    title: str,
    severity: str,
    description: str = "",
    category: str | None = None,
    location: str | None = None,
    evidence: list[str] | None = None,
    related_components: list[str] | None = None,
    related_deep_links: list[str] | None = None,
    cwe: str | None = None,
    owasp_masvs: str | None = None,
    confidence_score: int = 6,
    raw: Any = None,
) -> dict[str, Any]:
    normalized_sev = normalize_severity(severity)

    return {
        "pattern_id": pattern_id,
        "title": title,
        "severity": normalized_sev,
        "description": description or "",
        "severity_score": severity_score(normalized_sev),
        "confidence_score": clamp_score(confidence_score),
        "category": category,
        "location": location,
        "evidence": evidence or [],
        "related_components": related_components or [],
        "related_deep_links": related_deep_links or [],
        "cwe": cwe,
        "owasp_masvs": owasp_masvs,
        "source": "mobsf",
        "raw": raw,
    }


def classify_manifest_category(rule: str, title: str, component: Any) -> str:
    text = f"{rule} {title} {safe_str(component)}".lower()

    if "content provider" in text or "provider" in text:
        return "exported_provider"

    if "activity" in text:
        return "exported_activity"

    if "receiver" in text or "broadcast receiver" in text:
        return "exported_receiver"

    if "service" in text:
        return "exported_service"

    if "permission" in text:
        return "permission"

    if "vulnerable_os_version" in text or "minsdk" in text:
        return "platform_version"

    return "manifest"


def extract_component_names(component: Any) -> list[str]:
    if not isinstance(component, list):
        return []

    names: list[str] = []

    for item in component:
        if not isinstance(item, str):
            continue

        cleaned = re.sub(r"<[^>]+>", "", item).strip()

        # rough Java/Kotlin class pattern
        if "." in cleaned and " " not in cleaned and "/" not in cleaned:
            names.append(cleaned)

    return names


def normalize_manifest_findings(raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    manifest = raw_report.get("manifest_analysis") or {}
    findings = manifest.get("manifest_findings") or []

    if not isinstance(findings, list):
        return output

    for item in findings:
        if not isinstance(item, dict):
            continue

        rule = safe_str(item.get("rule") or "manifest")
        title = safe_str(item.get("title") or item.get("name") or rule)
        sev = safe_str(item.get("severity") or "info")
        desc = safe_str(item.get("description") or "")
        component = item.get("component")

        category = classify_manifest_category(rule, title, component)
        related_components = extract_component_names(component)

        evidence = [
            f"rule={rule}",
            f"title={title}",
        ]

        if component:
            evidence.append(f"component={safe_str(component)}")

        if desc:
            evidence.append(f"description={desc}")

        confidence = 7

        if category.startswith("exported_"):
            confidence = 8

        if category == "platform_version":
            confidence = 9

        output.append(
            make_finding(
                pattern_id="MOBSF_MANIFEST_" + slugify(rule),
                title=title,
                severity=sev,
                description=desc,
                category=category,
                location="AndroidManifest.xml",
                evidence=evidence,
                related_components=related_components,
                confidence_score=confidence,
                raw=item,
            )
        )

    return output


def normalize_certificate_findings(raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    cert = raw_report.get("certificate_analysis") or {}
    findings = cert.get("certificate_findings") or []

    if not isinstance(findings, list):
        return output

    for item in findings:
        # MobSF format:
        # ["high", "description", "title"]
        if not isinstance(item, list) or len(item) < 3:
            continue

        sev = safe_str(item[0])
        desc = safe_str(item[1])
        title = safe_str(item[2])

        evidence = [
            f"title={title}",
            f"description={desc}",
        ]

        output.append(
            make_finding(
                pattern_id="MOBSF_CERTIFICATE_" + slugify(title),
                title=title,
                severity=sev,
                description=desc,
                category="certificate",
                location="APK signature",
                evidence=evidence,
                confidence_score=8,
                raw=item,
            )
        )

    return output


def normalize_code_analysis_findings(raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    code = raw_report.get("code_analysis") or {}
    findings = code.get("findings") or {}

    if not isinstance(findings, dict):
        return output

    for rule, item in findings.items():
        if not isinstance(item, dict):
            continue

        files = item.get("files") or {}
        metadata = item.get("metadata") or {}

        if not isinstance(files, dict):
            files = {}

        if not isinstance(metadata, dict):
            metadata = {}

        title = safe_str(metadata.get("description") or rule)
        sev = safe_str(metadata.get("severity") or "info")
        cwe = safe_str(metadata.get("cwe") or "") or None
        masvs = safe_str(metadata.get("masvs") or "") or None
        desc = safe_str(metadata.get("description") or "")

        category = classify_code_category(rule, title, metadata)

        evidence = [
            f"rule={rule}",
            f"description={desc}",
        ]

        if cwe:
            evidence.append(f"cwe={cwe}")

        if masvs:
            evidence.append(f"masvs={masvs}")

        for file_path, lines in list(files.items())[:10]:
            evidence.append(f"{file_path}:{lines}")

        # Use first file as location for evaluation matching.
        location = None
        if files:
            first_file = next(iter(files.keys()))
            location = safe_str(first_file)

        confidence = 6

        if files:
            confidence += 1

        # MobSF hardcoded findings on third-party libraries are often noisy.
        if category == "hardcoded_secret":
            confidence = 5

        if category == "sql_injection":
            confidence = 7

        output.append(
            make_finding(
                pattern_id="MOBSF_CODE_" + slugify(rule),
                title=title,
                severity=sev,
                description=desc,
                category=category,
                location=location,
                evidence=evidence,
                cwe=cwe,
                owasp_masvs=masvs,
                confidence_score=confidence,
                raw=item,
            )
        )

    return output


def classify_code_category(rule: str, title: str, metadata: dict[str, Any]) -> str:
    text = f"{rule} {title} {safe_str(metadata)}".lower()

    if "hardcoded" in text or "password" in text or "key" in text or "secret" in text:
        return "hardcoded_secret"

    if "sql" in text or "raw_query" in text or "injection" in text:
        return "sql_injection"

    if "log" in text:
        return "logging"

    if "webview" in text:
        return "webview"

    if "file" in text or "storage" in text:
        return "storage"

    return "code_analysis"


def normalize_android_api(raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    api = raw_report.get("android_api") or {}

    if not isinstance(api, dict):
        return output

    for rule, item in api.items():
        if not isinstance(item, dict):
            continue

        files = item.get("files") or {}
        metadata = item.get("metadata") or {}

        if not isinstance(files, dict):
            files = {}

        if not isinstance(metadata, dict):
            metadata = {}

        desc = safe_str(metadata.get("description") or rule)
        sev = safe_str(metadata.get("severity") or "info")

        evidence = [
            f"rule={rule}",
            f"description={desc}",
        ]

        for file_path, lines in list(files.items())[:10]:
            evidence.append(f"{file_path}:{lines}")

        location = None
        if files:
            location = safe_str(next(iter(files.keys())))

        output.append(
            make_finding(
                pattern_id="MOBSF_ANDROID_API_" + slugify(rule),
                title=desc,
                severity=sev,
                description=desc,
                category="android_api",
                location=location,
                evidence=evidence,
                confidence_score=6 if files else 4,
                raw=item,
            )
        )

    return output


def normalize_urls(raw_report: dict[str, Any], include_urls: bool) -> list[dict[str, Any]]:
    if not include_urls:
        return []

    output: list[dict[str, Any]] = []

    urls = raw_report.get("urls") or []

    if not isinstance(urls, list):
        return output

    for item in urls:
        if not isinstance(item, dict):
            continue

        url_list = item.get("urls") or []
        path = safe_str(item.get("path") or "")

        if not isinstance(url_list, list):
            url_list = [url_list]

        title = "URL found"
        evidence = [
            f"urls={safe_str(url_list)}",
            f"path={path}",
        ]

        output.append(
            make_finding(
                pattern_id="MOBSF_URL_FOUND",
                title=title,
                severity="low",
                description="MobSF found URL strings in the decompiled code.",
                category="url",
                location=path or None,
                evidence=evidence,
                confidence_score=4,
                raw=item,
            )
        )

    return output


# ---------------------------------------------------------------------------
# Fallback for *_mobsf_findings.json
# ---------------------------------------------------------------------------

def normalize_fallback_findings(findings_data: Any) -> list[dict[str, Any]]:
    """
    Fallback parser for *_mobsf_findings.json.

    This file often contains:
        [
          {
            "category": "...",
            "title": "...",
            "severity": "...",
            "evidence": "..."
          }
        ]

    Evidence may be a truncated Python-dict-like string.
    """
    output: list[dict[str, Any]] = []

    if not isinstance(findings_data, list):
        return output

    for item in findings_data:
        if not isinstance(item, dict):
            continue

        raw_category = safe_str(item.get("category") or "unknown")
        title = safe_str(item.get("title") or raw_category)
        sev = safe_str(item.get("severity") or "low")

        parsed_evidence = parse_possible_dict_string(item.get("evidence"))
        evidence = [f"evidence={safe_str(parsed_evidence)}"]

        category = raw_category

        if raw_category == "manifest":
            category = "manifest"
        elif raw_category == "code_analysis":
            category = "code_analysis"
        elif raw_category == "url":
            category = "url"

        output.append(
            make_finding(
                pattern_id="MOBSF_FALLBACK_" + slugify(f"{raw_category}_{title}"),
                title=title,
                severity=sev,
                description="Finding extracted from pre-flattened MobSF findings file.",
                category=category,
                location=None,
                evidence=evidence,
                confidence_score=4,
                raw=item,
            )
        )

    return output


# ---------------------------------------------------------------------------
# Case collection / output
# ---------------------------------------------------------------------------

def collect_cases(input_dir: Path) -> dict[str, dict[str, Path]]:
    cases: dict[str, dict[str, Path]] = {}

    for path in input_dir.rglob("*"):
        if not path.is_file():
            continue

        name = path.name

        if name.endswith("_mobsf.json"):
            case_id = infer_case_id(path)
            cases.setdefault(case_id, {})["raw"] = path

        elif name.endswith("_mobsf_findings.json"):
            case_id = infer_case_id(path)
            cases.setdefault(case_id, {})["findings"] = path

        elif name.endswith("_mobsf_summary.md"):
            case_id = infer_case_id(path)
            cases.setdefault(case_id, {})["summary_md"] = path

    return cases


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []

    for finding in findings:
        key = (
            safe_str(finding.get("pattern_id")),
            safe_str(finding.get("title")),
            safe_str(finding.get("location")),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(finding)

    return output


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "vulnerability_count": len(findings),
        "attack_chain_count": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "medium_vulns": 0,
        "low_vulns": 0,
        "high_confidence_vulns": 0,
        "high_severity_vulns": 0,
        "high_severity_high_confidence_vulns": 0,
    }

    for finding in findings:
        sev = safe_str(finding.get("severity"))

        if sev == "Critical":
            summary["critical_vulns"] += 1
        elif sev == "High":
            summary["high_vulns"] += 1
        elif sev == "Medium":
            summary["medium_vulns"] += 1
        elif sev == "Low":
            summary["low_vulns"] += 1

        sev_score = int(finding.get("severity_score") or 0)
        conf_score = int(finding.get("confidence_score") or 0)

        if conf_score >= 8:
            summary["high_confidence_vulns"] += 1

        if sev_score >= 8:
            summary["high_severity_vulns"] += 1

        if sev_score >= 8 and conf_score >= 8:
            summary["high_severity_high_confidence_vulns"] += 1

    return summary


def build_meta(
    *,
    case_id: str,
    raw_report: dict[str, Any],
    md_text: str,
) -> dict[str, Any]:
    package_name = (
        safe_str(raw_report.get("package_name"))
        or safe_str(raw_report.get("package"))
        or safe_str(raw_report.get("packagename"))
        or extract_md_field(md_text, "Package")
        or ""
    )

    app_name = (
        safe_str(raw_report.get("app_name"))
        or safe_str(raw_report.get("appname"))
        or extract_md_field(md_text, "App name")
        or case_id
    )

    return {
        "package_name": package_name,
        "apk_path": safe_str(raw_report.get("file_name") or f"{case_id}.apk"),
        "app_name": app_name,
        "version_name": safe_str(raw_report.get("version_name") or "") or None,
        "version_code": safe_str(raw_report.get("version_code") or "") or None,
        "min_sdk": try_int(raw_report.get("min_sdk")),
        "target_sdk": try_int(raw_report.get("target_sdk")),
        "main_activity": safe_str(raw_report.get("main_activity") or "") or None,
        "md5": safe_str(raw_report.get("md5") or "") or None,
        "sha1": safe_str(raw_report.get("sha1") or "") or None,
        "sha256": safe_str(raw_report.get("sha256") or "") or None,
    }


def try_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_case(
    case_id: str,
    files: dict[str, Path],
    include_urls: bool,
    use_fallback_findings: bool,
) -> dict[str, Any]:
    raw_report: dict[str, Any] = {}

    if "raw" in files:
        loaded = load_json(files["raw"])
        if isinstance(loaded, dict):
            raw_report = loaded

    fallback_data: Any = []
    if "findings" in files:
        try:
            fallback_data = load_json(files["findings"])
        except Exception:
            fallback_data = []

    md_text = ""
    if "summary_md" in files:
        md_text = files["summary_md"].read_text(
            encoding="utf-8",
            errors="replace",
        )

    findings: list[dict[str, Any]] = []

    if raw_report:
        findings.extend(normalize_manifest_findings(raw_report))
        findings.extend(normalize_certificate_findings(raw_report))
        findings.extend(normalize_code_analysis_findings(raw_report))
        findings.extend(normalize_android_api(raw_report))
        findings.extend(normalize_urls(raw_report, include_urls=include_urls))

    # Only use fallback if raw report produced nothing, or user explicitly asks.
    if use_fallback_findings or not findings:
        findings.extend(normalize_fallback_findings(fallback_data))

    findings = deduplicate(findings)

    # Sort similarly to our_scanner: severity_score desc, confidence_score desc
    findings.sort(
        key=lambda f: (
            -(f.get("severity_score") or 0),
            -(f.get("confidence_score") or 0),
            safe_str(f.get("pattern_id")),
        )
    )

    return {
        "tool": "mobsf",
        "case_id": case_id,
        "meta": build_meta(case_id=case_id, raw_report=raw_report, md_text=md_text),
        "components": [],
        "deep_links": [],
        "custom_permissions": {},
        "vulnerabilities": findings,
        "attack_chains": [],
        "summary": build_summary(findings),
        "source_files": {
            key: str(path)
            for key, path in files.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize MobSF reports into our_scanner-like JSON.",
    )

    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing MobSF output files.",
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory to write normalized JSON files.",
    )

    parser.add_argument(
        "--include-urls",
        action="store_true",
        help="Include MobSF URL findings. Usually noisy for vulnerability evaluation.",
    )

    parser.add_argument(
        "--use-fallback-findings",
        action="store_true",
        help="Also include *_mobsf_findings.json entries. Usually unnecessary if *_mobsf.json exists.",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)

    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    cases = collect_cases(input_dir)

    if not cases:
        print(f"No MobSF files found in {input_dir}")
        return 1

    for case_id, files in sorted(cases.items()):
        normalized = normalize_case(
            case_id=case_id,
            files=files,
            include_urls=args.include_urls,
            use_fallback_findings=args.use_fallback_findings,
        )

        out_path = out_dir / f"{case_id}.json"
        out_path.write_text(
            json.dumps(normalized, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print(
            f"[OK] {case_id}: "
            f"{normalized['summary']['vulnerability_count']} findings -> {out_path}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())