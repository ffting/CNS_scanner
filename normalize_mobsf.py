#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "info": "low",
    "secure": "info",
}


RULE_CATEGORY_MAP = {
    # Manifest
    "explicitly_exported": "exported_component",
    "exported_protected_permission_not_defined": "exported_component",
    "exported_without_permission": "exported_component",

    # SQL / Provider
    "android_sql_raw_query": "content_provider_sql_injection",

    # Code
    "android_hardcoded": "hardcoded_secret",
    "android_logging": "logging_sensitive_data",

    # WebView common MobSF rules, names may differ by version
    "android_webview": "webview",
    "android_webview_javascript": "webview_javascript_enabled",
    "android_webview_addjavascriptinterface": "webview_javascript_interface",

    # PendingIntent common names, may need adjustment after seeing reports
    "android_pending_intent": "pending_intent",
}


def normalize_severity(sev):
    if not sev:
        return "info"
    return SEVERITY_MAP.get(str(sev).lower(), "medium")


def confidence_from_source(source_type, severity):
    """
    粗略規則：
    - manifest finding 通常 evidence 明確，confidence 高
    - code finding 有檔案和 rule，但不一定證明可利用，confidence 中高
    """
    if source_type == "manifest":
        return 8
    if source_type == "code":
        return 7
    if severity in ["critical", "high"]:
        return 7
    return 5


def infer_category_from_manifest_finding(finding):
    rule = str(finding.get("rule", "")).lower()
    title = str(finding.get("title", "")).lower()
    name = str(finding.get("name", "")).lower()

    text = f"{rule} {title} {name}"

    if "content provider" in text and "exported=true" in text:
        return "exported_provider"
    if "activity" in text and "exported=true" in text:
        return "exported_activity"
    if "service" in text and "exported=true" in text:
        return "exported_service"
    if "receiver" in text and "exported=true" in text:
        return "exported_receiver"
    if "deep link" in text or "browsable" in text:
        return "insecure_deep_link"

    return RULE_CATEGORY_MAP.get(rule, "manifest_issue")


def normalize_manifest_findings(data):
    findings = []
    manifest = data.get("manifest_analysis", {})
    raw_findings = manifest.get("manifest_findings", [])

    if not isinstance(raw_findings, list):
        return findings

    for item in raw_findings:
        category = infer_category_from_manifest_finding(item)
        severity = normalize_severity(item.get("severity"))

        findings.append({
            "category": category,
            "title": item.get("title") or item.get("name") or item.get("rule"),
            "severity": severity,
            "confidence": confidence_from_source("manifest", severity),
            "evidence": item.get("description", ""),
            "file": "AndroidManifest.xml",
            "raw_rule": item.get("rule", ""),
            "source": "manifest_analysis.manifest_findings"
        })

    return findings


def infer_category_from_code_rule(rule, metadata):
    rule_lower = str(rule).lower()
    desc = str(metadata.get("description", "")).lower()
    cwe = str(metadata.get("cwe", "")).lower()

    if rule_lower == "android_sql_raw_query" or "sql injection" in desc or "cwe-89" in cwe:
        return "content_provider_sql_injection"

    if "hardcoded" in rule_lower or "hardcoded" in desc:
        return "hardcoded_secret"

    if "logging" in rule_lower or "log" in desc:
        return "logging_sensitive_data"

    if "webview" in rule_lower:
        if "javascript" in rule_lower or "javascript" in desc:
            return "webview_javascript_enabled"
        return "webview"

    if "pendingintent" in rule_lower or "pending intent" in desc:
        return "pending_intent"

    if "notification" in rule_lower or "notification" in desc:
        return "plaintext_notification"

    return RULE_CATEGORY_MAP.get(rule_lower, "code_issue")


def normalize_code_findings(data):
    findings = []
    code = data.get("code_analysis", {})
    raw_findings = code.get("findings", {})

    if not isinstance(raw_findings, dict):
        return findings

    for rule, item in raw_findings.items():
        metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
        files = item.get("files", {}) if isinstance(item, dict) else {}

        category = infer_category_from_code_rule(rule, metadata)
        severity = normalize_severity(metadata.get("severity"))

        if isinstance(files, dict) and files:
            file_evidence = "; ".join(
                f"{file}:{lines}" for file, lines in list(files.items())[:5]
            )
        else:
            file_evidence = ""

        desc = metadata.get("description", "")

        findings.append({
            "category": category,
            "title": rule,
            "severity": severity,
            "confidence": confidence_from_source("code", severity),
            "evidence": f"{desc} {file_evidence}".strip(),
            "file": file_evidence,
            "raw_rule": rule,
            "source": "code_analysis.findings"
        })

    return findings


def normalize_android_api(data):
    findings = []
    api = data.get("android_api", {})

    if not isinstance(api, dict):
        return findings

    for rule, item in api.items():
        metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
        files = item.get("files", {}) if isinstance(item, dict) else {}

        rule_lower = str(rule).lower()

        if "content_provider" in rule_lower:
            category = "content_provider_usage"
        elif "file_io" in rule_lower:
            category = "local_file_io"
        else:
            category = "api_usage"

        severity = normalize_severity(metadata.get("severity", "info"))

        if isinstance(files, dict) and files:
            file_evidence = "; ".join(
                f"{file}:{lines}" for file, lines in list(files.items())[:5]
            )
        else:
            file_evidence = ""

        findings.append({
            "category": category,
            "title": rule,
            "severity": severity,
            "confidence": 4,
            "evidence": f"{metadata.get('description', '')} {file_evidence}".strip(),
            "file": file_evidence,
            "raw_rule": rule,
            "source": "android_api"
        })

    return findings


def deduplicate_findings(findings):
    seen = set()
    result = []

    for f in findings:
        key = (
            f.get("category", ""),
            f.get("title", ""),
            f.get("file", ""),
            f.get("raw_rule", "")
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(f)

    return result


def case_id_from_path(path):
    p = Path(path)
    case_name = p.stem.replace("_mobsf", "")

    # 如果路徑長這樣 reports/mobsf/Platform/MASTG-TEST0007_mobsf.json
    category = p.parent.name

    return f"{category}/{case_name}"


def normalize_one(path):
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))

    findings = []
    findings.extend(normalize_manifest_findings(data))
    findings.extend(normalize_code_findings(data))
    findings.extend(normalize_android_api(data))

    findings = deduplicate_findings(findings)

    return {
        "tool": "mobsf",
        "case_id": case_id_from_path(path),
        "apk": data.get("file_name"),
        "package_name": data.get("package_name"),
        "app_name": data.get("app_name"),
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "exported_count": data.get("exported_count", {}),
            "security_score": data.get("security_score"),
            "average_cvss": data.get("average_cvss")
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", default="./reports/mobsf")
    parser.add_argument("--output-root", default="./reports/normalized/mobsf")
    args = parser.parse_args()

    input_root = Path(args.input_root)
    output_root = Path(args.output_root)

    json_files = sorted(input_root.rglob("*_mobsf.json"))

    if not json_files:
        raise SystemExit(f"[ERROR] No MobSF reports found under {input_root}")

    for path in json_files:
        normalized = normalize_one(path)

        rel = path.relative_to(input_root)
        out_path = output_root / rel.parent / rel.name.replace("_mobsf.json", ".json")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        out_path.write_text(
            json.dumps(normalized, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        print(f"[OK] {path} -> {out_path}")


if __name__ == "__main__":
    main()