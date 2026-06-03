#!/usr/bin/env python3
"""
Evaluate normalized APK scanner reports against manually reviewed ground truth.

Designed for:
- our_scanner normalized reports
- MobSF normalized reports

Expected normalized report shape:
{
  "tool": "our_scanner" | "mobsf",
  "case_id": "Platform/MASTG-TEST0007" or "MASTG-TEST0007",
  "meta": {...},
  "vulnerabilities": [
    {
      "pattern_id": "...",
      "title": "...",
      "severity": "Critical|High|Medium|Low",
      "severity_score": 1-10,
      "confidence_score": 1-10,
      "category": "...",
      "location": "...",
      "evidence": [...],
      "related_components": [...],
      "related_deep_links": [...]
    }
  ],
  "summary": {...}
}

Ground truth flexible shape:
{
  "Platform/MASTG-TEST0007": {
    "test_id": "MASTG-TEST0007",
    "title": "...",
    "vulnerabilities": [
      {
        "id": "GT-0007-001",
        "category": "exported_provider",
        "description": "...",
        "must_detect": true,
        "acceptable_scanner_categories": [
          "exported_provider",
          "content_provider_exposure"
        ],
        "evidence_keywords": [
          "MyContentProvider",
          "exported=true"
        ],
        "component": "com.example.mastg_test0007.MyContentProvider",
        "location": "AndroidManifest.xml",
        "expected_severity_score": 8,
        "expected_confidence_score": 8
      }
    ]
  }
}
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "warning": 3,
    "low": 2,
    "info": 1,
    "secure": 0,
    "unknown": 0,
    "": 0,
}

SEVERITY_TO_SCORE = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "warning": 5,
    "low": 2,
    "info": 2,
    "secure": 1,
    "unknown": 1,
    "": 1,
}

DEFAULT_SCOPE_CATEGORIES = {
    # Platform / IPC / component exposure
    "exported_component",
    "exported_activity",
    "exported_service",
    "exported_receiver",
    "exported_provider",
    "content_provider_exposure",
    "ipc_exposure",
    "manifest_provider",
    "manifest_issue",
    "manifest",
    "platform_version",
    "app_config",
    "certificate",

    # SQL / provider
    "content_provider_sql_injection",
    "sql_injection",
    "unsafe_sql_query",
    "unsafe_content_provider_query",

    # Deep link / intent
    "deep_link",
    "insecure_deep_link",
    "deep_link_oauth",
    "deep_link_custom_scheme",
    "deep_link_http",
    "deep_link_payment",
    "intent_filter",
    "app_link_misconfiguration",
    "deeplink_exposure",
    "deep_link_input_validation",
    "unvalidated_deep_link",
    "intent_redirection",
    "unsafe_uri_handling",

    # Permission
    "dangerous_permission",
    "excessive_permission",
    "permission_risk",
    "least_privilege_violation",
    "custom_permission_weak_protection",
    "permission",

    # PendingIntent
    "pending_intent",
    "mutable_pending_intent",
    "unsafe_pending_intent",
    "missing_flag_immutable",
    "implicit_pending_intent",

    # WebView
    "webview",
    "webview_javascript_enabled",
    "webview_javascript",
    "javascript_enabled",
    "unsafe_webview",
    "webview_file_access",
    "unsafe_webview_protocol",
    "file_scheme_webview",
    "webview_local_file_access",
    "webview_javascript_interface",
    "javascript_interface",
    "webview_js_bridge",
    "addjavascriptinterface",
    "webview_native_bridge",
    "webview_cleanup",
    "webview_cache",
    "webview_sensitive_data",
    "webview_sensitive_data_not_cleared",

    # Storage / secret / logging / API
    "hardcoded_secret",
    "logging",
    "logging_sensitive_data",
    "local_file_io",
    "content_provider_usage",
    "storage",
    "android_api",
    "code_analysis",

    # Network / TLS / Network Security Config
    "cleartext_http",
    "uses_cleartext_traffic",
    "cleartext_traffic_enabled",
    "manifest_cleartext",
    "network_cleartext",
    "insecure_network",
    "insecure_network_config",
    "http_url",
    "plaintext_traffic",
    "insecure_protocol",
    "webview_http",

    "low_min_sdk",
    "low_min_sdk_network_security_bypass",
    "low_target_sdk",
    "low_target_sdk_network_security",
    "target_sdk_too_low",
    "network_security_config_bypass",
    "insecure_platform_version",
    "manifest_sdk",

    "hostname_verification_bypass",
    "insecure_hostname_verifier",
    "ssl_hostname_verifier",
    "tls_misconfiguration",
    "insecure_ssl",
    "insecure_tls",

    "tls_error_handling_disabled",
    "ssl_error_ignored",
    "webview_ssl_error_bypass",
    "certificate_validation_bypass",
    "insecure_trust_manager",
    "trust_all_certificates",
    "x509trustmanager",
    "ssl_certificate_validation_disabled",

    "user_ca_trust_enabled",
    "trust_user_ca",
    "custom_trust_anchors",

    "obsolete_tls_version",
    "insecure_tls_version",
    "weak_tls",
    "ssl_context",

    "certificate_pinning_configuration",
    "certificate_pinning",
    "ssl_pinning",
    "pin_set",
    "network_security_config",
    "custom_certificate_store",
    "certificate_pin",
    "tls_pinning",
}

THIRD_PARTY_PATH_HINTS = [
    "androidx/",
    "androidx.",
    "io/reactivex/",
    "io.reactivex",
    "kotlin/",
    "kotlinx/",
    "okhttp3/",
    "retrofit2/",
    "com/google/",
    "com.google.",
    "org/jetbrains/",
    "org.jetbrains.",
    "org/reactivestreams/",
]


# ---------------------------------------------------------------------------
# Basic IO
# ---------------------------------------------------------------------------

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def fmt_float(x: float | None) -> str:
    if x is None:
        return "N/A"
    return f"{x:.4f}"


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(normalize_text(x) for x in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False).lower()
    return str(value).lower()


def normalize_category(value: Any) -> str:
    return normalize_text(value).strip().replace(" ", "_").replace("-", "_")


def severity_rank(value: Any) -> int:
    return SEVERITY_RANK.get(normalize_text(value).strip(), 0)


def get_severity_score(finding: dict[str, Any]) -> int:
    raw = finding.get("severity_score")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass

    sev = normalize_text(finding.get("severity"))
    return SEVERITY_TO_SCORE.get(sev, 1)


def get_confidence_score(finding: dict[str, Any]) -> int:
    for key in ("confidence_score", "confidence"):
        raw = finding.get(key)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass

    return 0


def get_finding_id(finding: dict[str, Any]) -> str:
    return (
        str(finding.get("pattern_id") or "")
        or str(finding.get("id") or "")
        or str(finding.get("rule") or "")
    )


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def get_expected_list(
    gt_case: dict[str, Any],
    must_detect_only: bool,
) -> list[dict[str, Any]]:
    expected = (
        gt_case.get("expected_vulnerabilities")
        or gt_case.get("expected")
        or gt_case.get("vulnerabilities")
        or []
    )

    if not isinstance(expected, list):
        return []

    if must_detect_only:
        expected = [item for item in expected if item.get("must_detect", True)]

    return expected


def get_gt_id(gt: dict[str, Any], index: int) -> str:
    return str(
        gt.get("id")
        or gt.get("gt_id")
        or gt.get("name")
        or f"GT-{index + 1:03d}"
    )


def get_gt_text(gt: dict[str, Any]) -> str:
    parts = [
        gt.get("id", ""),
        gt.get("category", ""),
        gt.get("description", ""),
        gt.get("component", ""),
        gt.get("component_name", ""),
        gt.get("location", ""),
        gt.get("authority", ""),
        gt.get("scheme", ""),
        gt.get("host", ""),
        gt.get("path", ""),
        gt.get("file", ""),
        " ".join(gt.get("acceptable_scanner_categories", []) or []),
        " ".join(gt.get("evidence_keywords", []) or []),
    ]

    return normalize_text(" ".join(str(p) for p in parts if p is not None))


# ---------------------------------------------------------------------------
# Finding extraction / loading
# ---------------------------------------------------------------------------

def get_report_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Prefer new normalized shape:
        report["vulnerabilities"]

    Fallback for old normalized reports:
        report["findings"]
    """

    findings = report.get("vulnerabilities")

    if not isinstance(findings, list):
        findings = report.get("findings")

    if not isinstance(findings, list):
        return []

    cleaned: list[dict[str, Any]] = []

    for finding in findings:
        if isinstance(finding, dict):
            cleaned.append(finding)

    return cleaned


def get_finding_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("pattern_id", ""),
        finding.get("category", ""),
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("location", ""),
        finding.get("evidence", ""),
        finding.get("related_components", ""),
        finding.get("related_deep_links", ""),
        finding.get("component", ""),
        finding.get("file", ""),
        finding.get("raw_rule", ""),
        finding.get("source", ""),
    ]

    raw = finding.get("raw")
    if raw is not None:
        parts.append(raw)

    return normalize_text(" ".join(normalize_text(p) for p in parts if p is not None))


def is_third_party_finding(finding: dict[str, Any]) -> bool:
    text = get_finding_text(finding)
    return any(hint.lower() in text for hint in THIRD_PARTY_PATH_HINTS)


def get_case_id_from_report_path(path: Path, input_root: Path) -> str:
    """
    Example:
        reports/normalized/mobsf/Platform/MASTG-TEST0007.json
        -> Platform/MASTG-TEST0007
    """

    rel = path.relative_to(input_root)
    category = rel.parent.as_posix()
    case_name = path.stem

    if category == ".":
        return case_name

    return f"{category}/{case_name}"


def load_normalized_reports(
    input_root: Path,
    tool_name: str | None = None,
) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}

    if not input_root.exists():
        return reports

    for path in sorted(input_root.rglob("*.json")):
        try:
            report = load_json(path)
        except Exception as err:
            print(f"[WARN] Cannot read report {path}: {err}")
            continue

        if not isinstance(report, dict):
            print(f"[WARN] Ignore non-object report: {path}")
            continue

        case_id = report.get("case_id")

        if not case_id:
            case_id = get_case_id_from_report_path(path, input_root)
            report["case_id"] = case_id

        if tool_name and not report.get("tool"):
            report["tool"] = tool_name

        report["_path"] = str(path)
        reports[str(case_id)] = report

    return reports


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def category_matches(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    finding_category = normalize_category(finding.get("category", ""))
    gt_category = normalize_category(gt.get("category", ""))

    acceptable = gt.get("acceptable_scanner_categories", []) or []
    acceptable_set = {normalize_category(x) for x in acceptable}

    if gt_category:
        acceptable_set.add(gt_category)

    if not acceptable_set:
        return False

    return finding_category in acceptable_set


def keyword_match_score(finding: dict[str, Any], gt: dict[str, Any]) -> tuple[bool, int, int]:
    keywords = gt.get("evidence_keywords", []) or []
    if not keywords:
        return False, 0, 0

    text = get_finding_text(finding)
    hits = 0

    for kw in keywords:
        kw_text = normalize_text(kw).strip()
        if kw_text and kw_text in text:
            hits += 1

    # If the GT provides several keywords, requiring all of them may be too strict
    # across tools. Use at least 1 hit by default, but return hit count for scoring.
    return hits >= 1, hits, len(keywords)


def component_matches(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    expected_component = (
        gt.get("component")
        or gt.get("component_name")
        or gt.get("provider")
        or gt.get("activity")
        or gt.get("service")
        or gt.get("receiver")
    )

    if not expected_component:
        return False

    expected = normalize_text(expected_component)
    text = get_finding_text(finding)

    return expected in text


def location_matches(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    gt_location = gt.get("location") or gt.get("file") or gt.get("path")
    if not gt_location:
        return False

    finding_location = finding.get("location") or finding.get("file") or ""
    if not finding_location:
        return False

    gt_norm = normalize_text(gt_location).replace("\\", "/")
    finding_norm = normalize_text(finding_location).replace("\\", "/")

    return gt_norm in finding_norm or finding_norm in gt_norm


def authority_matches(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    authority = gt.get("authority")
    if not authority:
        return False

    return normalize_text(authority) in get_finding_text(finding)


def deeplink_matches(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    expected_parts = [
        gt.get("scheme"),
        gt.get("host"),
        gt.get("path"),
    ]

    expected_parts = [
        normalize_text(x).strip()
        for x in expected_parts
        if normalize_text(x).strip()
    ]

    if not expected_parts:
        return False

    text = get_finding_text(finding)
    hits = sum(1 for part in expected_parts if part in text)

    return hits == len(expected_parts)


def finding_matches_gt(
    finding: dict[str, Any],
    gt: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """
    Return:
        (matched, match_info)

    Matching policy:
    - Strong match:
        category + component/location/authority/deeplink
    - Medium match:
        category + keyword
    - Weak match:
        keyword only

    This avoids counting every generic MobSF finding as TP just because the
    category is broad.
    """

    cat_ok = category_matches(finding, gt)
    comp_ok = component_matches(finding, gt)
    loc_ok = location_matches(finding, gt)
    authority_ok = authority_matches(finding, gt)
    deeplink_ok = deeplink_matches(finding, gt)
    kw_ok, kw_hits, kw_total = keyword_match_score(finding, gt)

    strong_detail_ok = comp_ok or loc_ok or authority_ok or deeplink_ok

    if cat_ok and strong_detail_ok:
        return True, {
            "match_type": "strong",
            "category": cat_ok,
            "component": comp_ok,
            "location": loc_ok,
            "authority": authority_ok,
            "deeplink": deeplink_ok,
            "keyword_hits": kw_hits,
            "keyword_total": kw_total,
        }

    if cat_ok and kw_ok:
        return True, {
            "match_type": "medium",
            "category": cat_ok,
            "component": comp_ok,
            "location": loc_ok,
            "authority": authority_ok,
            "deeplink": deeplink_ok,
            "keyword_hits": kw_hits,
            "keyword_total": kw_total,
        }

    if kw_ok and not gt.get("acceptable_scanner_categories") and not gt.get("category"):
        return True, {
            "match_type": "weak_keyword_only",
            "category": cat_ok,
            "component": comp_ok,
            "location": loc_ok,
            "authority": authority_ok,
            "deeplink": deeplink_ok,
            "keyword_hits": kw_hits,
            "keyword_total": kw_total,
        }

    return False, {
        "match_type": "none",
        "category": cat_ok,
        "component": comp_ok,
        "location": loc_ok,
        "authority": authority_ok,
        "deeplink": deeplink_ok,
        "keyword_hits": kw_hits,
        "keyword_total": kw_total,
    }


# ---------------------------------------------------------------------------
# Filtering / sorting
# ---------------------------------------------------------------------------

def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort by ASNav navigation score (same rule as {package}_test_plan.md Top-10)."""

    from test_plan import sort_findings_by_navigation

    return sort_findings_by_navigation(findings)


def filter_scope_findings(
    findings: list[dict[str, Any]],
    scope_categories: set[str] | None,
    ignore_third_party: bool,
    min_severity_score: int | None,
    min_confidence_score: int | None,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    for finding in findings:
        category = normalize_category(finding.get("category", ""))

        if scope_categories is not None and category not in scope_categories:
            continue

        if ignore_third_party and is_third_party_finding(finding):
            continue

        if min_severity_score is not None and get_severity_score(finding) < min_severity_score:
            continue

        if min_confidence_score is not None and get_confidence_score(finding) < min_confidence_score:
            continue

        output.append(finding)

    return output


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def safe_div(num: int, den: int) -> float | None:
    if den == 0:
        return None
    return num / den


def compute_prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)

    if precision is None or recall is None or precision + recall == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def compute_score_error(
    matched_pairs: list[dict[str, Any]],
) -> dict[str, float | None]:
    sev_errors: list[int] = []
    conf_errors: list[int] = []

    for pair in matched_pairs:
        gt = pair["ground_truth"]
        finding = pair["finding"]

        expected_sev = gt.get("expected_severity_score")
        expected_conf = gt.get("expected_confidence_score")

        try:
            if expected_sev is not None:
                sev_errors.append(abs(int(expected_sev) - get_severity_score(finding)))
        except (TypeError, ValueError):
            pass

        try:
            if expected_conf is not None:
                conf_errors.append(abs(int(expected_conf) - get_confidence_score(finding)))
        except (TypeError, ValueError):
            pass

    sev_mae = sum(sev_errors) / len(sev_errors) if sev_errors else None
    conf_mae = sum(conf_errors) / len(conf_errors) if conf_errors else None

    return {
        "severity_score_mae": sev_mae,
        "confidence_score_mae": conf_mae,
    }


def evaluate_case(
    case_id: str,
    gt_case: dict[str, Any],
    report: dict[str, Any] | None,
    must_detect_only: bool,
    scope_categories: set[str] | None,
    ignore_third_party: bool,
    top_k: int,
    high_conf_threshold: int,
    high_sev_threshold: int,
    min_severity_score: int | None,
    min_confidence_score: int | None,
) -> dict[str, Any]:
    expected = get_expected_list(gt_case, must_detect_only=must_detect_only)

    raw_findings: list[dict[str, Any]] = []
    if report:
        raw_findings = get_report_findings(report)

    scoped_findings = filter_scope_findings(
        raw_findings,
        scope_categories=scope_categories,
        ignore_third_party=ignore_third_party,
        min_severity_score=min_severity_score,
        min_confidence_score=min_confidence_score,
    )

    scoped_findings = sort_findings(scoped_findings)

    matched_gt_indices: set[int] = set()
    matched_finding_indices: set[int] = set()
    matched_pairs: list[dict[str, Any]] = []

    for gi, gt in enumerate(expected):
        best_candidate: tuple[int, dict[str, Any], dict[str, Any]] | None = None

        for fi, finding in enumerate(scoped_findings):
            if fi in matched_finding_indices:
                continue

            matched, info = finding_matches_gt(finding, gt)
            if not matched:
                continue

            # Prefer stronger match, then higher confidence/severity.
            match_strength = {
                "strong": 3,
                "medium": 2,
                "weak_keyword_only": 1,
            }.get(info.get("match_type"), 0)

            ranking_score = (
                match_strength * 100
                + get_confidence_score(finding) * 10
                + get_severity_score(finding)
            )

            if best_candidate is None or ranking_score > best_candidate[0]:
                best_candidate = (ranking_score, finding, info)

        if best_candidate is not None:
            _, finding, info = best_candidate
            fi = scoped_findings.index(finding)

            matched_gt_indices.add(gi)
            matched_finding_indices.add(fi)

            matched_pairs.append(
                {
                    "gt_id": get_gt_id(gt, gi),
                    "gt_category": gt.get("category", ""),
                    "finding_id": get_finding_id(finding),
                    "finding_category": finding.get("category", ""),
                    "finding_title": finding.get("title", ""),
                    "finding_severity": finding.get("severity", ""),
                    "finding_severity_score": get_severity_score(finding),
                    "finding_confidence_score": get_confidence_score(finding),
                    "match_info": info,
                    "ground_truth": gt,
                    "finding": finding,
                }
            )

    tp = len(matched_gt_indices)
    fn = max(0, len(expected) - tp)
    fp = max(0, len(scoped_findings) - len(matched_finding_indices))

    base_metrics = compute_prf(tp, fp, fn)

    # Top-k precision
    top_findings = scoped_findings[:top_k]
    top_matched = 0

    for finding in top_findings:
        if any(finding_matches_gt(finding, gt)[0] for gt in expected):
            top_matched += 1

    topk_precision = safe_div(top_matched, len(top_findings))

    # High-confidence subset precision
    high_conf_findings = [
        finding
        for finding in scoped_findings
        if get_confidence_score(finding) >= high_conf_threshold
    ]

    high_conf_matched = 0
    for finding in high_conf_findings:
        if any(finding_matches_gt(finding, gt)[0] for gt in expected):
            high_conf_matched += 1

    high_conf_precision = safe_div(high_conf_matched, len(high_conf_findings))

    # High-priority = Top-N navigation targets (aligned with test plan / CLI Top-10)
    from test_plan import NAVIGATION_TOP_N

    nav_top_n = NAVIGATION_TOP_N
    high_priority_findings = scoped_findings[:nav_top_n]

    high_priority_matched = 0
    for finding in high_priority_findings:
        if any(finding_matches_gt(finding, gt)[0] for gt in expected):
            high_priority_matched += 1

    high_priority_precision = safe_div(
        high_priority_matched,
        len(high_priority_findings),
    )

    score_error = compute_score_error(matched_pairs)

    return {
        "case_id": case_id,
        "test_id": gt_case.get("test_id", ""),
        "title": gt_case.get("title", ""),
        "expected_count": len(expected),
        "raw_finding_count": len(raw_findings),
        "scoped_finding_count": len(scoped_findings),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": base_metrics["precision"],
        "recall": base_metrics["recall"],
        "f1": base_metrics["f1"],
        f"top{top_k}_precision": topk_precision,
        "high_confidence_finding_count": len(high_conf_findings),
        "high_confidence_precision": high_conf_precision,
        "high_priority_finding_count": len(high_priority_findings),
        "high_priority_precision": high_priority_precision,
        "severity_score_mae": score_error["severity_score_mae"],
        "confidence_score_mae": score_error["confidence_score_mae"],
        "matches": matched_pairs,
        "unmatched_expected": [
            gt for i, gt in enumerate(expected) if i not in matched_gt_indices
        ],
        "unmatched_findings": [
            finding
            for i, finding in enumerate(scoped_findings)
            if i not in matched_finding_indices
        ],
    }


def aggregate_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_tp = sum(r["tp"] for r in rows)
    total_fp = sum(r["fp"] for r in rows)
    total_fn = sum(r["fn"] for r in rows)
    total_expected = sum(r["expected_count"] for r in rows)
    total_raw_findings = sum(r["raw_finding_count"] for r in rows)
    total_scoped_findings = sum(r["scoped_finding_count"] for r in rows)

    prf = compute_prf(total_tp, total_fp, total_fn)

    high_conf_count = sum(r["high_confidence_finding_count"] for r in rows)
    high_priority_count = sum(r["high_priority_finding_count"] for r in rows)

    high_conf_matched_estimate = 0
    high_conf_total = 0
    high_priority_matched_estimate = 0
    high_priority_total = 0

    # Reconstruct weighted precision from per-case values.
    for r in rows:
        hc_count = r["high_confidence_finding_count"]
        hp_count = r["high_priority_finding_count"]

        if r["high_confidence_precision"] is not None:
            high_conf_matched_estimate += r["high_confidence_precision"] * hc_count
            high_conf_total += hc_count

        if r["high_priority_precision"] is not None:
            high_priority_matched_estimate += r["high_priority_precision"] * hp_count
            high_priority_total += hp_count

    high_conf_precision = (
        high_conf_matched_estimate / high_conf_total
        if high_conf_total
        else None
    )

    high_priority_precision = (
        high_priority_matched_estimate / high_priority_total
        if high_priority_total
        else None
    )

    sev_mae_values = [
        r["severity_score_mae"]
        for r in rows
        if r["severity_score_mae"] is not None
    ]

    conf_mae_values = [
        r["confidence_score_mae"]
        for r in rows
        if r["confidence_score_mae"] is not None
    ]

    return {
        "cases": len(rows),
        "expected": total_expected,
        "raw_findings": total_raw_findings,
        "scoped_findings": total_scoped_findings,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": prf["precision"],
        "recall": prf["recall"],
        "f1": prf["f1"],
        "high_confidence_findings": high_conf_count,
        "high_confidence_precision": high_conf_precision,
        "high_priority_findings": high_priority_count,
        "high_priority_precision": high_priority_precision,
        "severity_score_mae": (
            sum(sev_mae_values) / len(sev_mae_values)
            if sev_mae_values
            else None
        ),
        "confidence_score_mae": (
            sum(conf_mae_values) / len(conf_mae_values)
            if conf_mae_values
            else None
        ),
    }


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_case_csv(
    path: Path,
    tool_rows: dict[str, list[dict[str, Any]]],
    top_k: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "tool",
        "case_id",
        "test_id",
        "expected_count",
        "raw_finding_count",
        "scoped_finding_count",
        "tp",
        "fp",
        "fn",
        "precision",
        "recall",
        "f1",
        f"top{top_k}_precision",
        "high_confidence_finding_count",
        "high_confidence_precision",
        "high_priority_finding_count",
        "high_priority_precision",
        "severity_score_mae",
        "confidence_score_mae",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for tool, rows in tool_rows.items():
            for r in rows:
                writer.writerow(
                    {
                        "tool": tool,
                        "case_id": r["case_id"],
                        "test_id": r.get("test_id", ""),
                        "expected_count": r["expected_count"],
                        "raw_finding_count": r["raw_finding_count"],
                        "scoped_finding_count": r["scoped_finding_count"],
                        "tp": r["tp"],
                        "fp": r["fp"],
                        "fn": r["fn"],
                        "precision": fmt_float(r["precision"]),
                        "recall": fmt_float(r["recall"]),
                        "f1": fmt_float(r["f1"]),
                        f"top{top_k}_precision": fmt_float(r[f"top{top_k}_precision"]),
                        "high_confidence_finding_count": r["high_confidence_finding_count"],
                        "high_confidence_precision": fmt_float(r["high_confidence_precision"]),
                        "high_priority_finding_count": r["high_priority_finding_count"],
                        "high_priority_precision": fmt_float(r["high_priority_precision"]),
                        "severity_score_mae": fmt_float(r["severity_score_mae"]),
                        "confidence_score_mae": fmt_float(r["confidence_score_mae"]),
                    }
                )


def write_summary_csv(
    path: Path,
    summary_rows: dict[str, dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "tool",
        "cases",
        "expected",
        "raw_findings",
        "scoped_findings",
        "tp",
        "fp",
        "fn",
        "precision",
        "recall",
        "f1",
        "high_confidence_findings",
        "high_confidence_precision",
        "high_priority_findings",
        "high_priority_precision",
        "severity_score_mae",
        "confidence_score_mae",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for tool, s in summary_rows.items():
            writer.writerow(
                {
                    "tool": tool,
                    "cases": s["cases"],
                    "expected": s["expected"],
                    "raw_findings": s["raw_findings"],
                    "scoped_findings": s["scoped_findings"],
                    "tp": s["tp"],
                    "fp": s["fp"],
                    "fn": s["fn"],
                    "precision": fmt_float(s["precision"]),
                    "recall": fmt_float(s["recall"]),
                    "f1": fmt_float(s["f1"]),
                    "high_confidence_findings": s["high_confidence_findings"],
                    "high_confidence_precision": fmt_float(s["high_confidence_precision"]),
                    "high_priority_findings": s["high_priority_findings"],
                    "high_priority_precision": fmt_float(s["high_priority_precision"]),
                    "severity_score_mae": fmt_float(s["severity_score_mae"]),
                    "confidence_score_mae": fmt_float(s["confidence_score_mae"]),
                }
            )


def short_finding(finding: dict[str, Any]) -> str:
    title = str(finding.get("title", "")).replace("\n", " ")
    evidence = normalize_text(finding.get("evidence", "")).replace("\n", " ")

    if len(title) > 140:
        title = title[:140] + "..."

    if len(evidence) > 180:
        evidence = evidence[:180] + "..."

    return (
        f"`{finding.get('category', '')}` "
        f"id=`{get_finding_id(finding)}` "
        f"severity=`{finding.get('severity', '')}` "
        f"sev_score=`{get_severity_score(finding)}` "
        f"conf_score=`{get_confidence_score(finding)}` "
        f"title={title} "
        f"evidence={evidence}"
    )


def write_markdown_report(
    path: Path,
    tool_rows: dict[str, list[dict[str, Any]]],
    summary_rows: dict[str, dict[str, Any]],
    top_k: int,
    must_detect_only: bool,
    ignore_third_party: bool,
    use_scope_filter: bool,
    high_conf_threshold: int,
    high_sev_threshold: int,
    min_severity_score: int | None,
    min_confidence_score: int | None,
) -> None:
    from test_plan import NAVIGATION_TOP_N

    path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []

    lines.append("# Evaluation Report")
    lines.append("")
    lines.append("## Settings")
    lines.append("")
    lines.append(f"- Must-detect only: `{must_detect_only}`")
    lines.append(f"- Ignore third-party findings: `{ignore_third_party}`")
    lines.append(f"- Scope filter enabled: `{use_scope_filter}`")
    lines.append(f"- Top-k: `{top_k}`")
    lines.append(f"- High confidence threshold: `{high_conf_threshold}`")
    lines.append(f"- High severity threshold: `{high_sev_threshold}`")
    lines.append(
        "- High-priority subset: Top-N navigation list "
        f"(nav = priority_weight + severity×confidence, N=`{NAVIGATION_TOP_N}`)"
    )
    lines.append(f"- Minimum severity score filter: `{min_severity_score}`")
    lines.append(f"- Minimum confidence score filter: `{min_confidence_score}`")
    lines.append("")

    lines.append("## Overall Summary")
    lines.append("")
    lines.append(
        "| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | "
        "Precision | Recall | F1 | High-Conf Precision | High-Priority Precision | Severity MAE | Confidence MAE |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for tool, s in summary_rows.items():
        lines.append(
            f"| {tool} | {s['cases']} | {s['expected']} | {s['raw_findings']} | "
            f"{s['scoped_findings']} | {s['tp']} | {s['fp']} | {s['fn']} | "
            f"{fmt_float(s['precision'])} | {fmt_float(s['recall'])} | {fmt_float(s['f1'])} | "
            f"{fmt_float(s['high_confidence_precision'])} | "
            f"{fmt_float(s['high_priority_precision'])} | "
            f"{fmt_float(s['severity_score_mae'])} | "
            f"{fmt_float(s['confidence_score_mae'])} |"
        )

    lines.append("")
    lines.append("## Per-case Results")
    lines.append("")

    for tool, rows in tool_rows.items():
        lines.append(f"### {tool}")
        lines.append("")
        lines.append(
            f"| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | "
            f"Top-{top_k} Precision | High-Conf Precision | High-Priority Precision |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

        for r in rows:
            lines.append(
                f"| {r['case_id']} | {r['expected_count']} | {r['scoped_finding_count']} | "
                f"{r['tp']} | {r['fp']} | {r['fn']} | "
                f"{fmt_float(r['precision'])} | {fmt_float(r['recall'])} | "
                f"{fmt_float(r['f1'])} | {fmt_float(r[f'top{top_k}_precision'])} | "
                f"{fmt_float(r['high_confidence_precision'])} | "
                f"{fmt_float(r['high_priority_precision'])} |"
            )

        lines.append("")

    lines.append("## Matched Details")
    lines.append("")

    for tool, rows in tool_rows.items():
        lines.append(f"### {tool}")
        lines.append("")

        for r in rows:
            if not r["matches"]:
                continue

            lines.append(f"#### {r['case_id']}")
            lines.append("")

            for match in r["matches"]:
                lines.append(
                    f"- GT `{match['gt_id']}` `{match['gt_category']}` "
                    f"matched by `{match['finding_id']}` `{match['finding_category']}` "
                    f"score=({match['finding_severity_score']}, "
                    f"{match['finding_confidence_score']}) "
                    f"type=`{match['match_info'].get('match_type')}` "
                    f"title={match['finding_title']}"
                )

            lines.append("")

    lines.append("## Unmatched Details")
    lines.append("")
    lines.append("This section helps inspect false negatives and false positives.")
    lines.append("")

    for tool, rows in tool_rows.items():
        lines.append(f"### {tool}")
        lines.append("")

        for r in rows:
            if not r["unmatched_expected"] and not r["unmatched_findings"]:
                continue

            lines.append(f"#### {r['case_id']}")
            lines.append("")

            if r["unmatched_expected"]:
                lines.append("Unmatched expected vulnerabilities:")
                lines.append("")
                for gt in r["unmatched_expected"]:
                    lines.append(
                        f"- `{gt.get('category', '')}` "
                        f"id=`{gt.get('id', '')}` "
                        f"component=`{gt.get('component', gt.get('component_name', ''))}` "
                        f"location=`{gt.get('location', '')}` "
                        f"description={gt.get('description', '')}"
                    )
                lines.append("")

            if r["unmatched_findings"]:
                lines.append("Unmatched findings:")
                lines.append("")
                for finding in r["unmatched_findings"][:15]:
                    lines.append(f"- {short_finding(finding)}")
                if len(r["unmatched_findings"]) > 15:
                    lines.append(f"- ... {len(r['unmatched_findings']) - 15} more")
                lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")




def get_case_category(case_id: str) -> str:
    """
    Return the top-level category from a case_id.

    Examples:
        Platform/MASTG-TEST0007 -> Platform
        MASTG-TEST0007          -> uncategorized

    This is only used for output organization. It does not change matching or
    metric computation.
    """

    case_id = str(case_id).strip().replace("\\", "/")

    if "/" not in case_id:
        return "uncategorized"

    category = case_id.split("/", 1)[0].strip()
    return category or "uncategorized"


def filter_tool_rows_by_category(
    tool_rows: dict[str, list[dict[str, Any]]],
    category: str,
) -> dict[str, list[dict[str, Any]]]:
    """
    Keep only rows that belong to one top-level input category.
    """

    return {
        tool: [
            row
            for row in rows
            if get_case_category(row.get("case_id", "")) == category
        ]
        for tool, rows in tool_rows.items()
    }


def aggregate_nonempty_tool_rows(
    tool_rows: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """
    Aggregate rows per scanner/baseline.

    Empty scanner rows are skipped for category-specific output so that adding
    more baselines does not require changing this writer.
    """

    return {
        tool: aggregate_results(rows)
        for tool, rows in tool_rows.items()
        if rows
    }

def write_category_outputs(
    output_root: Path,
    all_tool_rows: dict[str, list[dict[str, Any]]],
    top_k: int,
    must_detect_only: bool,
    ignore_third_party: bool,
    use_scope_filter: bool,
    high_conf_threshold: int,
    high_sev_threshold: int,
    min_severity_score: int | None,
    min_confidence_score: int | None,
) -> list[Path]:
    """
    Write per-category output directories.

    Example:
        case_id = Platform/MASTG-TEST0007

    Output:
        <output_root>/Platform/summary.json
        <output_root>/Platform/summary_results.csv
        <output_root>/Platform/case_results.json
        <output_root>/Platform/case_results.csv
        <output_root>/Platform/evaluation_report.md
    """

    categories = sorted(
        {
            get_case_category(row.get("case_id", ""))
            for rows in all_tool_rows.values()
            for row in rows
        }
    )

    written_dirs: list[Path] = []

    for category in categories:
        category_rows = filter_tool_rows_by_category(all_tool_rows, category)
        category_summary = aggregate_nonempty_tool_rows(category_rows)

        if not category_summary:
            continue

        category_output_dir = output_root / category
        category_output_dir.mkdir(parents=True, exist_ok=True)

        write_json(category_output_dir / "summary.json", category_summary)
        write_json(category_output_dir / "case_results.json", category_rows)

        write_summary_csv(
            category_output_dir / "summary_results.csv",
            category_summary,
        )

        write_case_csv(
            category_output_dir / "case_results.csv",
            category_rows,
            top_k=top_k,
        )

        write_markdown_report(
            category_output_dir / "evaluation_report.md",
            tool_rows=category_rows,
            summary_rows=category_summary,
            top_k=top_k,
            must_detect_only=must_detect_only,
            ignore_third_party=ignore_third_party,
            use_scope_filter=use_scope_filter,
            high_conf_threshold=high_conf_threshold,
            high_sev_threshold=high_sev_threshold,
            min_severity_score=min_severity_score,
            min_confidence_score=min_confidence_score,
        )

        written_dirs.append(category_output_dir)

    return written_dirs



def infer_category_from_tool_inputs(tool_inputs: dict[str, Path]) -> str | None:
    """
    Infer a single requested category from paths like:
        mobsf=./reports/normalized/mobsf/Network
        our_scanner=./reports/normalized/our_scanner/Network

    If all tool input paths end with the same folder name, treat that folder as
    the selected category. If paths end with scanner names such as mobsf and
    our_scanner, return None so the full ground truth is evaluated.
    """

    leaf_names = {
        # Do not require the path to exist here.  The CLI path itself is the
        # user's intent, and using only .name keeps category detection stable.
        path.expanduser().name
        for path in tool_inputs.values()
        if str(path).strip()
    }

    if len(leaf_names) != 1:
        return None

    candidate = next(iter(leaf_names)).strip()

    if not candidate or candidate in {".", ".."}:
        return None

    return candidate


def filter_ground_truth_by_category(
    ground_truth: dict[str, Any],
    category: str | None,
) -> dict[str, Any]:
    """
    Keep only ground-truth cases in one top-level category.

    category=None or category="ALL" means no filter.
    """

    if category is None or category.upper() == "ALL":
        return ground_truth

    filtered = {
        case_id: gt_case
        for case_id, gt_case in ground_truth.items()
        if get_case_category(case_id) == category
    }

    if not filtered:
        available = sorted(
            {
                get_case_category(case_id)
                for case_id in ground_truth.keys()
                if get_case_category(case_id) != "uncategorized"
            }
        )
        raise ValueError(
            f"No ground-truth cases found for category '{category}'. "
            f"Available categories: {', '.join(available) if available else 'none'}"
        )

    return filtered

# ---------------------------------------------------------------------------
# Evaluation entry
# ---------------------------------------------------------------------------

def evaluate_all(
    ground_truth_path: Path,
    tool_inputs: dict[str, Path],
    output_dir: Path,
    category: str | None,
    must_detect_only: bool,
    ignore_third_party: bool,
    use_scope_filter: bool,
    top_k: int,
    high_conf_threshold: int,
    high_sev_threshold: int,
    min_severity_score: int | None,
    min_confidence_score: int | None,
) -> None:
    ground_truth = load_json(ground_truth_path)

    if not isinstance(ground_truth, dict):
        raise ValueError("Ground truth file must be a JSON object.")

    requested_category = category
    if requested_category is None:
        requested_category = infer_category_from_tool_inputs(tool_inputs)

    # Important:
    # If the user gives paths like .../mobsf/Network and .../our_scanner/Network,
    # we must not silently fall back to evaluating every ground-truth case.  That
    # was the reason Network inputs still produced Platform output.  Therefore a
    # detected/requested category is applied strictly; if the ground truth has no
    # such category, fail loudly instead of writing misleading results.
    ground_truth = filter_ground_truth_by_category(ground_truth, requested_category)

    scope_categories = DEFAULT_SCOPE_CATEGORIES if use_scope_filter else None

    all_tool_rows: dict[str, list[dict[str, Any]]] = {}
    summary_rows: dict[str, dict[str, Any]] = {}

    for tool, input_root in tool_inputs.items():
        reports = load_normalized_reports(input_root, tool_name=tool)
        rows: list[dict[str, Any]] = []

        for case_id, gt_case in sorted(ground_truth.items()):
            report = reports.get(case_id)

            # fallback: allow ground_truth key "Platform/MASTG-TEST0007"
            # to match report case_id "MASTG-TEST0007"
            if report is None and "/" in case_id:
                report = reports.get(case_id.split("/")[-1])

            result = evaluate_case(
                case_id=case_id,
                gt_case=gt_case,
                report=report,
                must_detect_only=must_detect_only,
                scope_categories=scope_categories,
                ignore_third_party=ignore_third_party,
                top_k=top_k,
                high_conf_threshold=high_conf_threshold,
                high_sev_threshold=high_sev_threshold,
                min_severity_score=min_severity_score,
                min_confidence_score=min_confidence_score,
            )

            rows.append(result)

        all_tool_rows[tool] = rows
        summary_rows[tool] = aggregate_results(rows)

    category_dirs = write_category_outputs(
        output_root=output_dir,
        all_tool_rows=all_tool_rows,
        top_k=top_k,
        must_detect_only=must_detect_only,
        ignore_third_party=ignore_third_party,
        use_scope_filter=use_scope_filter,
        high_conf_threshold=high_conf_threshold,
        high_sev_threshold=high_sev_threshold,
        min_severity_score=min_severity_score,
        min_confidence_score=min_confidence_score,
    )

    if requested_category is not None:
        print(f"[OK] Category filter: {requested_category}")

    for category_dir in category_dirs:
        print(f"[OK] Category output: {category_dir}")
        print(f"     Summary JSON: {category_dir / 'summary.json'}")


def parse_tool_inputs(values: list[str]) -> dict[str, Path]:
    """
    CLI format:
        --tool mobsf=./reports/normalized/mobsf
        --tool our_scanner=./reports/our_scanner
    """

    result: dict[str, Path] = {}

    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid --tool format: {value}. Expected name=path")

        name, path = value.split("=", 1)
        name = name.strip()
        path = path.strip()

        if not name or not path:
            raise ValueError(f"Invalid --tool format: {value}. Expected name=path")

        result[name] = Path(path)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate normalized APK scanner reports against manually reviewed ground truth."
        )
    )

    parser.add_argument(
        "--ground-truth",
        default="./ground_truth.json",
        help="Path to ground truth JSON.",
    )

    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        help=(
            "Tool input in format name=path. "
            "Example: --tool mobsf=./reports/normalized/mobsf"
        ),
    )

    parser.add_argument(
        "--output-dir",
        default="./evaluation_results",
        help=(
            "Root directory for evaluation outputs. "
            "Category-specific outputs will be written to "
            "<output-dir>/<Category>/, e.g. ./evaluation_results/Platform."
        ),
    )

    parser.add_argument(
        "--category",
        default=None,
        help=(
            "Optional ground-truth category to evaluate, e.g. Platform or Network. "
            "Use ALL to force evaluating every category. If omitted, the script "
            "auto-detects a category when all --tool paths end with the same folder name."
        ),
    )

    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Top-k findings used for top-k precision.",
    )

    parser.add_argument(
        "--high-conf-threshold",
        type=int,
        default=8,
        help="Confidence score threshold for high-confidence precision.",
    )

    parser.add_argument(
        "--high-sev-threshold",
        type=int,
        default=8,
        help="Severity score threshold for high-priority precision.",
    )

    parser.add_argument(
        "--min-severity-score",
        type=int,
        default=None,
        help="Optional filter: ignore findings below this severity_score.",
    )

    parser.add_argument(
        "--min-confidence-score",
        type=int,
        default=None,
        help="Optional filter: ignore findings below this confidence_score.",
    )

    parser.add_argument(
        "--include-optional",
        action="store_true",
        help="Include expected vulnerabilities where must_detect=false.",
    )

    parser.add_argument(
        "--no-scope-filter",
        action="store_true",
        help="Do not filter findings by supported categories.",
    )

    parser.add_argument(
        "--keep-third-party",
        action="store_true",
        help="Do not filter third-party library findings.",
    )

    args = parser.parse_args()

    if not args.tool:
        args.tool = [
            "mobsf=./reports/normalized/mobsf",
            "our_scanner=./reports/our_scanner",
        ]

    tool_inputs = parse_tool_inputs(args.tool)

    evaluate_all(
        ground_truth_path=Path(args.ground_truth),
        tool_inputs=tool_inputs,
        output_dir=Path(args.output_dir),
        category=args.category,
        must_detect_only=not args.include_optional,
        ignore_third_party=not args.keep_third_party,
        use_scope_filter=not args.no_scope_filter,
        top_k=args.top_k,
        high_conf_threshold=args.high_conf_threshold,
        high_sev_threshold=args.high_sev_threshold,
        min_severity_score=args.min_severity_score,
        min_confidence_score=args.min_confidence_score,
    )


if __name__ == "__main__":
    main()