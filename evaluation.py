#!/usr/bin/env python3
"""
Benchmark Evaluation Script for Android APK Scanners.

Goal:
    Compare scanner reports against benchmark ground truth.

Supported scanners:
    - our_scanner
    - mobsf, placeholder parser included

Main design:
    This script treats benchmark labels as the primary source of truth.
    For benchmark suites such as OWApp / MASTG-style tests, the README usually
    documents the intended vulnerability for each APK, but it may not guarantee
    that no other issue exists. Therefore, the primary metric is benchmark recall:

        benchmark_recall = TP / (TP + FN)

    Extra findings are reported as "extra_findings" / "noise candidates",
    but they are not counted as FP by default.

Example usage:

    Single report:

        python evaluation.py ^
          --scanner our_scanner ^
          --result .\\reports\\our_scanner\\Platform\\MASTG-TEST0007\\com.example.mastg_test0007.json ^
          --ground-truth .\\ground_truth.json ^
          --app-id MASTG-TEST0007 ^
          --out .\\evaluation_results

    Folder mode:

        python evaluation.py ^
          --scanner our_scanner ^
          --result-dir .\\reports\\our_scanner ^
          --ground-truth .\\ground_truth.json ^
          --out .\\evaluation_results

Expected ground_truth.json shape:

{
  "benchmark": "OWApp",
  "apps": [
    {
      "app_id": "MASTG-TEST0007",
      "category": "Platform",
      "apk": "benchmarks/Platform/MASTG-TEST0007/MASTG-TEST0007.apk",
      "readme": "benchmarks/Platform/MASTG-TEST0007/README.md",
      "package": "com.example.mastg_test0007",
      "ground_truth": [
        {
          "gt_id": "MASTG-TEST0007-001",
          "type": "exported_provider",
          "target": "com.example.mastg_test0007.MyContentProvider",
          "severity": "critical",
          "expected_pattern_id": "VULN_EXPORTED_PROVIDER_LEAK",
          "description": "Exported ContentProvider without strong permission protection."
        }
      ]
    }
  ]
}
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Data Models
# ============================================================

@dataclass
class NormalizedFinding:
    scanner: str
    source: str

    # Common fields
    finding_id: Optional[str]
    type: Optional[str]
    title: Optional[str]
    severity: Optional[str]
    target: Optional[str]

    # For our_scanner vulnerability matching
    pattern_id: Optional[str]

    # For component-level matching
    component_kind: Optional[str]
    component_name: Optional[str]
    exported: Optional[str]
    permission: Optional[str]

    # Raw evidence / debugging
    evidence: List[str]
    raw: Dict[str, Any]


@dataclass
class MatchResult:
    gt_id: str
    matched: bool
    matched_by: Optional[str]
    matched_finding: Optional[Dict[str, Any]]
    reason: str


@dataclass
class AppEvaluationResult:
    scanner: str
    app_id: str
    package: Optional[str]
    category: Optional[str]

    tp: int
    fn: int
    total_ground_truth: int
    benchmark_recall: float

    total_findings: int
    extra_findings_count: int

    matched: List[MatchResult]
    missed: List[MatchResult]
    extra_findings: List[Dict[str, Any]]


# ============================================================
# Basic JSON helpers
# ============================================================

def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def normalize_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# ============================================================
# Ground truth loading
# ============================================================

def load_ground_truth(path: Path) -> Dict[str, Any]:
    data = load_json(path)

    if "apps" not in data or not isinstance(data["apps"], list):
        raise ValueError(
            "Invalid ground truth format: expected top-level key 'apps' as a list."
        )

    return data


def find_gt_app(ground_truth: Dict[str, Any], app_id: str) -> Dict[str, Any]:
    for app in ground_truth.get("apps", []):
        if app.get("app_id") == app_id:
            return app

    raise ValueError(f"app_id not found in ground truth: {app_id}")


def build_package_to_app_id_map(ground_truth: Dict[str, Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}

    for app in ground_truth.get("apps", []):
        package = app.get("package")
        app_id = app.get("app_id")
        if package and app_id:
            mapping[package] = app_id

    return mapping


# ============================================================
# our_scanner normalizer
# ============================================================

def normalize_our_scanner_report(report: Dict[str, Any], source: str) -> List[NormalizedFinding]:
    """
    Convert our_scanner JSON report into a list of NormalizedFinding.

    It extracts two levels:
        1. vulnerabilities[]    -> preferred for benchmark evaluation
        2. components[]         -> useful fallback if no vulnerability pattern exists
    """

    findings: List[NormalizedFinding] = []
    scanner = "our_scanner"

    # 1. Vulnerability-level findings
    for vuln in report.get("vulnerabilities", []):
        pattern_id = vuln.get("pattern_id")
        title = vuln.get("title")
        severity = vuln.get("severity")
        evidence = as_list(vuln.get("evidence"))
        related_components = as_list(vuln.get("related_components"))

        if related_components:
            target = str(related_components[0])
        else:
            target = None

        findings.append(
            NormalizedFinding(
                scanner=scanner,
                source=source,
                finding_id=pattern_id,
                type=infer_type_from_pattern_id(pattern_id),
                title=title,
                severity=severity,
                target=target,
                pattern_id=pattern_id,
                component_kind=None,
                component_name=target,
                exported=None,
                permission=None,
                evidence=[str(x) for x in evidence],
                raw=vuln,
            )
        )

    # 2. Component-level findings
    for comp in report.get("components", []):
        kind = comp.get("kind")
        name = comp.get("name")
        exported = comp.get("exported")
        permission = comp.get("permission")
        risk_tags = as_list(comp.get("risk_tags"))

        component_type = infer_type_from_component(kind, risk_tags)

        findings.append(
            NormalizedFinding(
                scanner=scanner,
                source=source,
                finding_id=None,
                type=component_type,
                title=f"{kind}: {name}" if kind and name else None,
                severity=priority_to_severity(comp.get("priority")),
                target=name,
                pattern_id=None,
                component_kind=kind,
                component_name=name,
                exported=str(exported) if exported is not None else None,
                permission=permission,
                evidence=[str(x) for x in risk_tags],
                raw=comp,
            )
        )

    return findings


def infer_type_from_pattern_id(pattern_id: Optional[str]) -> Optional[str]:
    if not pattern_id:
        return None

    pid = pattern_id.upper()

    if "EXPORTED_PROVIDER" in pid or "PROVIDER" in pid:
        return "exported_provider"
    if "EXPORTED_ACTIVITY" in pid or "ACTIVITY" in pid:
        return "exported_activity"
    if "EXPORTED_SERVICE" in pid or "SERVICE" in pid:
        return "exported_service"
    if "EXPORTED_RECEIVER" in pid or "RECEIVER" in pid:
        return "exported_receiver"
    if "DEEPLINK" in pid or "DEEP_LINK" in pid or "APP_LINK" in pid:
        return "deep_link"
    if "CLEAR_TEXT" in pid or "CLEARTEXT" in pid:
        return "cleartext_traffic"
    if "DEBUGGABLE" in pid:
        return "debuggable_app"
    if "BACKUP" in pid:
        return "allow_backup"

    return None


def infer_type_from_component(kind: Optional[str], risk_tags: List[Any]) -> Optional[str]:
    kind_norm = normalize_str(kind)
    tags = " ".join(str(x).upper() for x in risk_tags)

    if kind_norm == "provider":
        if "WEAK_PROVIDER_PROTECTION" in tags or "PROVIDER_EXPLICIT_EXPORTED" in tags:
            return "exported_provider"
        return "provider"

    if kind_norm == "activity":
        if "EXPORTED" in tags:
            return "exported_activity"
        return "activity"

    if kind_norm == "service":
        if "EXPORTED" in tags or "IMPLICIT" in tags:
            return "exported_service"
        return "service"

    if kind_norm == "receiver":
        if "EXPORTED" in tags:
            return "exported_receiver"
        return "receiver"

    return kind_norm if kind_norm else None


def priority_to_severity(priority: Optional[str]) -> Optional[str]:
    if priority is None:
        return None

    p = str(priority).upper()

    table = {
        "P0": "critical",
        "P1": "high",
        "P2": "medium",
        "P3": "low",
    }

    return table.get(p, None)


# ============================================================
# MobSF normalizer
# ============================================================

def normalize_mobsf_report(report: Dict[str, Any], source: str) -> List[NormalizedFinding]:
    """
    Best-effort MobSF JSON normalizer.

    MobSF JSON format can vary by version and export method.
    This parser intentionally handles common shapes defensively.

    You should inspect your real MobSF JSON later and improve this function.
    """

    findings: List[NormalizedFinding] = []
    scanner = "mobsf"

    # 1. manifest_analysis is common in MobSF reports
    manifest_analysis = report.get("manifest_analysis")

    if isinstance(manifest_analysis, list):
        for item in manifest_analysis:
            title = (
                item.get("title")
                or item.get("rule")
                or item.get("name")
                or item.get("description")
            )
            severity = item.get("severity") or item.get("level")
            description = item.get("description") or item.get("info") or ""
            component = (
                item.get("component")
                or item.get("component_name")
                or item.get("name")
                or item.get("title")
            )

            inferred_type = infer_type_from_text(
                " ".join(
                    [
                        str(title or ""),
                        str(description or ""),
                        str(component or ""),
                    ]
                )
            )

            findings.append(
                NormalizedFinding(
                    scanner=scanner,
                    source=source,
                    finding_id=item.get("rule_id") or item.get("id"),
                    type=inferred_type,
                    title=str(title) if title else None,
                    severity=str(severity) if severity else None,
                    target=str(component) if component else None,
                    pattern_id=None,
                    component_kind=None,
                    component_name=str(component) if component else None,
                    exported=None,
                    permission=None,
                    evidence=[str(description)] if description else [],
                    raw=item,
                )
            )

    # 2. Some MobSF exports contain dictionaries by severity or issue name
    elif isinstance(manifest_analysis, dict):
        for key, value in manifest_analysis.items():
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    text = json.dumps(item, ensure_ascii=False)
                    title = item.get("title") or item.get("name") or key
                    component = item.get("component") or item.get("name")
                    severity = item.get("severity")
                    raw = item
                else:
                    text = str(item)
                    title = key
                    component = text
                    severity = None
                    raw = {"key": key, "value": item}

                findings.append(
                    NormalizedFinding(
                        scanner=scanner,
                        source=source,
                        finding_id=None,
                        type=infer_type_from_text(f"{key} {text}"),
                        title=str(title) if title else None,
                        severity=str(severity) if severity else None,
                        target=str(component) if component else None,
                        pattern_id=None,
                        component_kind=None,
                        component_name=str(component) if component else None,
                        exported=None,
                        permission=None,
                        evidence=[text],
                        raw=raw,
                    )
                )

    # 3. Try common top-level fields for exported components
    common_component_fields = [
        ("exported_activities", "exported_activity", "activity"),
        ("exported_services", "exported_service", "service"),
        ("exported_receivers", "exported_receiver", "receiver"),
        ("exported_providers", "exported_provider", "provider"),
        ("activities", "activity", "activity"),
        ("services", "service", "service"),
        ("receivers", "receiver", "receiver"),
        ("providers", "provider", "provider"),
    ]

    for field_name, finding_type, component_kind in common_component_fields:
        value = report.get(field_name)
        for item in extract_possible_component_list(value):
            findings.append(
                NormalizedFinding(
                    scanner=scanner,
                    source=source,
                    finding_id=None,
                    type=finding_type,
                    title=f"{component_kind}: {item}",
                    severity=None,
                    target=item,
                    pattern_id=None,
                    component_kind=component_kind,
                    component_name=item,
                    exported="true" if finding_type.startswith("exported_") else None,
                    permission=None,
                    evidence=[field_name],
                    raw={"field": field_name, "value": item},
                )
            )

    # 4. Permissions / network / backup / debug fields can be added later
    # For now, keep parser conservative.

    return findings


def extract_possible_component_list(value: Any) -> List[str]:
    if value is None:
        return []

    result: List[str] = []

    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("component") or item.get("class")
                if name:
                    result.append(str(name))

    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("component") or key
                if name:
                    result.append(str(name))
            else:
                result.append(str(key))

    elif isinstance(value, str):
        result.append(value)

    return result


def infer_type_from_text(text: str) -> Optional[str]:
    t = text.lower()

    if "contentprovider" in t or "content provider" in t or "provider" in t:
        if "export" in t or "exposed" in t:
            return "exported_provider"
        return "provider"

    if "activity" in t:
        if "export" in t or "exposed" in t:
            return "exported_activity"
        return "activity"

    if "service" in t:
        if "export" in t or "implicit" in t or "exposed" in t:
            return "exported_service"
        return "service"

    if "receiver" in t or "broadcast" in t:
        if "export" in t or "exposed" in t:
            return "exported_receiver"
        return "receiver"

    if "deep link" in t or "deeplink" in t or "app link" in t:
        return "deep_link"

    if "cleartext" in t or "clear text" in t:
        return "cleartext_traffic"

    if "debuggable" in t:
        return "debuggable_app"

    if "backup" in t:
        return "allow_backup"

    return None


# ============================================================
# Scanner dispatch
# ============================================================

def normalize_report(scanner: str, report: Dict[str, Any], source: str) -> List[NormalizedFinding]:
    scanner_norm = scanner.lower().strip()

    if scanner_norm in {"our", "ours", "our_scanner"}:
        return normalize_our_scanner_report(report, source)

    if scanner_norm in {"mobsf", "mobile_security_framework"}:
        return normalize_mobsf_report(report, source)

    raise ValueError(f"Unsupported scanner: {scanner}")


# ============================================================
# Matching logic
# ============================================================

def evaluate_app(
    scanner: str,
    app_gt: Dict[str, Any],
    report: Dict[str, Any],
    report_path: Path,
) -> AppEvaluationResult:
    findings = normalize_report(scanner, report, str(report_path))

    gt_items = app_gt.get("ground_truth", [])
    if not isinstance(gt_items, list):
        raise ValueError(f"Invalid ground_truth for app_id={app_gt.get('app_id')}: expected list.")

    matched_results: List[MatchResult] = []
    missed_results: List[MatchResult] = []
    used_finding_indexes = set()

    for gt in gt_items:
        matched, finding_index, matched_by, reason = match_one_ground_truth(gt, findings)

        gt_id = str(gt.get("gt_id") or gt.get("id") or "UNKNOWN_GT")

        if matched and finding_index is not None:
            used_finding_indexes.add(finding_index)
            result = MatchResult(
                gt_id=gt_id,
                matched=True,
                matched_by=matched_by,
                matched_finding=asdict(findings[finding_index]),
                reason=reason,
            )
            matched_results.append(result)
        else:
            result = MatchResult(
                gt_id=gt_id,
                matched=False,
                matched_by=None,
                matched_finding=None,
                reason=reason,
            )
            missed_results.append(result)

    tp = len(matched_results)
    fn = len(missed_results)
    total_gt = len(gt_items)
    recall = safe_div(tp, total_gt)

    extra_findings = []
    for idx, finding in enumerate(findings):
        if idx not in used_finding_indexes:
            extra_findings.append(asdict(finding))

    return AppEvaluationResult(
        scanner=scanner,
        app_id=str(app_gt.get("app_id")),
        package=app_gt.get("package"),
        category=app_gt.get("category"),
        tp=tp,
        fn=fn,
        total_ground_truth=total_gt,
        benchmark_recall=recall,
        total_findings=len(findings),
        extra_findings_count=len(extra_findings),
        matched=matched_results,
        missed=missed_results,
        extra_findings=extra_findings,
    )


def match_one_ground_truth(
    gt: Dict[str, Any],
    findings: List[NormalizedFinding],
) -> Tuple[bool, Optional[int], Optional[str], str]:
    """
    Matching priority:
        1. expected_pattern_id exact match
        2. type + target exact / suffix / containment match
        3. target-only fallback
        4. match object fallback: kind/exported/permission_required
        5. type-only fallback, optional if allow_type_only_match is true
    """

    expected_pattern_id = gt.get("expected_pattern_id")
    gt_type = gt.get("type")
    gt_target = gt.get("target")

    # --------------------------------------------------------
    # 1. pattern_id exact match
    # --------------------------------------------------------
    if expected_pattern_id:
        for idx, finding in enumerate(findings):
            if normalize_str(finding.pattern_id) == normalize_str(expected_pattern_id):
                return (
                    True,
                    idx,
                    "expected_pattern_id",
                    f"Matched by pattern_id: {expected_pattern_id}",
                )

    # --------------------------------------------------------
    # 2. type + target match
    # --------------------------------------------------------
    if gt_type and gt_target and normalize_str(gt_target) not in {"unknown", "n/a", "none"}:
        for idx, finding in enumerate(findings):
            if not loose_equal(gt_type, finding.type):
                continue

            candidate_targets = [
                finding.target,
                finding.component_name,
                finding.title,
            ]

            for candidate in candidate_targets:
                if target_matches(str(gt_target), candidate):
                    return (
                        True,
                        idx,
                        "type_and_target",
                        f"Matched by type={gt_type} and target={gt_target}",
                    )

    # --------------------------------------------------------
    # 3. target-only fallback
    # --------------------------------------------------------
    if gt_target and normalize_str(gt_target) not in {"unknown", "n/a", "none"}:
        for idx, finding in enumerate(findings):
            candidate_targets = [
                finding.target,
                finding.component_name,
                finding.title,
            ]

            for candidate in candidate_targets:
                if target_matches(str(gt_target), candidate):
                    return (
                        True,
                        idx,
                        "target",
                        f"Matched by target={gt_target}",
                    )

    # --------------------------------------------------------
    # 4. match object fallback
    # --------------------------------------------------------
    match_rule = gt.get("match")
    if isinstance(match_rule, dict):
        for idx, finding in enumerate(findings):
            if match_by_rule(match_rule, finding):
                return (
                    True,
                    idx,
                    "match_rule",
                    f"Matched by custom match rule: {match_rule}",
                )

    # --------------------------------------------------------
    # 5. type-only fallback
    # --------------------------------------------------------
    allow_type_only = bool(gt.get("allow_type_only_match", False))
    if allow_type_only and gt_type:
        for idx, finding in enumerate(findings):
            if loose_equal(gt_type, finding.type):
                return (
                    True,
                    idx,
                    "type_only",
                    f"Matched by type only: {gt_type}",
                )

    return (
        False,
        None,
        None,
        "No scanner finding matched this ground truth item.",
    )


def loose_equal(a: Any, b: Any) -> bool:
    return normalize_str(a) == normalize_str(b)


def target_matches(expected: str, actual: Optional[str]) -> bool:
    if actual is None:
        return False

    e = normalize_str(expected)
    a = normalize_str(actual)

    if not e or not a:
        return False

    if e == a:
        return True

    # Handles ".MyProvider" vs "com.example.MyProvider"
    if a.endswith(e) or e.endswith(a):
        return True

    # Handles evidence strings containing component names
    if e in a or a in e:
        return True

    # Handles class simple name match
    e_simple = e.split(".")[-1]
    a_simple = a.split(".")[-1]
    if e_simple and a_simple and e_simple == a_simple:
        return True

    return False


def match_by_rule(rule: Dict[str, Any], finding: NormalizedFinding) -> bool:
    """
    Supported match rule examples:

    "match": {
      "kind": "provider",
      "exported": "true",
      "permission_required": false
    }

    "match": {
      "component_type": "provider",
      "exported": true,
      "permission_required": false
    }
    """

    expected_kind = rule.get("kind") or rule.get("component_type")
    expected_exported = rule.get("exported")
    permission_required = rule.get("permission_required")

    if expected_kind:
        if normalize_str(expected_kind) != normalize_str(finding.component_kind):
            return False

    if expected_exported is not None:
        expected_exported_str = normalize_boolish(expected_exported)
        actual_exported_str = normalize_boolish(finding.exported)
        if expected_exported_str != actual_exported_str:
            return False

    if permission_required is not None:
        has_permission = bool(finding.permission)

        if bool(permission_required) != has_permission:
            return False

    return True


def normalize_boolish(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"

    s = normalize_str(value)

    if s in {"true", "1", "yes"}:
        return "true"
    if s in {"false", "0", "no", ""}:
        return "false"

    return s


def safe_div(a: int, b: int) -> float:
    if b == 0:
        return 0.0
    return a / b


# ============================================================
# Report discovery
# ============================================================

def infer_package_from_report(report: Dict[str, Any]) -> Optional[str]:
    meta = report.get("meta")
    if isinstance(meta, dict):
        if meta.get("package_name"):
            return meta.get("package_name")

    # Possible MobSF fields
    for key in ["package_name", "packagename", "package"]:
        if report.get(key):
            return report.get(key)

    return None


def discover_json_reports(result_dir: Path) -> List[Path]:
    if not result_dir.exists():
        raise FileNotFoundError(f"Result directory not found: {result_dir}")

    reports = []
    for path in result_dir.rglob("*.json"):
        # Avoid reading previous evaluation result files by accident
        name = path.name.lower()
        if name.startswith("evaluation_") or name in {"summary.json", "summary.csv"}:
            continue
        reports.append(path)

    return sorted(reports)


def infer_app_id_for_report(
    report_path: Path,
    report: Dict[str, Any],
    ground_truth: Dict[str, Any],
) -> Optional[str]:
    # 1. package mapping
    package = infer_package_from_report(report)
    package_map = build_package_to_app_id_map(ground_truth)
    if package and package in package_map:
        return package_map[package]

    # 2. path contains app_id
    path_text = str(report_path).lower()
    for app in ground_truth.get("apps", []):
        app_id = app.get("app_id")
        if app_id and normalize_str(app_id) in path_text:
            return app_id

    # 3. filename contains app_id
    filename = report_path.name.lower()
    for app in ground_truth.get("apps", []):
        app_id = app.get("app_id")
        if app_id and normalize_str(app_id) in filename:
            return app_id

    return None


# ============================================================
# Output writers
# ============================================================

def write_app_result(out_dir: Path, result: AppEvaluationResult) -> Path:
    scanner_dir = out_dir / result.scanner
    scanner_dir.mkdir(parents=True, exist_ok=True)

    out_path = scanner_dir / f"{result.app_id}_evaluation.json"
    write_json(out_path, asdict(result))
    return out_path


def write_summary_csv(out_dir: Path, scanner: str, results: List[AppEvaluationResult]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{scanner}_summary.csv"

    fields = [
        "scanner",
        "app_id",
        "package",
        "category",
        "tp",
        "fn",
        "total_ground_truth",
        "benchmark_recall",
        "total_findings",
        "extra_findings_count",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "scanner": r.scanner,
                "app_id": r.app_id,
                "package": r.package,
                "category": r.category,
                "tp": r.tp,
                "fn": r.fn,
                "total_ground_truth": r.total_ground_truth,
                "benchmark_recall": f"{r.benchmark_recall:.4f}",
                "total_findings": r.total_findings,
                "extra_findings_count": r.extra_findings_count,
            })

    return out_path


def write_overall_json(out_dir: Path, scanner: str, results: List[AppEvaluationResult]) -> Path:
    total_tp = sum(r.tp for r in results)
    total_fn = sum(r.fn for r in results)
    total_gt = sum(r.total_ground_truth for r in results)
    total_findings = sum(r.total_findings for r in results)
    total_extra = sum(r.extra_findings_count for r in results)

    overall = {
        "scanner": scanner,
        "apps_evaluated": len(results),
        "total_tp": total_tp,
        "total_fn": total_fn,
        "total_ground_truth": total_gt,
        "overall_benchmark_recall": safe_div(total_tp, total_gt),
        "total_findings": total_findings,
        "total_extra_findings": total_extra,
        "note": (
            "Extra findings are not counted as false positives by default, "
            "because benchmark labels may not be exhaustive."
        ),
        "apps": [
            {
                "app_id": r.app_id,
                "category": r.category,
                "tp": r.tp,
                "fn": r.fn,
                "total_ground_truth": r.total_ground_truth,
                "benchmark_recall": r.benchmark_recall,
                "total_findings": r.total_findings,
                "extra_findings_count": r.extra_findings_count,
            }
            for r in results
        ],
    }

    out_path = out_dir / f"{scanner}_overall.json"
    write_json(out_path, overall)
    return out_path


# ============================================================
# CLI
# ============================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate Android scanner reports against benchmark ground truth."
    )

    parser.add_argument(
        "--scanner",
        required=True,
        choices=["our_scanner", "our", "mobsf"],
        help="Scanner report format.",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--result",
        help="Path to a single scanner result JSON.",
    )
    input_group.add_argument(
        "--result-dir",
        help="Path to a directory containing scanner result JSON files.",
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Path to ground_truth.json.",
    )

    parser.add_argument(
        "--app-id",
        default=None,
        help="Benchmark app id, e.g. MASTG-TEST0007. Required for single result unless it can be inferred.",
    )

    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for evaluation results.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    scanner = canonical_scanner_name(args.scanner)
    gt_path = Path(args.ground_truth)
    out_dir = Path(args.out)

    try:
        ground_truth = load_ground_truth(gt_path)

        if args.result:
            results = run_single_result(
                scanner=scanner,
                result_path=Path(args.result),
                ground_truth=ground_truth,
                app_id=args.app_id,
                out_dir=out_dir,
            )
        else:
            results = run_result_dir(
                scanner=scanner,
                result_dir=Path(args.result_dir),
                ground_truth=ground_truth,
                out_dir=out_dir,
            )

        summary_csv = write_summary_csv(out_dir, scanner, results)
        overall_json = write_overall_json(out_dir, scanner, results)

        print()
        print("Evaluation completed.")
        print(f"Scanner: {scanner}")
        print(f"Apps evaluated: {len(results)}")
        print(f"Summary CSV: {summary_csv.resolve()}")
        print(f"Overall JSON: {overall_json.resolve()}")
        print()

        total_tp = sum(r.tp for r in results)
        total_fn = sum(r.fn for r in results)
        total_gt = sum(r.total_ground_truth for r in results)
        print(f"Total TP: {total_tp}")
        print(f"Total FN: {total_fn}")
        print(f"Total ground truth: {total_gt}")
        print(f"Overall benchmark recall: {safe_div(total_tp, total_gt):.4f}")
        print()

        return 0

    except Exception as err:
        print(f"Evaluation failed: {err}", file=sys.stderr)
        return 1


def canonical_scanner_name(scanner: str) -> str:
    s = scanner.lower().strip()

    if s in {"our", "ours", "our_scanner"}:
        return "our_scanner"

    if s == "mobsf":
        return "mobsf"

    raise ValueError(f"Unsupported scanner: {scanner}")


def run_single_result(
    scanner: str,
    result_path: Path,
    ground_truth: Dict[str, Any],
    app_id: Optional[str],
    out_dir: Path,
) -> List[AppEvaluationResult]:
    report = load_json(result_path)

    actual_app_id = app_id
    if actual_app_id is None:
        actual_app_id = infer_app_id_for_report(result_path, report, ground_truth)

    if actual_app_id is None:
        raise ValueError(
            "Cannot infer app_id. Please provide --app-id, e.g. --app-id MASTG-TEST0007."
        )

    app_gt = find_gt_app(ground_truth, actual_app_id)

    result = evaluate_app(
        scanner=scanner,
        app_gt=app_gt,
        report=report,
        report_path=result_path,
    )

    app_result_path = write_app_result(out_dir, result)

    print()
    print(f"Evaluated app: {result.app_id}")
    print(f"Result file: {app_result_path.resolve()}")
    print(f"TP={result.tp}, FN={result.fn}, Recall={result.benchmark_recall:.4f}")
    print(f"Total findings: {result.total_findings}")
    print(f"Extra findings: {result.extra_findings_count}")

    return [result]


def run_result_dir(
    scanner: str,
    result_dir: Path,
    ground_truth: Dict[str, Any],
    out_dir: Path,
) -> List[AppEvaluationResult]:
    reports = discover_json_reports(result_dir)

    if not reports:
        raise ValueError(f"No JSON reports found under: {result_dir}")

    results: List[AppEvaluationResult] = []
    skipped: List[Tuple[str, str]] = []

    for report_path in reports:
        try:
            report = load_json(report_path)
            app_id = infer_app_id_for_report(report_path, report, ground_truth)

            if app_id is None:
                skipped.append((str(report_path), "Cannot infer app_id"))
                continue

            app_gt = find_gt_app(ground_truth, app_id)

            result = evaluate_app(
                scanner=scanner,
                app_gt=app_gt,
                report=report,
                report_path=report_path,
            )

            write_app_result(out_dir, result)
            results.append(result)

            print(
                f"[OK] {app_id}: "
                f"TP={result.tp}, FN={result.fn}, Recall={result.benchmark_recall:.4f}"
            )

        except Exception as err:
            skipped.append((str(report_path), str(err)))

    if skipped:
        skipped_path = out_dir / f"{scanner}_skipped.json"
        write_json(skipped_path, {
            "scanner": scanner,
            "skipped": [
                {
                    "path": path,
                    "reason": reason,
                }
                for path, reason in skipped
            ],
        })

        print()
        print(f"Skipped {len(skipped)} report(s). Details: {skipped_path.resolve()}")

    if not results:
        raise ValueError("No reports were successfully evaluated.")

    return results


if __name__ == "__main__":
    sys.exit(main())