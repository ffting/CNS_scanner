#!/usr/bin/env python3
import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "warning": 3,
    "low": 2,
    "info": 1,
    "secure": 0,
    "unknown": 0,
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

    # SQL / provider
    "content_provider_sql_injection",
    "sql_injection",
    "unsafe_sql_query",
    "unsafe_content_provider_query",

    # Deep link / intent
    "deep_link",
    "insecure_deep_link",
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

    # UI disclosure / notification
    "unobscured_sensitive_input",
    "unobscured_input",
    "sensitive_ui_disclosure",
    "missing_password_input_type",
    "plaintext_notification",
    "sensitive_data_in_notification",

    # Other common supported categories
    "hardcoded_secret",
    "logging_sensitive_data",
    "local_file_io",
    "content_provider_usage",
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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def normalize_category(value: Any) -> str:
    return normalize_text(value).strip().replace(" ", "_").replace("-", "_")


def severity_score(value: Any) -> int:
    return SEVERITY_RANK.get(normalize_text(value), 0)


def get_expected_list(gt_case: Dict[str, Any], must_detect_only: bool) -> List[Dict[str, Any]]:
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


def get_finding_text(finding: Dict[str, Any]) -> str:
    parts = [
        finding.get("category", ""),
        finding.get("title", ""),
        finding.get("evidence", ""),
        finding.get("file", ""),
        finding.get("raw_rule", ""),
        finding.get("source", ""),
    ]
    return normalize_text(" ".join(str(p) for p in parts if p is not None))


def get_gt_text(gt: Dict[str, Any]) -> str:
    parts = [
        gt.get("category", ""),
        gt.get("description", ""),
        " ".join(gt.get("acceptable_scanner_categories", []) or []),
        " ".join(gt.get("evidence_keywords", []) or []),
    ]
    return normalize_text(" ".join(str(p) for p in parts if p is not None))


def is_third_party_finding(finding: Dict[str, Any]) -> bool:
    text = get_finding_text(finding)
    return any(hint.lower() in text for hint in THIRD_PARTY_PATH_HINTS)


def category_matches(finding: Dict[str, Any], gt: Dict[str, Any]) -> bool:
    finding_category = normalize_category(finding.get("category", ""))
    gt_category = normalize_category(gt.get("category", ""))

    acceptable = gt.get("acceptable_scanner_categories", []) or []
    acceptable = {normalize_category(x) for x in acceptable}
    acceptable.add(gt_category)

    return finding_category in acceptable


def keyword_matches(finding: Dict[str, Any], gt: Dict[str, Any]) -> bool:
    keywords = gt.get("evidence_keywords", []) or []
    if not keywords:
        return False

    text = get_finding_text(finding)

    # 至少命中一個 keyword 就算弱匹配。
    # 若你覺得太鬆，可以改成 required_hits >= 2。
    required_hits = 1
    hits = 0

    for kw in keywords:
        kw = normalize_text(kw).strip()
        if kw and kw in text:
            hits += 1

    return hits >= required_hits


def finding_matches_gt(finding: Dict[str, Any], gt: Dict[str, Any]) -> bool:
    return category_matches(finding, gt) or keyword_matches(finding, gt)


def get_case_id_from_report_path(path: Path, input_root: Path) -> str:
    """
    reports/normalized/mobsf/Platform/MASTG-TEST0007.json
    -> Platform/MASTG-TEST0007
    """
    rel = path.relative_to(input_root)
    category = rel.parent.as_posix()
    case_name = path.stem
    if category == ".":
        return case_name
    return f"{category}/{case_name}"


def load_normalized_reports(input_root: Path, tool_name: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    reports = {}

    if not input_root.exists():
        return reports

    for path in sorted(input_root.rglob("*.json")):
        try:
            report = load_json(path)
        except Exception as e:
            print(f"[WARN] Cannot read report {path}: {e}")
            continue

        case_id = report.get("case_id")
        if not case_id:
            case_id = get_case_id_from_report_path(path, input_root)
            report["case_id"] = case_id

        if tool_name and not report.get("tool"):
            report["tool"] = tool_name

        findings = report.get("findings", [])
        if not isinstance(findings, list):
            report["findings"] = []

        reports[case_id] = report

    return reports


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            int(f.get("confidence", 0) or 0),
            severity_score(f.get("severity")),
        ),
        reverse=True,
    )


def filter_scope_findings(
    findings: List[Dict[str, Any]],
    scope_categories: Optional[set],
    ignore_third_party: bool,
) -> List[Dict[str, Any]]:
    result = []

    for f in findings:
        category = normalize_category(f.get("category", ""))

        if scope_categories is not None and category not in scope_categories:
            continue

        if ignore_third_party and is_third_party_finding(f):
            continue

        result.append(f)

    return result


def evaluate_case(
    case_id: str,
    gt_case: Dict[str, Any],
    report: Optional[Dict[str, Any]],
    must_detect_only: bool,
    scope_categories: Optional[set],
    ignore_third_party: bool,
    top_k: int,
) -> Dict[str, Any]:
    expected = get_expected_list(gt_case, must_detect_only=must_detect_only)

    raw_findings = []
    if report:
        raw_findings = report.get("findings", []) or []

    findings = filter_scope_findings(
        raw_findings,
        scope_categories=scope_categories,
        ignore_third_party=ignore_third_party,
    )
    findings = sort_findings(findings)

    matched_gt_indices = set()
    matched_finding_indices = set()
    matches = []

    for gi, gt in enumerate(expected):
        for fi, finding in enumerate(findings):
            if fi in matched_finding_indices:
                continue

            if finding_matches_gt(finding, gt):
                matched_gt_indices.add(gi)
                matched_finding_indices.add(fi)
                matches.append({
                    "gt_category": gt.get("category", ""),
                    "finding_category": finding.get("category", ""),
                    "finding_title": finding.get("title", ""),
                    "finding_severity": finding.get("severity", ""),
                    "finding_confidence": finding.get("confidence", ""),
                })
                break

    tp = len(matched_gt_indices)
    fn = max(0, len(expected) - tp)

    # 這裡的 FP 是「在 scope 內，但沒有對應到 ground truth 的 finding」。
    # 如果你覺得太嚴格，可以只把 high/medium finding 計入 FP。
    fp = max(0, len(findings) - len(matched_finding_indices))

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    top_findings = findings[:top_k]
    top_matched = 0

    for f in top_findings:
        if any(finding_matches_gt(f, gt) for gt in expected):
            top_matched += 1

    topk_precision = top_matched / len(top_findings) if top_findings else None

    return {
        "case_id": case_id,
        "test_id": gt_case.get("test_id", ""),
        "title": gt_case.get("title", ""),
        "expected_count": len(expected),
        "raw_finding_count": len(raw_findings),
        "scoped_finding_count": len(findings),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        f"top{top_k}_precision": topk_precision,
        "matches": matches,
        "unmatched_expected": [
            gt for i, gt in enumerate(expected) if i not in matched_gt_indices
        ],
        "unmatched_findings": [
            f for i, f in enumerate(findings) if i not in matched_finding_indices
        ],
    }


def aggregate_results(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_tp = sum(r["tp"] for r in rows)
    total_fp = sum(r["fp"] for r in rows)
    total_fn = sum(r["fn"] for r in rows)
    total_expected = sum(r["expected_count"] for r in rows)
    total_raw_findings = sum(r["raw_finding_count"] for r in rows)
    total_scoped_findings = sum(r["scoped_finding_count"] for r in rows)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else None
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    return {
        "cases": len(rows),
        "expected": total_expected,
        "raw_findings": total_raw_findings,
        "scoped_findings": total_scoped_findings,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def fmt_float(x: Optional[float]) -> str:
    if x is None:
        return "N/A"
    return f"{x:.4f}"


def write_case_csv(path: Path, tool_rows: Dict[str, List[Dict[str, Any]]], top_k: int) -> None:
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
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for tool, rows in tool_rows.items():
            for r in rows:
                writer.writerow({
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
                })


def write_summary_csv(path: Path, summary_rows: Dict[str, Dict[str, Any]]) -> None:
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
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for tool, s in summary_rows.items():
            writer.writerow({
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
            })


def write_markdown_report(
    path: Path,
    tool_rows: Dict[str, List[Dict[str, Any]]],
    summary_rows: Dict[str, Dict[str, Any]],
    top_k: int,
    must_detect_only: bool,
    ignore_third_party: bool,
    use_scope_filter: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("# Evaluation Report")
    lines.append("")
    lines.append("## Settings")
    lines.append("")
    lines.append(f"- Must-detect only: `{must_detect_only}`")
    lines.append(f"- Ignore third-party findings: `{ignore_third_party}`")
    lines.append(f"- Scope filter enabled: `{use_scope_filter}`")
    lines.append(f"- Top-k: `{top_k}`")
    lines.append("")
    lines.append("## Overall Summary")
    lines.append("")
    lines.append("| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

    for tool, s in summary_rows.items():
        lines.append(
            f"| {tool} | {s['cases']} | {s['expected']} | {s['raw_findings']} | "
            f"{s['scoped_findings']} | {s['tp']} | {s['fp']} | {s['fn']} | "
            f"{fmt_float(s['precision'])} | {fmt_float(s['recall'])} | {fmt_float(s['f1'])} |"
        )

    lines.append("")
    lines.append("## Per-case Results")
    lines.append("")

    for tool, rows in tool_rows.items():
        lines.append(f"### {tool}")
        lines.append("")
        lines.append(f"| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-{top_k} Precision |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")

        for r in rows:
            lines.append(
                f"| {r['case_id']} | {r['expected_count']} | {r['scoped_finding_count']} | "
                f"{r['tp']} | {r['fp']} | {r['fn']} | "
                f"{fmt_float(r['precision'])} | {fmt_float(r['recall'])} | "
                f"{fmt_float(r['f1'])} | {fmt_float(r[f'top{top_k}_precision'])} |"
            )

        lines.append("")

    lines.append("## Unmatched Details")
    lines.append("")
    lines.append("This section is useful for manually checking false positives and false negatives.")
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
                        f"- `{gt.get('category', '')}`: {gt.get('description', '')}"
                    )
                lines.append("")

            if r["unmatched_findings"]:
                lines.append("Unmatched findings:")
                lines.append("")
                for f in r["unmatched_findings"][:10]:
                    title = str(f.get("title", "")).replace("\n", " ")
                    evidence = str(f.get("evidence", "")).replace("\n", " ")
                    if len(evidence) > 160:
                        evidence = evidence[:160] + "..."
                    lines.append(
                        f"- `{f.get('category', '')}` "
                        f"severity=`{f.get('severity', '')}` "
                        f"confidence=`{f.get('confidence', '')}` "
                        f"title={title} evidence={evidence}"
                    )
                lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def evaluate_all(
    ground_truth_path: Path,
    tool_inputs: Dict[str, Path],
    output_dir: Path,
    must_detect_only: bool,
    ignore_third_party: bool,
    use_scope_filter: bool,
    top_k: int,
) -> None:
    ground_truth = load_json(ground_truth_path)

    if not isinstance(ground_truth, dict):
        raise ValueError("ground truth file must be a JSON object")

    scope_categories = DEFAULT_SCOPE_CATEGORIES if use_scope_filter else None

    all_tool_rows = {}
    summary_rows = {}

    for tool, input_root in tool_inputs.items():
        reports = load_normalized_reports(input_root, tool_name=tool)
        rows = []

        for case_id, gt_case in sorted(ground_truth.items()):
            report = reports.get(case_id)

            result = evaluate_case(
                case_id=case_id,
                gt_case=gt_case,
                report=report,
                must_detect_only=must_detect_only,
                scope_categories=scope_categories,
                ignore_third_party=ignore_third_party,
                top_k=top_k,
            )
            rows.append(result)

        all_tool_rows[tool] = rows
        summary_rows[tool] = aggregate_results(rows)

    output_dir.mkdir(parents=True, exist_ok=True)

    write_case_csv(output_dir / "case_results.csv", all_tool_rows, top_k=top_k)
    write_summary_csv(output_dir / "summary_results.csv", summary_rows)
    write_markdown_report(
        output_dir / "evaluation_report.md",
        all_tool_rows,
        summary_rows,
        top_k=top_k,
        must_detect_only=must_detect_only,
        ignore_third_party=ignore_third_party,
        use_scope_filter=use_scope_filter,
    )

    write_json(output_dir / "case_results.json", all_tool_rows)
    write_json(output_dir / "summary_results.json", summary_rows)

    print(f"[OK] Wrote results to: {output_dir}")
    print(f"[OK] Summary: {output_dir / 'summary_results.csv'}")
    print(f"[OK] Cases:   {output_dir / 'case_results.csv'}")
    print(f"[OK] Report:  {output_dir / 'evaluation_report.md'}")


def parse_tool_inputs(values: List[str]) -> Dict[str, Path]:
    """
    CLI format:
      --tool mobsf=./reports/normalized/mobsf
      --tool our_scanner=./reports/normalized/our_scanner
    """
    result = {}

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


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate normalized APK scanner reports against manually reviewed ground truth."
    )
    parser.add_argument(
        "--ground-truth",
        default="./ground_truth_platform.json",
        help="Path to manually reviewed ground truth JSON.",
    )
    parser.add_argument(
        "--tool",
        action="append",
        default=[],
        help="Tool input in format name=path. Example: --tool mobsf=./reports/normalized/mobsf",
    )
    parser.add_argument(
        "--output-dir",
        default="./evaluation_results",
        help="Directory for CSV/JSON/Markdown outputs.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Top-k findings used for top-k precision.",
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
        # Default tools
        args.tool = [
            "mobsf=./reports/normalized/mobsf",
            "our_scanner=./reports/normalized/our_scanner",
        ]

    tool_inputs = parse_tool_inputs(args.tool)

    evaluate_all(
        ground_truth_path=Path(args.ground_truth),
        tool_inputs=tool_inputs,
        output_dir=Path(args.output_dir),
        must_detect_only=not args.include_optional,
        ignore_third_party=not args.keep_third_party,
        use_scope_filter=not args.no_scope_filter,
        top_k=args.top_k,
    )


if __name__ == "__main__":
    main()