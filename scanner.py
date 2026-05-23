"""Core scan pipeline."""

from __future__ import annotations

import os
from pathlib import Path

from deep_link import extract_deep_links
from manifest_parser import extract_components, load_apk
from models import ScanResult
from poc_generator import attach_poc_commands
from report import write_json, write_markdown, write_poc_shell
from risk_rules import apply_risk_analysis
from vulnerability_patterns import detect_vulnerabilities


def scan_apk(apk_path: str) -> ScanResult:
    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    meta, root, custom_permissions = load_apk(apk_path)
    components = extract_components(
        root,
        meta.package_name,
        custom_permissions,
        meta.target_sdk,
    )
    deep_links = extract_deep_links(components)

    result = ScanResult(
        meta=meta,
        components=components,
        deep_links=deep_links,
        custom_permissions=custom_permissions,
    )
    apply_risk_analysis(result)
    attach_poc_commands(result)
    detect_vulnerabilities(result)
    return result


def scan_apk_to_dir(apk_path: str, output_dir: str) -> ScanResult:
    result = scan_apk(apk_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pkg = result.meta.package_name or "unknown"
    base = out / pkg

    write_json(result, base.with_suffix(".json"))
    write_markdown(result, base.with_suffix(".md"))
    write_poc_shell(result, base.with_name(base.name + "_poc.sh"))
    return result
