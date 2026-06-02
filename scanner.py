"""Core scan pipeline.

This module is the coordinator of the scanner.

Responsibilities:
- Validate APK path
- Load APK / AndroidManifest.xml
- Extract platform-level attack surfaces
- Extract deep links
- Apply heuristic risk tags
- Generate PoC commands
- Detect vulnerability patterns and attack chains
- Apply severity / confidence scoring
- Write reports when requested
"""

from __future__ import annotations

import os
from pathlib import Path

from network_code_scanner import scan_network_code_patterns

from api_key_scanner import (
    extract_full_tokens_for_verification,
    scan_apk_for_api_keys,
    verify_full_tokens,
)
from deep_link import extract_deep_links
from manifest_parser import extract_components, load_apk
from models import ScanResult
from poc_generator import attach_poc_commands
from report import write_json, write_markdown, write_poc_shell
from test_plan import write_test_plan_markdown
from risk_rules import apply_risk_analysis
from scoring import apply_scoring
from vulnerability_patterns import detect_vulnerabilities

DEFAULT_VERIFY_PROVIDERS = frozenset({
    "github",
    "stripe",
    "slack",
    "openai",
    "google",
    "firebase",
    "anthropic",
})


def _scan_api_keys(apk_path: str, result: ScanResult) -> None:
    """Static secret scan + optional online verification for supported providers."""
    result.api_keys = scan_apk_for_api_keys(apk_path)
    if not result.summary:
        result.summary = {}

    result.summary["api_key_candidate_count"] = len(result.api_keys)
    result.summary["api_key_confirmed_count"] = sum(1 for k in result.api_keys if k.verified)
    result.summary["api_key_warning_count"] = sum(1 for k in result.api_keys if not k.verified)

    if not result.api_keys:
        return

    full_tokens = extract_full_tokens_for_verification(
        apk_path,
        allow_providers=DEFAULT_VERIFY_PROVIDERS,
    )
    verified = verify_full_tokens(full_tokens, allow_providers=DEFAULT_VERIFY_PROVIDERS)
    for finding in result.api_keys:
        if finding.fingerprint in verified:
            ok, detail = verified[finding.fingerprint]
            finding.verified = ok
            finding.verification_detail = detail
        else:
            finding.verification_detail = (
                "Verification unavailable for this provider/pattern."
            )

    result.summary["api_key_confirmed_count"] = sum(1 for k in result.api_keys if k.verified)
    result.summary["api_key_warning_count"] = sum(1 for k in result.api_keys if not k.verified)


def scan_apk(apk_path: str) -> ScanResult:
    """Scan one APK and return a ScanResult.

    Pipeline order:

    1. Load APK metadata and AndroidManifest.xml
    2. Extract components from Manifest
    3. Extract deep links from intent filters
    4. Static API key / token scan (+ online verification when supported)
    5. Apply risk tags and rough priority labels
    6. Attach adb PoC commands for actionable findings
    7. Detect vulnerability patterns and attack chains
    8. Apply severity_score / confidence_score
    """

    apk_path = os.path.abspath(apk_path)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    meta, root, custom_permissions = load_apk(apk_path)

    components = extract_components(
        root=root,
        package_name=meta.package_name,
        custom_permissions=custom_permissions,
        target_sdk=meta.target_sdk,
    )

    deep_links = extract_deep_links(components)

    result = ScanResult(
        meta=meta,
        components=components,
        deep_links=deep_links,
        custom_permissions=custom_permissions,
    )

    _scan_api_keys(apk_path, result)
    apply_risk_analysis(result)
    attach_poc_commands(result)
    detect_vulnerabilities(result)
    scan_network_code_patterns(apk_path, result)
    apply_scoring(result)
    
    return result


def scan_apk_to_dir(apk_path: str, output_dir: str) -> ScanResult:
    """Scan one APK and write JSON / Markdown / PoC reports."""

    result = scan_apk(apk_path)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pkg = result.meta.package_name or "unknown"
    base = out / pkg

    write_json(result, base.with_suffix(".json"))
    write_markdown(result, base.with_suffix(".md"))
    write_test_plan_markdown(result, base.with_name(f"{pkg}_test_plan.md"))
    write_poc_shell(result, base.with_name(base.name + "_poc.sh"))

    return result
