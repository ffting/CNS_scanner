"""Core scan pipeline."""

from __future__ import annotations

import os
from pathlib import Path

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
from risk_rules import apply_risk_analysis
from vulnerability_patterns import detect_vulnerabilities


def scan_apk(
    apk_path: str,
    verify_api_keys: bool = False,
    verify_allow_providers: set[str] | None = None,
    i_own_these_keys: bool = False,
) -> ScanResult:
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

    # Static secret scan: detect likely hardcoded API keys/tokens (redacted).
    result.api_keys = scan_apk_for_api_keys(apk_path)
    if not result.summary:
        result.summary = {}
    result.summary["api_key_candidate_count"] = len(result.api_keys)
    result.summary["api_key_confirmed_count"] = sum(1 for k in result.api_keys if k.verified)
    result.summary["api_key_warning_count"] = sum(1 for k in result.api_keys if not k.verified)

    # Optional verification: only runs when explicitly enabled and acknowledged.
    if verify_api_keys and i_own_these_keys:
        allow = verify_allow_providers or set()
        if allow:
            full_tokens = extract_full_tokens_for_verification(apk_path, allow_providers=allow)
            verified = verify_full_tokens(full_tokens, allow_providers=allow)
            for f in result.api_keys:
                if f.fingerprint in verified:
                    ok, detail = verified[f.fingerprint]
                    f.verified = ok
                    f.verification_detail = detail
            result.summary["api_key_confirmed_count"] = sum(1 for k in result.api_keys if k.verified)
            result.summary["api_key_warning_count"] = sum(1 for k in result.api_keys if not k.verified)

    apply_risk_analysis(result)
    attach_poc_commands(result)
    detect_vulnerabilities(result)
    return result


def scan_apk_to_dir(
    apk_path: str,
    output_dir: str,
    verify_api_keys: bool = False,
    verify_allow_providers: set[str] | None = None,
    i_own_these_keys: bool = False,
) -> ScanResult:
    result = scan_apk(
        apk_path,
        verify_api_keys=verify_api_keys,
        verify_allow_providers=verify_allow_providers,
        i_own_these_keys=i_own_these_keys,
    )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    pkg = result.meta.package_name or "unknown"
    base = out / pkg

    write_json(result, base.with_suffix(".json"))
    write_markdown(result, base.with_suffix(".md"))
    write_poc_shell(result, base.with_name(base.name + "_poc.sh"))
    return result
