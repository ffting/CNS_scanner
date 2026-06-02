"""Severity / confidence scoring for vulnerability findings and attack chains.

This module does not detect vulnerabilities.
It only assigns numeric scores to findings that were already produced by
vulnerability_patterns.py.

Scores:
- severity_score: 1-10, potential impact if the finding is real
- confidence_score: 1-10, how reliable the static evidence is

The goal is to support the proposal's two-dimensional ranking:
high severity + high confidence should be reviewed first.
"""

from __future__ import annotations

from models import AttackChainFinding, ScanResult, VulnerabilityFinding
from test_plan import assign_test_priorities, navigation_sort_result


SEVERITY_BASE_SCORE: dict[str, int] = {
    "Critical": 9,
    "High": 7,
    "Medium": 5,
    "Low": 3,
}


PATTERN_SEVERITY_OVERRIDES: dict[str, int] = {
    "VULN_EXPORTED_PROVIDER_LEAK": 9,
    "VULN_PROVIDER_IMPLICIT_EXPORT": 8,
    "VULN_IMPLICIT_EXPORTED_SERVICE": 7,
    "VULN_EXPORTED_NO_PERMISSION": 5,
    "VULN_OAUTH_DEEP_LINK_OPEN": 9,
    "VULN_CUSTOM_SCHEME_CALLBACK": 8,
    "VULN_HTTP_DEEP_LINK": 8,
    "VULN_PAYMENT_CALLBACK_OPEN": 8,
    "VULN_INTENT_FILTER_NO_ACTION": 4,
    "VULN_APP_DEBUGGABLE": 5,
    "VULN_APP_ALLOW_BACKUP": 4,
    "VULN_DANGEROUS_CUSTOM_PERMISSION": 7,
}


PATTERN_CONFIDENCE_BASE: dict[str, int] = {
    # Manifest-only provider evidence is usually reliable.
    "VULN_EXPORTED_PROVIDER_LEAK": 8,
    "VULN_PROVIDER_IMPLICIT_EXPORT": 7,

    # Service / exported component findings are real surfaces,
    # but exploitability depends on runtime behavior.
    "VULN_IMPLICIT_EXPORTED_SERVICE": 7,
    "VULN_EXPORTED_NO_PERMISSION": 6,

    # Deep link findings depend on whether the path really processes sensitive data.
    "VULN_OAUTH_DEEP_LINK_OPEN": 7,
    "VULN_CUSTOM_SCHEME_CALLBACK": 7,
    "VULN_HTTP_DEEP_LINK": 7,
    "VULN_PAYMENT_CALLBACK_OPEN": 6,

    # Config signals are reliable, but may not always be exploitable.
    "VULN_INTENT_FILTER_NO_ACTION": 6,
    "VULN_APP_DEBUGGABLE": 9,
    "VULN_APP_ALLOW_BACKUP": 8,
    "VULN_DANGEROUS_CUSTOM_PERMISSION": 8,
}


CHAIN_SEVERITY_OVERRIDES: dict[str, int] = {
    "CHAIN_OAUTH_HIJACK": 9,
    "CHAIN_OAUTH_HTTP_MITM": 9,
    "CHAIN_PROVIDER_PLUS_EXPORTED_ACTIVITY": 9,
    "CHAIN_BACKUP_AND_SENSITIVE_EXPORT": 7,
    "CHAIN_DEBUG_AND_EXPORT": 7,
    "CHAIN_IMPLICIT_SERVICE_PLUS_OPEN_ACTIVITY": 7,
    "CHAIN_PAYMENT_FORGERY": 8,
    "CHAIN_OAUTH_CUSTOM_SCHEME_SAME_HANDLER": 9,
    "CHAIN_OAUTH_HTTP_SAME_HANDLER": 9,
}


CHAIN_CONFIDENCE_BASE: dict[str, int] = {
    "CHAIN_OAUTH_HIJACK": 7,
    "CHAIN_OAUTH_HTTP_MITM": 7,
    "CHAIN_PROVIDER_PLUS_EXPORTED_ACTIVITY": 6,
    "CHAIN_BACKUP_AND_SENSITIVE_EXPORT": 6,
    "CHAIN_DEBUG_AND_EXPORT": 7,
    "CHAIN_IMPLICIT_SERVICE_PLUS_OPEN_ACTIVITY": 6,
    "CHAIN_PAYMENT_FORGERY": 6,
    "CHAIN_OAUTH_CUSTOM_SCHEME_SAME_HANDLER": 8,
    "CHAIN_OAUTH_HTTP_SAME_HANDLER": 8,
}


def _clamp_score(value: int) -> int:
    return max(1, min(10, value))


def _evidence_text(items: list[str]) -> str:
    return "\n".join(items).lower()


def _component_by_name(result: ScanResult) -> dict[str, object]:
    return {component.name: component for component in result.components}


def _deep_links_by_component(result: ScanResult) -> dict[str, list[object]]:
    mapping: dict[str, list[object]] = {}

    for link in result.deep_links:
        mapping.setdefault(link.component_name, []).append(link)

    return mapping


def _has_related_code_signal(
    finding: VulnerabilityFinding,
    result: ScanResult,
    signals: set[str],
) -> bool:
    components = _component_by_name(result)

    for name in finding.related_components:
        comp = components.get(name)
        if not comp:
            continue

        comp_signals = set(getattr(comp, "code_signals", []))
        if comp_signals & signals:
            return True

    return False


def _score_vulnerability_severity(finding: VulnerabilityFinding) -> int:
    if finding.pattern_id in PATTERN_SEVERITY_OVERRIDES:
        return PATTERN_SEVERITY_OVERRIDES[finding.pattern_id]

    return SEVERITY_BASE_SCORE.get(finding.severity, 5)


def _score_vulnerability_confidence(
    finding: VulnerabilityFinding,
    result: ScanResult,
) -> int:
    score = PATTERN_CONFIDENCE_BASE.get(finding.pattern_id, 5)
    evidence = _evidence_text(finding.evidence)

    # ------------------------------------------------------------------
    # Manifest / provider evidence
    # ------------------------------------------------------------------
    if finding.pattern_id in {
        "VULN_EXPORTED_PROVIDER_LEAK",
        "VULN_PROVIDER_IMPLICIT_EXPORT",
    }:
        if "authorities=" in evidence:
            score += 1
        if "provider permissions=(none)" in evidence:
            score += 1
        if "exported=true" in evidence:
            score += 1
        if "exported=implicit" in evidence:
            score -= 1

    # ------------------------------------------------------------------
    # Exported components
    # ------------------------------------------------------------------
    if finding.pattern_id == "VULN_EXPORTED_NO_PERMISSION":
        if "permission=(none)" in evidence:
            score += 1

        if _has_related_code_signal(
            finding,
            result,
            {
                "USES_INTENT_INPUT",
                "USES_DEEP_LINK_DATA",
                "USES_CONTENT_RESOLVER",
                "USES_WEBVIEW_LOADURL",
                "USES_FILE_IO",
                "USES_RUNTIME_EXEC",
            },
        ):
            score += 2

    if finding.pattern_id == "VULN_IMPLICIT_EXPORTED_SERVICE":
        if "exported=implicit" in evidence:
            score += 1

        if _has_related_code_signal(
            finding,
            result,
            {
                "USES_INTENT_INPUT",
                "USES_FILE_IO",
                "USES_RUNTIME_EXEC",
                "USES_NETWORK",
            },
        ):
            score += 1

    # ------------------------------------------------------------------
    # Deep links
    # ------------------------------------------------------------------
    if finding.category and finding.category.startswith("deep_link"):
        if "browsable=true" in evidence:
            score += 1
        if "browsable=false" in evidence:
            score -= 2

        if "test: adb shell" in evidence:
            score += 1

        if "hosts=[]" in evidence:
            score -= 1

        if _has_related_code_signal(
            finding,
            result,
            {
                "USES_DEEP_LINK_DATA",
                "USES_INTENT_INPUT",
                "USES_WEBVIEW_LOADURL",
            },
        ):
            score += 2

    if finding.pattern_id == "VULN_OAUTH_DEEP_LINK_OPEN":
        if any(
            keyword in evidence
            for keyword in ("oauth", "callback", "redirect", "token", "authorize", "sso")
        ):
            score += 1

    if finding.pattern_id == "VULN_PAYMENT_CALLBACK_OPEN":
        if any(
            keyword in evidence
            for keyword in ("payment", "pay", "checkout", "order", "purchase", "wallet")
        ):
            score += 1

    if finding.pattern_id == "VULN_CUSTOM_SCHEME_CALLBACK":
        if "schemes=['http']" in evidence or "schemes=['https']" in evidence:
            score -= 2

    if finding.pattern_id == "VULN_HTTP_DEEP_LINK":
        if "http" in evidence:
            score += 1

    # ------------------------------------------------------------------
    # App-level configuration
    # ------------------------------------------------------------------
    if finding.pattern_id in {
        "VULN_APP_DEBUGGABLE",
        "VULN_APP_ALLOW_BACKUP",
        "VULN_DANGEROUS_CUSTOM_PERMISSION",
    }:
        if "app signal:" in evidence:
            score += 1

    return _clamp_score(score)


def _score_chain_severity(chain: AttackChainFinding) -> int:
    if chain.chain_id in CHAIN_SEVERITY_OVERRIDES:
        return CHAIN_SEVERITY_OVERRIDES[chain.chain_id]

    return SEVERITY_BASE_SCORE.get(chain.severity, 5)


def _score_chain_confidence(
    chain: AttackChainFinding,
    result: ScanResult,
) -> int:
    score = CHAIN_CONFIDENCE_BASE.get(chain.chain_id, 5)
    evidence = _evidence_text(chain.evidence)

    if chain.related_components:
        score += 1

    if chain.related_deep_links:
        score += 1

    if "global tags:" in evidence:
        score += 1

    if "app signals:" in evidence:
        score += 1

    if "browsable=false" in evidence:
        score -= 2

    if "browsable=true" in evidence:
        score += 1

    if chain.chain_id in {
        "CHAIN_OAUTH_CUSTOM_SCHEME_SAME_HANDLER",
        "CHAIN_OAUTH_HTTP_SAME_HANDLER",
    }:
        # Same-handler chains are stronger than cross-entity composition.
        score += 1

    return _clamp_score(score)


def _sort_results(result: ScanResult) -> None:
    """Sort findings by severity score, confidence score, then stable IDs."""

    result.vulnerabilities.sort(
        key=lambda finding: (
            -(finding.severity_score or 0),
            -(finding.confidence_score or 0),
            finding.pattern_id,
            ",".join(finding.related_components),
        )
    )

    result.attack_chains.sort(
        key=lambda chain: (
            -(chain.severity_score or 0),
            -(chain.confidence_score or 0),
            chain.chain_id,
        )
    )


def _update_summary(result: ScanResult) -> None:
    if not result.summary:
        result.summary = {}

    result.summary["high_confidence_vulns"] = sum(
        1
        for finding in result.vulnerabilities
        if (finding.confidence_score or 0) >= 8
    )

    result.summary["high_severity_vulns"] = sum(
        1
        for finding in result.vulnerabilities
        if (finding.severity_score or 0) >= 8
    )

    result.summary["high_severity_high_confidence_vulns"] = sum(
        1
        for finding in result.vulnerabilities
        if (finding.severity_score or 0) >= 8
        and (finding.confidence_score or 0) >= 8
    )

    result.summary["high_confidence_chains"] = sum(
        1
        for chain in result.attack_chains
        if (chain.confidence_score or 0) >= 8
    )


def apply_scoring(result: ScanResult) -> None:
    """Assign numeric severity/confidence scores to findings and chains."""

    for finding in result.vulnerabilities:
        finding.severity_score = _score_vulnerability_severity(finding)
        finding.confidence_score = _score_vulnerability_confidence(finding, result)

    for chain in result.attack_chains:
        chain.severity_score = _score_chain_severity(chain)
        chain.confidence_score = _score_chain_confidence(chain, result)

    assign_test_priorities(result)
    navigation_sort_result(result)
    _update_summary(result)