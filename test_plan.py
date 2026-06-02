"""Attack-surface navigation ranking and prioritized manual test plans.

Unified navigation score (used for Top-10 in CLI, reports, and evaluation):

    nav_score = priority_weight(P0..P3) + severity_score * confidence_score

where priority_weight is P0=4, P1=3, P2=2, P3=1.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from models import (
    ApiKeyFinding,
    AttackChainFinding,
    ComponentSurface,
    DeepLink,
    ScanResult,
    VulnerabilityFinding,
)

PRIORITY_WEIGHT: dict[str, int] = {
    "P0": 4,
    "P1": 3,
    "P2": 2,
    "P3": 1,
}

PRIORITY_ORDER: tuple[str, ...] = ("P0", "P1", "P2", "P3")

NAVIGATION_TOP_N = 10
URGENT_TOP_N = 3


@dataclass
class NavigationItem:
    """One row in the prioritized navigation / test plan."""

    kind: str  # vulnerability | attack_chain | component | deep_link | api_key
    title: str
    priority: str
    severity_score: int
    confidence_score: int
    nav_score: int
    rationale: str
    poc_commands: list[str]
    ref_id: str = ""
    severity_label: str = ""


def priority_weight(priority: str) -> int:
    return PRIORITY_WEIGHT.get(priority, 1)


def navigation_score(priority: str, severity_score: int, confidence_score: int) -> int:
    sev = max(1, min(10, int(severity_score)))
    conf = max(1, min(10, int(confidence_score)))
    return priority_weight(priority) + sev * conf


def _best_priority(priorities: list[str], default: str = "P3") -> str:
    if not priorities:
        return default
    return min(priorities, key=lambda p: PRIORITY_ORDER.index(p) if p in PRIORITY_ORDER else 9)


def infer_vulnerability_priority(vuln: VulnerabilityFinding, result: ScanResult) -> str:
    comp_by_name = {c.name: c for c in result.components}
    priorities: list[str] = []

    for name in vuln.related_components:
        comp = comp_by_name.get(name)
        if comp:
            priorities.append(comp.priority)

    link_names = set(vuln.related_deep_links) | set(vuln.related_components)
    for link in result.deep_links:
        if link.component_name in link_names:
            priorities.append(link.priority)

    if vuln.pattern_id == "VULN_HARDCODED_API_KEY":
        return "P0"

    if vuln.pattern_id.startswith("VULN_APP_"):
        return _best_priority(priorities, default="P2")

    return _best_priority(priorities, default="P2")


def infer_chain_priority(chain: AttackChainFinding, result: ScanResult) -> str:
    comp_by_name = {c.name: c for c in result.components}
    priorities: list[str] = []

    for name in chain.related_components:
        comp = comp_by_name.get(name)
        if comp:
            priorities.append(comp.priority)

    for link in result.deep_links:
        if link.component_name in chain.related_deep_links:
            priorities.append(link.priority)

    return _best_priority(priorities, default="P1")


def _poc_from_component(comp: ComponentSurface) -> list[str]:
    cmds: list[str] = []
    for note in comp.notes:
        if note.startswith("Suggested test:"):
            cmds.append(note.replace("Suggested test: ", "", 1))
    return cmds


def collect_poc_commands(result: ScanResult, component_names: list[str]) -> list[str]:
    """Collect adb PoC commands for related components / deep links."""

    names = set(component_names)
    emitted: set[str] = set()
    cmds: list[str] = []

    for link in result.deep_links:
        if link.component_name in names and link.adb_command:
            if link.adb_command not in emitted:
                cmds.append(link.adb_command)
                emitted.add(link.adb_command)

    for comp in result.components:
        if comp.name in names:
            for cmd in _poc_from_component(comp):
                if cmd not in emitted:
                    cmds.append(cmd)
                    emitted.add(cmd)

    return cmds


def assign_test_priorities(result: ScanResult) -> None:
    """Set test_priority on vulnerabilities and attack chains for ranking."""

    for vuln in result.vulnerabilities:
        vuln.test_priority = infer_vulnerability_priority(vuln, result)

    for chain in result.attack_chains:
        chain.test_priority = infer_chain_priority(chain, result)


_SEVERITY_FALLBACK = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 3,
}


def dict_severity_score(finding: dict[str, Any]) -> int:
    raw = finding.get("severity_score")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    sev = str(finding.get("severity", "")).strip().lower()
    return _SEVERITY_FALLBACK.get(sev, 5)


def dict_confidence_score(finding: dict[str, Any]) -> int:
    for key in ("confidence_score", "confidence"):
        raw = finding.get(key)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    return 0


def navigation_score_for_finding(finding: dict[str, Any]) -> int:
    """Navigation score for evaluation normalized finding dicts."""

    priority = finding.get("test_priority") or finding.get("priority") or "P3"
    return navigation_score(
        str(priority),
        dict_severity_score(finding),
        dict_confidence_score(finding),
    )


def sort_findings_by_navigation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort normalized findings by navigation score (descending)."""

    return sorted(
        findings,
        key=lambda f: (
            -navigation_score_for_finding(f),
            -int(f.get("severity_score") or 0),
            -int(f.get("confidence_score") or 0),
            str(f.get("pattern_id") or f.get("id") or ""),
        ),
    )


def is_high_priority_navigation(finding: dict[str, Any], ranked_findings: list[dict[str, Any]]) -> bool:
    """True when finding is in the Top-N navigation list (same rule as test plan)."""

    top = ranked_findings[:NAVIGATION_TOP_N]
    fid = str(finding.get("pattern_id") or finding.get("id") or "")
    for item in top:
        if item is finding:
            return True
        if str(item.get("pattern_id") or item.get("id") or "") == fid and fid:
            if item.get("title") == finding.get("title"):
                return True
    return False


def _item_from_vuln(vuln: VulnerabilityFinding, result: ScanResult) -> NavigationItem:
    pri = vuln.test_priority or infer_vulnerability_priority(vuln, result)
    sev = vuln.severity_score or 5
    conf = vuln.confidence_score or 5
    return NavigationItem(
        kind="vulnerability",
        ref_id=vuln.pattern_id,
        title=vuln.title,
        priority=pri,
        severity_label=vuln.severity,
        severity_score=sev,
        confidence_score=conf,
        nav_score=navigation_score(pri, sev, conf),
        rationale=vuln.description[:240],
        poc_commands=collect_poc_commands(result, vuln.related_components),
    )


def _item_from_chain(chain: AttackChainFinding, result: ScanResult) -> NavigationItem:
    pri = chain.test_priority or infer_chain_priority(chain, result)
    sev = chain.severity_score or 5
    conf = chain.confidence_score or 5
    poc = list(chain.poc_commands) if chain.poc_commands else collect_poc_commands(
        result, chain.related_components
    )
    return NavigationItem(
        kind="attack_chain",
        ref_id=chain.chain_id,
        title=chain.title,
        priority=pri,
        severity_label=chain.severity,
        severity_score=sev,
        confidence_score=conf,
        nav_score=navigation_score(pri, sev, conf),
        rationale=chain.narrative[:240],
        poc_commands=poc,
    )


def _item_from_component(comp: ComponentSurface) -> NavigationItem | None:
    if comp.priority not in ("P0", "P1"):
        return None
    if comp.exported not in ("true", "implicit"):
        return None

    sev = 7 if comp.priority == "P0" else 6
    conf = 8 if comp.exported == "true" else 7
    tags = ", ".join(comp.risk_tags[:4]) if comp.risk_tags else "exported surface"
    return NavigationItem(
        kind="component",
        ref_id=comp.name,
        title=f"{comp.kind}: {comp.name}",
        priority=comp.priority,
        severity_label="High" if comp.priority == "P0" else "Medium",
        severity_score=sev,
        confidence_score=conf,
        nav_score=navigation_score(comp.priority, sev, conf),
        rationale=f"Exported {comp.kind} ({tags}).",
        poc_commands=_poc_from_component(comp),
    )


def _item_from_deep_link(link: DeepLink) -> NavigationItem | None:
    if link.priority not in ("P0", "P1"):
        return None
    if not (link.schemes or link.hosts):
        return None

    sev = 8 if link.priority == "P0" else 7
    conf = 8 if link.browsable else 7
    scheme = link.schemes[0] if link.schemes else "?"
    return NavigationItem(
        kind="deep_link",
        ref_id=link.component_name,
        title=f"Deep link @ {link.component_name}",
        priority=link.priority,
        severity_label="High",
        severity_score=sev,
        confidence_score=conf,
        nav_score=navigation_score(link.priority, sev, conf),
        rationale=f"Reachable URI surface ({scheme}); tags: {', '.join(link.risk_tags[:4]) or '-'}.",
        poc_commands=[link.adb_command] if link.adb_command else [],
    )


def _item_from_api_key(key: ApiKeyFinding) -> NavigationItem | None:
    if not key.verified:
        return None

    return NavigationItem(
        kind="api_key",
        ref_id=key.fingerprint,
        title=f"Verified {key.provider} {key.kind}",
        priority="P0",
        severity_label="Critical",
        severity_score=10,
        confidence_score=10,
        nav_score=navigation_score("P0", 10, 10),
        rationale=f"Provider accepted key at {key.source}.",
        poc_commands=[],
    )


def build_navigation_items(result: ScanResult) -> list[NavigationItem]:
    """Merge all navigable surfaces into one sortable list."""

    items: list[NavigationItem] = []

    for vuln in result.vulnerabilities:
        items.append(_item_from_vuln(vuln, result))

    for chain in result.attack_chains:
        items.append(_item_from_chain(chain, result))

    for comp in result.components:
        row = _item_from_component(comp)
        if row:
            items.append(row)

    for link in result.deep_links:
        row = _item_from_deep_link(link)
        if row:
            items.append(row)

    for key in getattr(result, "api_keys", []) or []:
        row = _item_from_api_key(key)
        if row:
            items.append(row)

    items.sort(
        key=lambda row: (
            -row.nav_score,
            PRIORITY_ORDER.index(row.priority) if row.priority in PRIORITY_ORDER else 9,
            row.ref_id,
        )
    )

    return items


def navigation_sort_result(result: ScanResult) -> None:
    """Re-sort vulnerabilities and chains using navigation score."""

    def vuln_key(v: VulnerabilityFinding) -> tuple:
        pri = v.test_priority or "P3"
        return (
            -navigation_score(pri, v.severity_score or 0, v.confidence_score or 0),
            v.pattern_id,
        )

    def chain_key(c: AttackChainFinding) -> tuple:
        pri = c.test_priority or "P3"
        return (
            -navigation_score(pri, c.severity_score or 0, c.confidence_score or 0),
            c.chain_id,
        )

    result.vulnerabilities.sort(key=vuln_key)
    result.attack_chains.sort(key=chain_key)


def write_test_plan_markdown(result: ScanResult, output_path: Path) -> None:
    """Write {package}_test_plan.md for manual pentest prioritization."""

    items = build_navigation_items(result)
    top = items[:NAVIGATION_TOP_N]
    urgent = items[:URGENT_TOP_N]
    meta = result.meta

    lines: list[str] = [
        "# Prioritized Test Plan (ASNav)",
        "",
        f"**Package:** `{meta.package_name}`  ",
        f"**APK:** `{meta.apk_path}`",
        "",
        "Navigation score: `priority_weight + severity_score × confidence_score` "
        f"(weights: P0={PRIORITY_WEIGHT['P0']}, P1={PRIORITY_WEIGHT['P1']}, "
        f"P2={PRIORITY_WEIGHT['P2']}, P3={PRIORITY_WEIGHT['P3']}).",
        "",
        "## If you only have limited time — test these first",
        "",
    ]

    if not urgent:
        lines.append("_No high-priority navigation targets identified._")
    else:
        for idx, row in enumerate(urgent, start=1):
            lines.append(
                f"{idx}. **[{row.priority}]** {row.title} "
                f"(nav={row.nav_score}, sev={row.severity_score}, conf={row.confidence_score})"
            )
            lines.append(f"   - {row.rationale}")
            if row.poc_commands:
                lines.append("   - PoC:")
                for cmd in row.poc_commands[:2]:
                    lines.append(f"     ```bash\n     {cmd}\n     ```")
        lines.append("")

    lines.extend(["", f"## Top {NAVIGATION_TOP_N} navigation targets", ""])

    if not top:
        lines.append("_No items ranked._")
    else:
        lines.append("| # | P | Nav | Sev×Conf | Kind | Target |")
        lines.append("|---:|---|---:|---|---|---|")
        for idx, row in enumerate(top, start=1):
            lines.append(
                f"| {idx} | {row.priority} | {row.nav_score} | "
                f"{row.severity_score}×{row.confidence_score} | {row.kind} | {row.title} |"
            )
        lines.append("")

        for idx, row in enumerate(top, start=1):
            lines.append(f"### {idx}. [{row.priority}] {row.title}")
            lines.append("")
            lines.append(f"- **Kind:** `{row.kind}` / `{row.ref_id}`")
            lines.append(
                f"- **Scores:** nav={row.nav_score}, severity={row.severity_score}, "
                f"confidence={row.confidence_score}"
            )
            lines.append(f"- **Why test:** {row.rationale}")
            lines.append("")

            if row.kind == "attack_chain":
                chain = next(
                    (c for c in result.attack_chains if c.chain_id == row.ref_id),
                    None,
                )
                if chain and chain.reasoning_steps:
                    lines.append("**3-step attack reasoning:**")
                    for step_i, step in enumerate(chain.reasoning_steps[:3], start=1):
                        lines.append(f"{step_i}. {step}")
                    lines.append("")

            if row.poc_commands:
                lines.append("**Suggested PoC (adb):**")
                lines.append("```bash")
                for cmd in row.poc_commands:
                    lines.append(cmd)
                lines.append("```")
                lines.append("")

    lines.extend(
        [
            "## Attack-chain driven tests",
            "",
        ]
    )

    if not result.attack_chains:
        lines.append("_No composed attack chains._")
    else:
        for chain in result.attack_chains[:5]:
            lines.append(f"### {chain.title} (`{chain.chain_id}`)")
            lines.append("")
            if chain.reasoning_steps:
                for step_i, step in enumerate(chain.reasoning_steps[:3], start=1):
                    lines.append(f"{step_i}. {step}")
                lines.append("")
            poc = chain.poc_commands or collect_poc_commands(result, chain.related_components)
            if poc:
                lines.append("```bash")
                lines.extend(poc)
                lines.append("```")
            lines.append("")

    lines.extend(
        [
            "## Warnings / out of scope",
            "",
            "- Regex-only API key matches are **not** in this plan unless verified.",
            "- adb PoCs require a test device, USB debugging, and installed APK.",
            "- Review commands before running on production builds.",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
