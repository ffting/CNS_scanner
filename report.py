"""JSON and Markdown report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from models import ScanResult


def _result_to_dict(result: ScanResult) -> dict:
    return asdict(result)


def write_json(result: ScanResult, output_path: Path) -> None:
    """Write machine-readable JSON report."""

    output_path.write_text(
        json.dumps(
            _result_to_dict(result),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _score_pair(severity_score: int | None, confidence_score: int | None) -> str:
    sev = "-" if severity_score is None else str(severity_score)
    conf = "-" if confidence_score is None else str(confidence_score)
    return f"{sev}/10 / {conf}/10"


def _safe_join(items: list[str]) -> str:
    return ", ".join(items) if items else "-"


def write_markdown(result: ScanResult, output_path: Path) -> None:
    """Write human-readable Markdown report."""

    meta = result.meta

    lines: list[str] = [
        "# Attack Surface Scan Report",
        "",
        "## App metadata",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Package | `{meta.package_name}` |",
        f"| APK | `{meta.apk_path}` |",
        f"| Version | {meta.version_name or '-'} ({meta.version_code or '-'}) |",
        f"| minSdk / targetSdk | {meta.min_sdk} / {meta.target_sdk} |",
        f"| debuggable | {meta.debuggable} |",
        f"| allowBackup | {meta.allow_backup} |",
        "",
        "## Summary",
        "",
    ]

    for key, val in result.summary.items():
        lines.append(f"- **{key}**: {val}")

    lines.extend(["", "## API keys / tokens", ""])
    if not getattr(result, "api_keys", None):
        lines.append("_No API keys/tokens matched by built-in patterns._")
    else:
        confirmed = [k for k in result.api_keys if k.verified]
        warnings = [k for k in result.api_keys if not k.verified]

        lines.append(
            "Only **verified** keys are treated as confirmed findings. "
            "Regex-only matches are warnings/candidates."
        )
        lines.append("")
        lines.append(f"- Confirmed: **{len(confirmed)}**")
        lines.append(f"- Warnings: **{len(warnings)}**")
        lines.append("")
        lines.append("| Provider | Kind | Redacted | Status | Source |")
        lines.append("|----------|------|----------|----------|--------|")
        for k in sorted(result.api_keys, key=lambda x: (x.provider, x.kind, x.source)):
            verified = "confirmed" if k.verified else "warning"
            lines.append(
                f"| {k.provider} | {k.kind} | `{k.redacted}` | {verified} | `{k.source}` |"
            )
        lines.append("")
        # Include details separately to keep table clean.
        for k in result.api_keys:
            if k.verification_detail:
                lines.append(f"- `{k.redacted}`: {k.verification_detail}")

    lines.extend(["", "## Detected vulnerabilities (patterns)", ""])
    if not result.vulnerabilities:
        lines.append("_No vulnerability patterns matched._")
    else:
        for vuln in result.vulnerabilities:
            lines.append(f"### [{vuln.severity}] {vuln.title}")
            lines.append("")
            lines.append(f"- **ID**: `{vuln.pattern_id}`")
            lines.append(
                "- **Severity / Confidence**: "
                f"{_score_pair(vuln.severity_score, vuln.confidence_score)}"
            )

            if vuln.category:
                lines.append(f"- **Category**: `{vuln.category}`")

            if vuln.location:
                lines.append(f"- **Location**: `{vuln.location}`")

            if vuln.cwe:
                lines.append(f"- **CWE**: {vuln.cwe}")

            if vuln.owasp_masvs:
                lines.append(f"- **OWASP MASVS**: {vuln.owasp_masvs}")

            if vuln.related_components:
                lines.append(
                    f"- **Related components**: `{_safe_join(vuln.related_components)}`"
                )

            if vuln.related_deep_links:
                lines.append(
                    f"- **Related deep links**: `{_safe_join(vuln.related_deep_links)}`"
                )

            lines.append("")
            lines.append(vuln.description)
            lines.append("")

            if vuln.evidence:
                lines.append("**Evidence:**")
                for ev in vuln.evidence:
                    lines.append(f"- {ev}")
                lines.append("")

    # ------------------------------------------------------------------
    # Attack chains
    # ------------------------------------------------------------------
    lines.extend(
        [
            "",
            "## Attack chains",
            "",
        ]
    )

    if not result.attack_chains:
        lines.append("_No attack chains composed._")
    else:
        for chain in result.attack_chains:
            lines.append(f"### [{chain.severity}] {chain.title}")
            lines.append("")
            lines.append(f"- **ID**: `{chain.chain_id}`")
            lines.append(
                "- **Severity / Confidence**: "
                f"{_score_pair(chain.severity_score, chain.confidence_score)}"
            )
            lines.append(
                f"- **Composed of**: {', '.join(f'`{x}`' for x in chain.composed_of)}"
            )

            if chain.related_components:
                lines.append(
                    f"- **Related components**: `{_safe_join(chain.related_components)}`"
                )

            if chain.related_deep_links:
                lines.append(
                    f"- **Related deep links**: `{_safe_join(chain.related_deep_links)}`"
                )

            lines.append("")
            lines.append(chain.narrative)
            lines.append("")

            if chain.evidence:
                lines.append("**Evidence:**")
                for ev in chain.evidence:
                    lines.append(f"- {ev}")
                lines.append("")

    # ------------------------------------------------------------------
    # High-priority components
    # ------------------------------------------------------------------
    lines.extend(
        [
            "",
            "## High-priority components (P0 / P1)",
            "",
        ]
    )

    high_components = [c for c in result.components if c.priority in ("P0", "P1")]

    if not high_components:
        lines.append("_No P0/P1 components._")
    else:
        for comp in sorted(high_components, key=lambda c: (c.priority, c.kind, c.name)):
            lines.append(f"### `{comp.name}` ({comp.kind}) — **{comp.priority}**")
            lines.append("")
            lines.append(f"- exported: `{comp.exported}`")
            lines.append(f"- permission: `{comp.permission or '(none)'}`")

            if comp.read_permission:
                lines.append(f"- readPermission: `{comp.read_permission}`")

            if comp.write_permission:
                lines.append(f"- writePermission: `{comp.write_permission}`")

            if comp.authorities:
                lines.append(f"- authorities: `{', '.join(comp.authorities)}`")

            if comp.risk_tags:
                lines.append(f"- tags: {', '.join(f'`{t}`' for t in comp.risk_tags)}")

            if comp.code_signals:
                lines.append(
                    f"- code signals: {', '.join(f'`{s}`' for s in comp.code_signals)}"
                )

            if comp.code_evidence:
                lines.append("- code evidence:")
                for ev in comp.code_evidence[:5]:
                    lines.append(f"  - {ev}")

            for note in comp.notes:
                lines.append(f"- {note}")

            lines.append("")

    # ------------------------------------------------------------------
    # Deep links
    # ------------------------------------------------------------------
    lines.extend(
        [
            "",
            "## Deep links",
            "",
        ]
    )

    if not result.deep_links:
        lines.append("_No deep links found in intent-filters._")
    else:
        for link in sorted(result.deep_links, key=lambda d: (d.priority, d.component_name)):
            lines.append(f"### `{link.component_name}` — **{link.priority}**")
            lines.append("")
            lines.append(f"- component kind: `{link.component_kind}`")
            lines.append(f"- browsable: `{link.browsable}`")
            lines.append(f"- autoVerify declared: `{link.auto_verify}`")

            if link.actions:
                lines.append(f"- actions: `{', '.join(link.actions)}`")

            if link.categories:
                lines.append(f"- categories: `{', '.join(link.categories)}`")

            if link.schemes:
                lines.append(f"- schemes: `{', '.join(link.schemes)}`")

            if link.hosts:
                lines.append(f"- hosts: `{', '.join(link.hosts)}`")

            if link.path_prefixes:
                lines.append(f"- paths / prefixes: `{', '.join(link.path_prefixes)}`")

            if link.path_patterns:
                lines.append(f"- path patterns: `{', '.join(link.path_patterns)}`")

            if link.mime_types:
                lines.append(f"- mime types: `{', '.join(link.mime_types)}`")

            if link.risk_tags:
                lines.append(f"- tags: {', '.join(f'`{t}`' for t in link.risk_tags)}")

            if link.adb_command:
                lines.append("")
                lines.append("```bash")
                lines.append(link.adb_command)
                lines.append("```")

            lines.append("")

    # ------------------------------------------------------------------
    # All exported components
    # ------------------------------------------------------------------
    lines.extend(
        [
            "",
            "## All exported / implicit components",
            "",
        ]
    )

    exported = [c for c in result.components if c.exported in ("true", "implicit")]

    if not exported:
        lines.append("_No exported or implicitly exported components._")
    else:
        lines.append("| Priority | Kind | Name | exported | permission | authorities | tags |")
        lines.append("|----------|------|------|----------|------------|-------------|------|")

        for comp in sorted(exported, key=lambda c: (c.priority, c.kind, c.name)):
            tags = ", ".join(comp.risk_tags) if comp.risk_tags else "-"
            authorities = ", ".join(comp.authorities) if comp.authorities else "-"
            lines.append(
                f"| {comp.priority} | {comp.kind} | `{comp.name}` | {comp.exported} | "
                f"{comp.permission or '-'} | {authorities} | {tags} |"
            )

    # ------------------------------------------------------------------
    # adb script block
    # ------------------------------------------------------------------
    lines.extend(
        [
            "",
            "## adb test script",
            "",
            "```bash",
            "# Install APK and enable USB debugging first",
        ]
    )

    emitted: set[str] = set()

    for link in result.deep_links:
        if link.adb_command and link.priority in ("P0", "P1"):
            if link.adb_command not in emitted:
                lines.append(link.adb_command)
                emitted.add(link.adb_command)

    for comp in result.components:
        if comp.priority in ("P0", "P1"):
            for note in comp.notes:
                if note.startswith("Suggested test:"):
                    cmd = note.replace("Suggested test: ", "")
                    if cmd not in emitted:
                        lines.append(cmd)
                        emitted.add(cmd)

    lines.append("```")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_poc_shell(result: ScanResult, output_path: Path) -> None:
    """Write shell script containing suggested adb manual tests."""

    lines = [
        "#!/usr/bin/env bash",
        "# Suggested manual tests — review before running",
        f"# Package: {result.meta.package_name}",
        "",
        "set -u",
        "",
    ]

    emitted: set[str] = set()

    for link in result.deep_links:
        if link.adb_command and link.priority in ("P0", "P1"):
            if link.adb_command not in emitted:
                lines.append(link.adb_command)
                emitted.add(link.adb_command)

    for comp in result.components:
        if comp.priority in ("P0", "P1"):
            for note in comp.notes:
                if note.startswith("Suggested test:"):
                    cmd = note.replace("Suggested test: ", "")
                    if cmd not in emitted:
                        lines.append(cmd)
                        emitted.add(cmd)

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")