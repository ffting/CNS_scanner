"""JSON and Markdown report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from models import ScanResult


def _result_to_dict(result: ScanResult) -> dict:
    return asdict(result)


def write_json(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(
        json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_markdown(result: ScanResult, output_path: Path) -> None:
    meta = result.meta
    lines: list[str] = [
        "# Attack Surface Scan Report",
        "",
        "## App metadata",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
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

    lines.extend(["", "## Detected vulnerabilities (patterns)", ""])
    if not result.vulnerabilities:
        lines.append("_No vulnerability patterns matched._")
    else:
        for vuln in result.vulnerabilities:
            lines.append(f"### [{vuln.severity}] {vuln.title}")
            lines.append("")
            lines.append(f"- **ID**: `{vuln.pattern_id}`")
            if vuln.cwe:
                lines.append(f"- **CWE**: {vuln.cwe}")
            if vuln.owasp_masvs:
                lines.append(f"- **OWASP MASVS**: {vuln.owasp_masvs}")
            lines.append("")
            lines.append(vuln.description)
            lines.append("")
            if vuln.evidence:
                lines.append("**Evidence:**")
                for ev in vuln.evidence:
                    lines.append(f"- {ev}")
            lines.append("")

    lines.extend(["", "## Attack chains (A + B => path)", ""])
    if not result.attack_chains:
        lines.append("_No attack chains composed._")
    else:
        for chain in result.attack_chains:
            lines.append(f"### [{chain.severity}] {chain.title}")
            lines.append("")
            lines.append(f"- **ID**: `{chain.chain_id}`")
            lines.append(f"- **Composed of**: {', '.join(f'`{x}`' for x in chain.composed_of)}")
            lines.append("")
            lines.append(chain.narrative)
            lines.append("")
            if chain.evidence:
                lines.append("**Evidence:**")
                for ev in chain.evidence:
                    lines.append(f"- {ev}")
            lines.append("")

    lines.extend(["", "## High-priority components (P0 / P1)", ""])
    high = [c for c in result.components if c.priority in ("P0", "P1")]
    if not high:
        lines.append("_No P0/P1 components._")
    else:
        for comp in sorted(high, key=lambda c: (c.priority, c.name)):
            lines.append(f"### `{comp.name}` ({comp.kind}) — **{comp.priority}**")
            lines.append("")
            lines.append(f"- exported: `{comp.exported}`")
            lines.append(f"- permission: `{comp.permission or '(none)'}`")
            if comp.risk_tags:
                lines.append(f"- tags: {', '.join(f'`{t}`' for t in comp.risk_tags)}")
            for note in comp.notes:
                lines.append(f"- {note}")
            lines.append("")

    lines.extend(["", "## Deep links", ""])
    if not result.deep_links:
        lines.append("_No deep links found in intent-filters._")
    else:
        for link in sorted(result.deep_links, key=lambda d: (d.priority, d.component_name)):
            lines.append(f"### `{link.component_name}` — **{link.priority}**")
            lines.append("")
            if link.schemes:
                lines.append(f"- schemes: `{', '.join(link.schemes)}`")
            if link.hosts:
                lines.append(f"- hosts: `{', '.join(link.hosts)}`")
            if link.path_prefixes:
                lines.append(f"- pathPrefix: `{', '.join(link.path_prefixes)}`")
            if link.risk_tags:
                lines.append(f"- tags: {', '.join(f'`{t}`' for t in link.risk_tags)}")
            if link.adb_command:
                lines.append("")
                lines.append("```bash")
                lines.append(link.adb_command)
                lines.append("```")
            lines.append("")

    lines.extend(["", "## All exported components", ""])
    exported = [c for c in result.components if c.exported in ("true", "implicit")]
    lines.append("| Priority | Kind | Name | exported | permission | tags |")
    lines.append("|----------|------|------|----------|------------|------|")
    for comp in sorted(exported, key=lambda c: (c.priority, c.kind, c.name)):
        tags = ", ".join(comp.risk_tags) if comp.risk_tags else "-"
        lines.append(
            f"| {comp.priority} | {comp.kind} | `{comp.name}` | {comp.exported} | "
            f"{comp.permission or '-'} | {tags} |"
        )

    lines.extend(["", "## adb test script", "", "```bash", "# Install APK and enable USB debugging first"])
    for link in result.deep_links:
        if link.adb_command and link.priority in ("P0", "P1"):
            lines.append(link.adb_command)
    for comp in result.components:
        if comp.priority in ("P0", "P1"):
            for note in comp.notes:
                if note.startswith("Suggested test:"):
                    lines.append(note.replace("Suggested test: ", ""))
    lines.append("```")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_poc_shell(result: ScanResult, output_path: Path) -> None:
    lines = [
        "#!/usr/bin/env bash",
        "# Suggested manual tests — review before running",
        f"# Package: {result.meta.package_name}",
        "",
    ]
    for link in result.deep_links:
        if link.adb_command and link.priority in ("P0", "P1"):
            lines.append(link.adb_command)
    for comp in result.components:
        for note in comp.notes:
            if note.startswith("Suggested test:"):
                lines.append(note.replace("Suggested test: ", ""))
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
