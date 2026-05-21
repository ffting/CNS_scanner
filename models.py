"""Data models for attack-surface scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data_entries: list[dict[str, str]] = field(default_factory=list)
    auto_verify: bool = False


@dataclass
class ComponentSurface:
    kind: str  # activity | activity-alias | service | receiver | provider
    name: str
    exported: str  # true | false | implicit
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    intent_filters: list[IntentFilter] = field(default_factory=list)
    is_launcher: bool = False
    is_sync_adapter: bool = False
    risk_tags: list[str] = field(default_factory=list)
    priority: str = "P3"  # P0 | P1 | P2 | P3
    notes: list[str] = field(default_factory=list)


@dataclass
class DeepLink:
    component_kind: str
    component_name: str
    schemes: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)
    path_patterns: list[str] = field(default_factory=list)
    mime_types: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    auto_verify: bool = False
    risk_tags: list[str] = field(default_factory=list)
    priority: str = "P3"
    adb_command: str | None = None


@dataclass
class AppMeta:
    package_name: str
    apk_path: str
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool | None = None


@dataclass
class VulnerabilityFinding:
    """Single vulnerability pattern match."""

    pattern_id: str
    title: str
    severity: str  # Critical | High | Medium | Low
    description: str
    evidence: list[str] = field(default_factory=list)
    related_components: list[str] = field(default_factory=list)
    related_deep_links: list[str] = field(default_factory=list)
    cwe: str | None = None
    owasp_masvs: str | None = None


@dataclass
class AttackChainFinding:
    """Combined patterns / signals forming a plausible attack path."""

    chain_id: str
    title: str
    severity: str
    narrative: str
    composed_of: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    related_components: list[str] = field(default_factory=list)
    related_deep_links: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    meta: AppMeta
    components: list[ComponentSurface] = field(default_factory=list)
    deep_links: list[DeepLink] = field(default_factory=list)
    custom_permissions: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    attack_chains: list[AttackChainFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
