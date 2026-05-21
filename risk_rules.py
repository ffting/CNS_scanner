"""Heuristic risk tagging and bounty-oriented priority scoring."""

from __future__ import annotations

import re

from models import ComponentSurface, DeepLink, ScanResult

OAUTH_PATH_RE = re.compile(
    r"(oauth|callback|redirect|login|token|authorize|auth|sso|session)",
    re.I,
)
PAYMENT_PATH_RE = re.compile(
    r"(pay|payment|billing|checkout|order|purchase|wallet)",
    re.I,
)

WEAK_PROTECTION = frozenset({"normal", "dangerous"})


def _is_weakly_protected(perm_name: str | None, custom_permissions: dict[str, str]) -> bool:
    if not perm_name:
        return True
    level = custom_permissions.get(perm_name)
    if level is None:
        return True
    return level in WEAK_PROTECTION


def _provider_permissions_weak(comp: ComponentSurface, custom_permissions: dict[str, str]) -> bool:
    perms = [p for p in (comp.permission, comp.read_permission, comp.write_permission) if p]
    if not perms:
        return True
    return any(_is_weakly_protected(p, custom_permissions) for p in perms)


def analyze_component(
    comp: ComponentSurface,
    custom_permissions: dict[str, str],
    target_sdk: int | None,
) -> None:
    tags: list[str] = []
    notes: list[str] = []
    priority = "P3"

    is_exported = comp.exported in ("true", "implicit")
    if not is_exported:
        comp.risk_tags = tags
        comp.priority = priority
        comp.notes = notes
        return

    if comp.kind == "provider":
        if comp.exported == "implicit" and target_sdk is not None and target_sdk >= 17:
            tags.append("PROVIDER_IMPLICIT_EXPORTED")
            notes.append(
                "ContentProvider has no explicit exported attribute; default differs by API level."
            )
            priority = "P0"
        elif comp.exported == "true":
            tags.append("PROVIDER_EXPLICIT_EXPORTED")
            priority = "P0"

        if _provider_permissions_weak(comp, custom_permissions):
            tags.append("WEAK_PROVIDER_PROTECTION")
            priority = "P0"
        comp.risk_tags = tags
        comp.priority = priority
        comp.notes = notes
        return

    if comp.is_launcher:
        tags.append("LAUNCHER_ENTRY")
        comp.risk_tags = tags
        comp.priority = "P3"
        comp.notes = notes
        return

    weak_perm = _is_weakly_protected(comp.permission, custom_permissions)
    if weak_perm:
        tags.append("EXPORTED_NO_STRONG_PERMISSION")

    if comp.kind == "service" and comp.intent_filters and not comp.is_sync_adapter:
        tags.append("IMPLICIT_EXPORTED_SERVICE")
        priority = "P0"
        notes.append("Exported service with intent-filter; prefer explicit intents only.")

    has_non_google_action = False
    for filt in comp.intent_filters:
        for action in filt.actions:
            if not action.startswith("android.") and not action.startswith("com.android."):
                has_non_google_action = True
        for data in filt.data_entries:
            if data.get("scheme") or data.get("host"):
                tags.append("HAS_DEEP_LINK_FILTER")

    if comp.exported == "implicit" and comp.intent_filters:
        tags.append("IMPLICIT_EXPORTED")

    for filt in comp.intent_filters:
        if not filt.actions:
            tags.append("INTENT_FILTER_NO_ACTION")
            priority = "P0"

    if has_non_google_action and weak_perm:
        priority = "P1"
    elif "IMPLICIT_EXPORTED_SERVICE" in tags:
        priority = "P0"
    elif "EXPORTED_NO_STRONG_PERMISSION" in tags and comp.intent_filters:
        priority = "P1"
    elif is_exported and weak_perm:
        priority = "P2"

    comp.risk_tags = list(dict.fromkeys(tags))
    comp.priority = priority
    comp.notes = notes


def analyze_deep_link(link: DeepLink, comp: ComponentSurface | None) -> None:
    tags: list[str] = []
    priority = "P3"

    schemes = [s.lower() for s in link.schemes]
    paths = " ".join(link.path_prefixes + link.path_patterns).lower()

    if any(s == "http" for s in schemes):
        tags.append("HTTP_SCHEME")
    if any(s and s not in ("https", "http") for s in schemes):
        tags.append("CUSTOM_SCHEME")
        priority = "P1"

    if link.auto_verify:
        tags.append("APP_LINK_VERIFIED")
    elif "https" in schemes:
        tags.append("HTTPS_DEEP_LINK")

    if OAUTH_PATH_RE.search(paths):
        tags.append("OAUTH_LIKE_PATH")
        priority = "P0"
    if PAYMENT_PATH_RE.search(paths):
        tags.append("PAYMENT_LIKE_PATH")
        if priority != "P0":
            priority = "P1"

    if not link.hosts and link.schemes:
        tags.append("BROAD_HOST")

    if comp and comp.exported in ("true", "implicit"):
        if comp.permission is None or "EXPORTED_NO_STRONG_PERMISSION" in comp.risk_tags:
            tags.append("EXPORTED_HANDLER")
            if "OAUTH_LIKE_PATH" in tags:
                priority = "P0"
            elif priority == "P3":
                priority = "P1"

    link.risk_tags = list(dict.fromkeys(tags))
    link.priority = priority


def apply_risk_analysis(result: ScanResult) -> None:
    custom = result.custom_permissions
    target_sdk = result.meta.target_sdk

    comp_by_name = {c.name: c for c in result.components}

    for comp in result.components:
        analyze_component(comp, custom, target_sdk)

    for link in result.deep_links:
        comp = comp_by_name.get(link.component_name)
        analyze_deep_link(link, comp)

    if not result.summary:
        result.summary = {}
    result.summary.update({
        "total_components": len(result.components),
        "exported_or_implicit": sum(
            1 for c in result.components if c.exported in ("true", "implicit")
        ),
        "deep_link_count": len(result.deep_links),
        "p0_components": sum(1 for c in result.components if c.priority == "P0"),
        "p0_deep_links": sum(1 for d in result.deep_links if d.priority == "P0"),
        "debuggable": result.meta.debuggable,
        "allow_backup": result.meta.allow_backup,
    })
