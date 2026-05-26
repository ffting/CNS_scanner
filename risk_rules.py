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


def _is_weakly_protected(
    perm_name: str | None,
    custom_permissions: dict[str, str],
) -> bool:
    """Return True if permission is missing or not signature-level.

    Conservative assumption:
    - No permission => weak
    - Unknown permission => weak
    - normal / dangerous custom permission => weak
    - signature / internal => strong
    """

    if not perm_name:
        return True

    level = custom_permissions.get(perm_name)

    if level is None:
        # Could be platform permission or external library permission.
        # Without resolving its protection level, treat as weak for manual review.
        return True

    return level in WEAK_PROTECTION


def _provider_permissions_weak(
    comp: ComponentSurface,
    custom_permissions: dict[str, str],
) -> bool:
    perms = [
        p
        for p in (
            comp.permission,
            comp.read_permission,
            comp.write_permission,
        )
        if p
    ]

    if not perms:
        return True

    return any(_is_weakly_protected(p, custom_permissions) for p in perms)


def analyze_component(
    comp: ComponentSurface,
    custom_permissions: dict[str, str],
    target_sdk: int | None,
) -> None:
    """Attach risk tags and rough priority to one Android component."""

    tags: list[str] = []
    notes: list[str] = []
    priority = "P3"

    is_exported = comp.exported in ("true", "implicit")

    if not is_exported:
        comp.risk_tags = tags
        comp.priority = priority
        comp.notes = notes
        return

    # ------------------------------------------------------------------
    # ContentProvider
    # ------------------------------------------------------------------
    if comp.kind == "provider":
        if comp.exported == "implicit" and (target_sdk is None or target_sdk < 17):
            tags.append("PROVIDER_IMPLICIT_EXPORTED")
            notes.append(
                "ContentProvider has no explicit android:exported; "
                "older targetSdk may make it accessible by default."
            )
            priority = "P0"

        elif comp.exported == "true":
            tags.append("PROVIDER_EXPLICIT_EXPORTED")
            notes.append("ContentProvider is explicitly exported.")
            priority = "P0"

        if _provider_permissions_weak(comp, custom_permissions):
            tags.append("WEAK_PROVIDER_PROTECTION")
            notes.append("Provider lacks signature-level read/write protection.")
            priority = "P0"

        if comp.authorities:
            notes.append(f"Provider authorities: {', '.join(comp.authorities)}")
        else:
            notes.append("Provider authority not found in manifest.")

        comp.risk_tags = list(dict.fromkeys(tags))
        comp.priority = priority
        comp.notes = notes
        return

    # ------------------------------------------------------------------
    # Launcher activity is normally expected to be exported.
    # ------------------------------------------------------------------
    if comp.is_launcher:
        tags.append("LAUNCHER_ENTRY")
        comp.risk_tags = tags
        comp.priority = "P3"
        comp.notes = notes
        return

    # ------------------------------------------------------------------
    # Activity / Service / Receiver
    # ------------------------------------------------------------------
    weak_perm = _is_weakly_protected(comp.permission, custom_permissions)

    if weak_perm:
        tags.append("EXPORTED_NO_STRONG_PERMISSION")

    if comp.exported == "implicit" and comp.intent_filters:
        tags.append("IMPLICIT_EXPORTED")

    if comp.kind == "service" and comp.intent_filters and not comp.is_sync_adapter:
        tags.append("IMPLICIT_EXPORTED_SERVICE")
        notes.append("Exported service has intent-filter; prefer explicit intents only.")
        priority = "P0"

    has_non_android_action = False

    for filt in comp.intent_filters:
        if not filt.actions:
            tags.append("INTENT_FILTER_NO_ACTION")
            notes.append("Intent filter has no action.")
            priority = "P0"

        for action in filt.actions:
            if not action.startswith("android.") and not action.startswith("com.android."):
                has_non_android_action = True

        for data in filt.data_entries:
            if data.get("scheme") or data.get("host"):
                tags.append("HAS_DEEP_LINK_FILTER")

    if has_non_android_action and weak_perm:
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
    """Attach risk tags and rough priority to one deep link."""

    tags: list[str] = []
    priority = "P3"

    schemes = [s.lower() for s in link.schemes]
    paths = " ".join(link.path_prefixes + link.path_patterns).lower()

    if link.browsable:
        tags.append("BROWSABLE")
    else:
        tags.append("NOT_BROWSABLE")

    if any(s == "http" for s in schemes):
        tags.append("HTTP_SCHEME")

    if any(s and s not in ("https", "http") for s in schemes):
        tags.append("CUSTOM_SCHEME")
        priority = "P1"

    if link.auto_verify:
        # Static manifest flag only. This does not prove assetlinks.json is valid.
        tags.append("APP_LINK_AUTO_VERIFY_DECLARED")

    if "https" in schemes:
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

    # VIEW + data but not BROWSABLE is less externally reachable from browser links.
    if "NOT_BROWSABLE" in tags and priority == "P0":
        priority = "P1"
    elif "NOT_BROWSABLE" in tags and priority == "P1":
        priority = "P2"

    link.risk_tags = list(dict.fromkeys(tags))
    link.priority = priority


def apply_risk_analysis(result: ScanResult) -> None:
    """Apply component and deep-link risk analysis."""

    custom = result.custom_permissions
    target_sdk = result.meta.target_sdk

    comp_by_name = {c.name: c for c in result.components}

    for comp in result.components:
        analyze_component(
            comp=comp,
            custom_permissions=custom,
            target_sdk=target_sdk,
        )

    for link in result.deep_links:
        comp = comp_by_name.get(link.component_name)
        analyze_deep_link(link, comp)

    if not result.summary:
        result.summary = {}

    result.summary.update(
        {
            "total_components": len(result.components),
            "exported_or_implicit": sum(
                1 for c in result.components if c.exported in ("true", "implicit")
            ),
            "deep_link_count": len(result.deep_links),
            "p0_components": sum(1 for c in result.components if c.priority == "P0"),
            "p0_deep_links": sum(1 for d in result.deep_links if d.priority == "P0"),
            "debuggable": result.meta.debuggable,
            "allow_backup": result.meta.allow_backup,
        }
    )