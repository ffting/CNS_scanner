"""Generate adb command drafts for manual verification."""

from __future__ import annotations

from models import ComponentSurface, DeepLink, ScanResult


def _shell_quote(value: str) -> str:
    """Escape double quotes for simple adb shell command generation."""
    return value.replace('"', '\\"')


def _component_short_name(full_name: str, package_name: str) -> str:
    """Return Android component name usable in package/.Class format."""

    if not full_name:
        return full_name

    if full_name.startswith(package_name):
        rel = full_name[len(package_name) :]
        return rel if rel.startswith(".") else "." + rel

    if full_name.startswith("."):
        return full_name

    return "." + full_name.split(".")[-1]


def _build_deep_link_uri(link: DeepLink) -> str:
    scheme = link.schemes[0] if link.schemes else "https"
    host = link.hosts[0] if link.hosts else "example.com"

    path = "/"
    if link.path_prefixes:
        path = link.path_prefixes[0]
    elif link.path_patterns:
        path = link.path_patterns[0]

    if not path.startswith("/"):
        path = "/" + path

    query = "test=1"

    if "OAUTH_LIKE_PATH" in link.risk_tags:
        query = "code=TEST_CODE&state=TEST_STATE"
    elif "PAYMENT_LIKE_PATH" in link.risk_tags:
        query = "order_id=TEST_ORDER&status=success"

    return f"{scheme}://{host}{path}?{query}"


def poc_for_deep_link(link: DeepLink, package_name: str) -> str:
    """Generate adb command for manually invoking a deep link."""

    uri = _build_deep_link_uri(link)
    short_name = _component_short_name(link.component_name, package_name)

    return (
        f'adb shell am start '
        f'-a android.intent.action.VIEW '
        f'-d "{_shell_quote(uri)}" '
        f"-n {package_name}/{short_name}"
    )


def _first_action(comp: ComponentSurface, default: str) -> str:
    for filt in comp.intent_filters:
        if filt.actions:
            return filt.actions[0]
    return default


def poc_for_component(comp: ComponentSurface, package_name: str) -> str | None:
    """Generate adb command for manually invoking an exported component."""

    short_name = _component_short_name(comp.name, package_name)

    if comp.kind in ("activity", "activity-alias"):
        action = _first_action(comp, "android.intent.action.VIEW")
        return f'adb shell am start -a "{_shell_quote(action)}" -n {package_name}/{short_name}'

    if comp.kind == "service":
        action = _first_action(comp, "")
        action_part = f'-a "{_shell_quote(action)}" ' if action else ""

        # startservice is kept for compatibility with the current project.
        # On newer Android versions, background service restrictions may affect runtime behavior.
        return f"adb shell am startservice {action_part}-n {package_name}/{short_name}"

    if comp.kind == "receiver":
        action = _first_action(comp, "android.intent.action.VIEW")
        return f'adb shell am broadcast -a "{_shell_quote(action)}" -n {package_name}/{short_name}'

    if comp.kind == "provider":
        if comp.authorities:
            authority = comp.authorities[0]
            return f"adb shell content query --uri content://{authority}/"

        # Fallback only; provider authorities are normally required for accurate testing.
        return f"adb shell content query --uri content://{package_name}/"

    return None


def attach_poc_commands(result: ScanResult) -> None:
    """Attach adb command drafts to high-priority components and deep links."""

    pkg = result.meta.package_name

    for link in result.deep_links:
        if link.priority in ("P0", "P1") and (link.schemes or link.hosts):
            link.adb_command = poc_for_deep_link(link, pkg)

    for comp in result.components:
        if comp.priority in ("P0", "P1") and comp.exported in ("true", "implicit"):
            cmd = poc_for_component(comp, pkg)
            if cmd:
                comp.notes.append(f"Suggested test: {cmd}")