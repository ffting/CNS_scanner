"""Generate adb command drafts for manual verification."""

from __future__ import annotations

from models import ComponentSurface, DeepLink, ScanResult


def _shell_quote(value: str) -> str:
    return value.replace('"', '\\"')


def _component_short_name(full_name: str, package_name: str) -> str:
    if full_name.startswith(package_name):
        rel = full_name[len(package_name) :]
        return rel if rel.startswith(".") else "." + rel
    if full_name.startswith("."):
        return full_name
    return "." + full_name.split(".")[-1]


def _build_deep_link_uri(link: DeepLink) -> str:
    scheme = link.schemes[0] if link.schemes else "https"
    host = link.hosts[0] if link.hosts else "example.com"
    path = link.path_prefixes[0] if link.path_prefixes else "/"
    if not path.startswith("/"):
        path = "/" + path
    query = "test=1"
    if "OAUTH_LIKE_PATH" in link.risk_tags:
        query = "code=TEST_CODE&state=TEST_STATE"
    return f"{scheme}://{host}{path}?{query}"


def poc_for_deep_link(link: DeepLink, package_name: str) -> str:
    uri = _build_deep_link_uri(link)
    short_name = _component_short_name(link.component_name, package_name)
    return (
        f'adb shell am start -a android.intent.action.VIEW -d "{_shell_quote(uri)}" '
        f"-n {package_name}/{short_name}"
    )


def poc_for_component(comp: ComponentSurface, package_name: str) -> str | None:
    short_name = _component_short_name(comp.name, package_name)

    if comp.kind in ("activity", "activity-alias"):
        action = "android.intent.action.VIEW"
        if comp.intent_filters and comp.intent_filters[0].actions:
            action = comp.intent_filters[0].actions[0]
        return f"adb shell am start -a {action} -n {package_name}/{short_name}"

    if comp.kind == "service":
        action_part = ""
        if comp.intent_filters and comp.intent_filters[0].actions:
            action_part = f'-a "{comp.intent_filters[0].actions[0]}" '
        return f"adb shell am startservice {action_part}-n {package_name}/{short_name}"

    if comp.kind == "receiver":
        action = "android.intent.action.VIEW"
        if comp.intent_filters and comp.intent_filters[0].actions:
            action = comp.intent_filters[0].actions[0]
        return f"adb shell am broadcast -a {action} -n {package_name}/{short_name}"

    if comp.kind == "provider":
        return f"adb shell content query --uri content://{package_name}/"
    return None


def attach_poc_commands(result: ScanResult) -> None:
    pkg = result.meta.package_name

    for link in result.deep_links:
        if link.schemes or link.hosts:
            link.adb_command = poc_for_deep_link(link, pkg)

    for comp in result.components:
        if comp.priority in ("P0", "P1") and comp.exported in ("true", "implicit"):
            cmd = poc_for_component(comp, pkg)
            if cmd:
                comp.notes.append(f"Suggested test: {cmd}")
