"""Parse AndroidManifest from APK via androguard."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

# Androguard logs heavily to stderr; suppress for cleaner CLI on Windows PowerShell.
logging.getLogger("androguard").setLevel(logging.ERROR)
try:
    from loguru import logger as loguru_logger

    loguru_logger.disable("androguard")
except ImportError:
    pass

from androguard.core.apk import APK

from models import AppMeta, ComponentSurface, IntentFilter

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_NS_URI = "{" + ANDROID_NS + "}"


def _tag_name(elem: ET.Element) -> str:
    """Return local tag name without XML namespace."""
    return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag


def _attr(elem: ET.Element, name: str, default: str = "") -> str:
    """Read android:<name> attribute."""
    return elem.get(ANDROID_NS_URI + name, default) or default


def _parse_protection_level(raw: str) -> str:
    """Normalize android:protectionLevel.

    Returns one of:
    - normal
    - dangerous
    - signature
    - internal

    Unknown / missing values are treated as normal.
    """

    if not raw:
        return "normal"

    raw = raw.strip().lower()

    if raw in ("normal", "dangerous", "signature", "signatureorsystem", "internal"):
        return "signature" if raw == "signatureorsystem" else raw

    # Android protectionLevel can be integer flags.
    # Base values:
    # 0 = normal
    # 1 = dangerous
    # 2 = signature
    # 3 = signatureOrSystem
    try:
        value = int(raw, 0)
        base = value & 0xF
        mapping = {
            0: "normal",
            1: "dangerous",
            2: "signature",
            3: "signature",
        }
        return mapping.get(base, "normal")
    except ValueError:
        return "normal"


def _parse_intent_filter(filter_elem: ET.Element) -> IntentFilter:
    actions: list[str] = []
    categories: list[str] = []
    data_entries: list[dict[str, str]] = []

    for child in filter_elem:
        tag = _tag_name(child)

        if tag == "action":
            name = _attr(child, "name")
            if name:
                actions.append(name)

        elif tag == "category":
            name = _attr(child, "name")
            if name:
                categories.append(name)

        elif tag == "data":
            entry: dict[str, str] = {}

            for key in (
                "scheme",
                "host",
                "port",
                "path",
                "pathPrefix",
                "pathPattern",
                "mimeType",
            ):
                val = _attr(child, key)
                if val:
                    entry[key] = val

            if entry:
                data_entries.append(entry)

    auto_verify = _attr(filter_elem, "autoVerify").lower() == "true"

    return IntentFilter(
        actions=actions,
        categories=categories,
        data_entries=data_entries,
        auto_verify=auto_verify,
    )


def _is_launcher(intent_filters: list[IntentFilter]) -> bool:
    for filt in intent_filters:
        if "android.intent.category.LAUNCHER" in filt.categories:
            return True
    return False


def _is_sync_adapter(intent_filters: list[IntentFilter]) -> bool:
    for filt in intent_filters:
        if "android.content.SyncAdapter" in filt.actions:
            return True
    return False


def _resolve_exported(
    kind: str,
    exported_raw: str,
    intent_filters: list[IntentFilter],
    target_sdk: int | None,
) -> str:
    """Return exported status: true | false | implicit.

    Android default behavior:
    - activity/service/receiver:
      no android:exported + has intent-filter => exported by implication
      no intent-filter => false
    - provider:
      targetSdk >= 17 => false by default
      targetSdk < 17 or unknown => risky implicit default
    """

    if exported_raw:
        raw = exported_raw.lower()
        if raw in ("true", "false"):
            return raw

    if kind == "provider":
        if target_sdk is not None and target_sdk >= 17:
            return "false"
        return "implicit"

    if intent_filters:
        return "implicit"

    return "false"


def _collect_permissions(root: ET.Element) -> dict[str, str]:
    """Collect custom permissions declared by this app.

    Returns:
        permission name -> normalized protection level
    """

    perms: dict[str, str] = {}

    for elem in root.iter():
        if _tag_name(elem) != "permission":
            continue

        name = _attr(elem, "name")
        if not name:
            continue

        perms[name] = _parse_protection_level(_attr(elem, "protectionLevel"))

    return perms


def _parse_application_flags(app_elem: ET.Element) -> tuple[bool, bool | None, bool | None]:
    debuggable = _attr(app_elem, "debuggable").lower() == "true"

    backup_raw = _attr(app_elem, "allowBackup")
    if backup_raw == "":
        # Android default is true for many apps if not explicitly disabled.
        allow_backup: bool | None = True
    else:
        allow_backup = backup_raw.lower() == "true"

    cleartext_raw = _attr(app_elem, "usesCleartextTraffic")
    if cleartext_raw == "":
        uses_cleartext_traffic: bool | None = None
    else:
        uses_cleartext_traffic = cleartext_raw.lower() == "true"

    return debuggable, allow_backup, uses_cleartext_traffic


def _format_component_name(package_name: str, name: str) -> str:
    """Normalize component class name."""

    if not name:
        return name

    if name.startswith("."):
        return package_name + name

    # Some manifests use class names without package prefix.
    # Example: MainActivity
    if "." not in name and package_name:
        return package_name + "." + name

    return name


def _parse_authorities(raw: str) -> list[str]:
    """Parse provider authorities.

    Android allows semicolon-separated authorities.
    """

    if not raw:
        return []

    return [part.strip() for part in raw.split(";") if part.strip()]


def load_apk(apk_path: str) -> tuple[AppMeta, ET.Element, dict[str, str]]:
    apk = APK(apk_path)

    package_name = apk.get_package() or ""
    version_name = apk.get_androidversion_name()
    version_code = apk.get_androidversion_code()

    min_sdk: int | None = None
    target_sdk: int | None = None

    try:
        min_sdk = int(apk.get_min_sdk_version())
    except (TypeError, ValueError):
        pass

    try:
        target_sdk = int(apk.get_target_sdk_version())
    except (TypeError, ValueError):
        pass

    raw_manifest = apk.get_android_manifest_xml()

    if isinstance(raw_manifest, bytes):
        manifest_xml = raw_manifest.decode("utf-8", errors="replace")
    elif isinstance(raw_manifest, str):
        manifest_xml = raw_manifest
    else:
        manifest_xml = ET.tostring(raw_manifest, encoding="unicode")

    root = ET.fromstring(manifest_xml)
    custom_permissions = _collect_permissions(root)

    debuggable = False
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None

    for elem in root.iter():
        if _tag_name(elem) == "application":
            debuggable, allow_backup, uses_cleartext_traffic = _parse_application_flags(elem)
            break

    meta = AppMeta(
        package_name=package_name,
        apk_path=apk_path,
        version_name=version_name,
        version_code=str(version_code) if version_code is not None else None,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        debuggable=debuggable,
        allow_backup=allow_backup,
        uses_cleartext_traffic=uses_cleartext_traffic,
    )

    return meta, root, custom_permissions


def extract_components(
    root: ET.Element,
    package_name: str,
    custom_permissions: dict[str, str],
    target_sdk: int | None,
) -> list[ComponentSurface]:
    components: list[ComponentSurface] = []
    component_tags = ("activity", "activity-alias", "service", "receiver", "provider")

    for app_elem in root.iter():
        if _tag_name(app_elem) != "application":
            continue

        for elem in app_elem:
            kind = _tag_name(elem)

            if kind not in component_tags:
                continue

            raw_name = _attr(elem, "name")
            if not raw_name:
                continue

            name = _format_component_name(package_name, raw_name)

            intent_filters: list[IntentFilter] = []
            for child in elem:
                if _tag_name(child) == "intent-filter":
                    intent_filters.append(_parse_intent_filter(child))

            exported_raw = _attr(elem, "exported")
            exported = _resolve_exported(
                kind=kind,
                exported_raw=exported_raw,
                intent_filters=intent_filters,
                target_sdk=target_sdk,
            )

            authorities: list[str] = []
            if kind == "provider":
                authorities = _parse_authorities(_attr(elem, "authorities"))

            surface = ComponentSurface(
                kind=kind,
                name=name,
                exported=exported,
                permission=_attr(elem, "permission") or None,
                read_permission=_attr(elem, "readPermission") or None,
                write_permission=_attr(elem, "writePermission") or None,
                authorities=authorities,
                intent_filters=intent_filters,
                is_launcher=_is_launcher(intent_filters),
                is_sync_adapter=_is_sync_adapter(intent_filters),
            )

            components.append(surface)

    return components


def format_component_name(package_name: str, name: str) -> str:
    return _format_component_name(package_name, name)