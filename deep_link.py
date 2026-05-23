"""Extract deep links and app links from intent filters."""

from __future__ import annotations

from models import ComponentSurface, DeepLink, IntentFilter


def _merge_data_entries(filters: list[IntentFilter]) -> list[dict]:
    entries: list[dict] = []
    for filt in filters:
        if filt.data_entries:
            entries.extend(filt.data_entries)
        elif filt.actions and any(a == "android.intent.action.VIEW" for a in filt.actions):
            entries.append({})
    return entries


def extract_deep_links(components: list[ComponentSurface]) -> list[DeepLink]:
    links: list[DeepLink] = []

    for comp in components:
        if comp.kind not in ("activity", "activity-alias"):
            continue

        for filt in comp.intent_filters:
            is_view = "android.intent.action.VIEW" in filt.actions
            is_browsable = "android.intent.category.BROWSABLE" in filt.categories
            if not is_view and not filt.data_entries:
                continue

            data_entries = filt.data_entries or ([{}] if is_view else [])
            for data in data_entries:
                schemes = [data["scheme"]] if data.get("scheme") else []
                hosts = [data["host"]] if data.get("host") else []
                path_prefixes = []
                path_patterns = []
                if data.get("pathPrefix"):
                    path_prefixes.append(data["pathPrefix"])
                if data.get("pathPattern"):
                    path_patterns.append(data["pathPattern"])
                if data.get("path"):
                    path_prefixes.append(data["path"])

                mime_types = [data["mimeType"]] if data.get("mimeType") else []

                if not schemes and not hosts and not path_prefixes and not is_browsable:
                    continue

                links.append(
                    DeepLink(
                        component_kind=comp.kind,
                        component_name=comp.name,
                        schemes=schemes,
                        hosts=hosts,
                        path_prefixes=path_prefixes,
                        path_patterns=path_patterns,
                        mime_types=mime_types,
                        actions=list(filt.actions),
                        auto_verify=filt.auto_verify,
                    )
                )

    return links
