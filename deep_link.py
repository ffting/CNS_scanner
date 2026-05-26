"""Extract deep links and app links from intent filters."""

from __future__ import annotations

from models import ComponentSurface, DeepLink


def extract_deep_links(components: list[ComponentSurface]) -> list[DeepLink]:
    """Extract deep-link-like surfaces from Activity intent filters.

    A deep link is considered externally relevant when:
    - It is on an activity / activity-alias
    - It has ACTION_VIEW or <data> entries
    - It has BROWSABLE, scheme, host, path, or mimeType evidence

    This function is intentionally conservative:
    - VIEW + BROWSABLE + data is high-confidence deep link evidence
    - VIEW without BROWSABLE is still recorded but later risk rules can reduce confidence
    """

    links: list[DeepLink] = []

    for comp in components:
        if comp.kind not in ("activity", "activity-alias"):
            continue

        for filt in comp.intent_filters:
            is_view = "android.intent.action.VIEW" in filt.actions
            is_browsable = "android.intent.category.BROWSABLE" in filt.categories

            # Not a URL/deep-link-like filter.
            if not is_view and not filt.data_entries:
                continue

            # If VIEW exists but no <data>, keep a weak placeholder only when BROWSABLE exists.
            data_entries = filt.data_entries
            if not data_entries and is_view and is_browsable:
                data_entries = [{}]

            for data in data_entries:
                schemes = [data["scheme"]] if data.get("scheme") else []
                hosts = [data["host"]] if data.get("host") else []

                path_prefixes: list[str] = []
                path_patterns: list[str] = []

                if data.get("path"):
                    path_prefixes.append(data["path"])
                if data.get("pathPrefix"):
                    path_prefixes.append(data["pathPrefix"])
                if data.get("pathPattern"):
                    path_patterns.append(data["pathPattern"])

                mime_types = [data["mimeType"]] if data.get("mimeType") else []

                has_url_or_data_evidence = any(
                    [
                        schemes,
                        hosts,
                        path_prefixes,
                        path_patterns,
                        mime_types,
                    ]
                )

                # Avoid recording extremely weak entries such as VIEW without data and without BROWSABLE.
                if not has_url_or_data_evidence and not is_browsable:
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
                        categories=list(filt.categories),
                        browsable=is_browsable,
                        auto_verify=filt.auto_verify,
                    )
                )

    return links