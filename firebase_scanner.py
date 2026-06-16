"""
Parse Firebase google-services.json embedded in APK.

Common paths:
  res/raw/google-services.json
  assets/google-services.json
  google-services.json
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from androguard.core.apk import APK

from models import ApiKeyFinding


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _redact(value: str, keep: int = 4) -> str:
    v = value.strip()
    if len(v) <= keep * 2:
        return v[:1] + "*" * max(0, len(v) - 2) + v[-1:]
    return f"{v[:keep]}…{v[-keep:]}"

_GOOGLE_SERVICES_NAMES = (
    "google-services.json",
    "google_services.json",
)
_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{30,60}\b")


def _is_firebase_config_path(path: str) -> bool:
    lower = path.replace("\\", "/").lower()
    return any(lower.endswith(name) for name in _GOOGLE_SERVICES_NAMES)


def _walk_api_keys(obj: Any, keys: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("current_key", "api_key", "key") and isinstance(v, str):
                if _AIZA_RE.fullmatch(v.strip()):
                    keys.append(v.strip())
            else:
                _walk_api_keys(v, keys)
    elif isinstance(obj, list):
        for item in obj:
            _walk_api_keys(item, keys)


def _collect_metadata(data: dict) -> list[str]:
    lines: list[str] = []
    pinfo = data.get("project_info") or {}
    if pinfo.get("project_id"):
        lines.append(f"project_id={pinfo['project_id']}")
    if pinfo.get("project_number"):
        lines.append(f"project_number={pinfo['project_number']}")
    for client in data.get("client") or []:
        cinfo = (client.get("client_info") or {})
        if cinfo.get("mobilesdk_app_id"):
            lines.append(f"mobilesdk_app_id={cinfo['mobilesdk_app_id']}")
        android = (cinfo.get("android_client_info") or {})
        if android.get("package_name"):
            lines.append(f"firebase_package={android['package_name']}")
        for oauth in client.get("oauth_client") or []:
            cid = oauth.get("client_id")
            if cid:
                lines.append(f"oauth_client_id={cid}")
    return lines


def parse_google_services_json(content: bytes, source: str) -> list[ApiKeyFinding]:
    findings: list[ApiKeyFinding] = []
    try:
        text = content.decode("utf-8", errors="replace")
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeError):
        return findings

    if not isinstance(data, dict):
        return findings

    api_keys: list[str] = []
    _walk_api_keys(data, api_keys)
    meta = _collect_metadata(data)
    meta_ev = "; ".join(meta[:6]) if meta else "no extra metadata"

    seen: set[str] = set()
    for key in api_keys:
        fp = _fingerprint(key)
        if fp in seen:
            continue
        seen.add(fp)
        findings.append(
            ApiKeyFinding(
                provider="firebase",
                kind="api_key",
                value=key,
                redacted=_redact(key),
                fingerprint=fp,
                source=source,
                evidence=f"Firebase google-services.json current_key ({meta_ev})",
                confidence="High",
            )
        )

    return findings


def scan_firebase_from_apk(apk_path: str) -> list[ApiKeyFinding]:
    apk = APK(apk_path)
    findings: dict[str, ApiKeyFinding] = {}

    for name in apk.get_files():
        if not _is_firebase_config_path(name):
            continue
        try:
            blob = apk.get_file(name)
        except Exception:
            continue
        if not blob:
            continue
        for item in parse_google_services_json(blob, source=name):
            findings[item.fingerprint] = item

    return list(findings.values())


def extract_firebase_tokens_for_verification(
    apk_path: str,
) -> list[tuple[str, str, str, str]]:
    """(fingerprint, provider, kind, full_value) for Firebase API keys."""
    out: dict[str, tuple[str, str, str, str]] = {}
    apk = APK(apk_path)

    for name in apk.get_files():
        if not _is_firebase_config_path(name):
            continue
        try:
            blob = apk.get_file(name) or b""
        except Exception:
            continue
        try:
            data = json.loads(blob.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        keys: list[str] = []
        _walk_api_keys(data, keys)
        for key in keys:
            fp = _fingerprint(key)
            if fp not in out:
                out[fp] = (fp, "firebase", "api_key", key)

    return list(out.values())
