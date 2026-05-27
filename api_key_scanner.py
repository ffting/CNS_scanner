"""
API key / token leak scanner for APK.

Goal: identify likely hardcoded keys (bug-bounty-relevant) and optionally verify
whether a key is accepted by a provider API (only when explicitly enabled).

Security / ethics:
- Verification sends minimal "whoami"-style requests for a small provider set.
- This feature is OFF by default and should only be used for keys you own or
  have explicit authorization to test.
"""

from __future__ import annotations

import hashlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from androguard.core.apk import APK

from models import ApiKeyFinding


@dataclass(frozen=True)
class _Pattern:
    provider: str
    kind: str
    regex: re.Pattern[str]
    confidence: str


def _fingerprint(value: str) -> str:
    # Short stable fingerprint to dedupe without storing full secret.
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _redact(value: str, keep: int = 4) -> str:
    v = value.strip()
    if len(v) <= keep * 2:
        return v[:1] + "*" * max(0, len(v) - 2) + v[-1:]
    return f"{v[:keep]}…{v[-keep:]}"


def _iter_ascii_strings(data: bytes, min_len: int = 12) -> Iterable[str]:
    # Extract ASCII-ish runs from binary content; keeps it fast and provider-agnostic.
    buf = []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                yield "".join(buf)
            buf = []
    if len(buf) >= min_len:
        yield "".join(buf)


PATTERNS: list[_Pattern] = [
    _Pattern(
        provider="google",
        kind="api_key",
        # Google API key (e.g., Maps, Firebase): AIza...
        regex=re.compile(r"\bAIza[0-9A-Za-z\-_]{30,60}\b"),
        confidence="High",
    ),
    _Pattern(
        provider="github",
        kind="token",
        # GitHub classic PAT
        regex=re.compile(r"\bghp_[0-9A-Za-z]{20,200}\b"),
        confidence="High",
    ),
    _Pattern(
        provider="github",
        kind="token",
        # GitHub fine-grained tokens (common prefix)
        regex=re.compile(r"\bgithub_pat_[0-9A-Za-z_]{20,300}\b"),
        confidence="High",
    ),
    _Pattern(
        provider="stripe",
        kind="api_key",
        regex=re.compile(r"\bsk_(live|test)_[0-9A-Za-z]{16,200}\b"),
        confidence="High",
    ),
    _Pattern(
        provider="slack",
        kind="token",
        regex=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"),
        confidence="High",
    ),
    _Pattern(
        provider="aws",
        kind="api_key",
        # Access key ID. Alone is not sufficient; still a strong signal.
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        confidence="Medium",
    ),
]

GENERIC_NAME_PATTERNS: list[re.Pattern[str]] = [
    # API_KEY = "....", apiKey: "...", "API_KEY":"..."
    re.compile(
        r"""(?ix)
        (?:
            ["']?
            (?:api[_-]?key|apikey|access[_-]?key|client[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)
            ["']?
        )
        \s*[:=]\s*
        ["']?
        ([A-Za-z0-9_\-]{16,200})
        ["']?
        """,
    ),
    # const API_KEY "...."  (smali / decompiled edge cases)
    re.compile(
        r"""(?ix)
        (?:api[_-]?key|apikey|access[_-]?key|client[_-]?secret|secret[_-]?key|auth[_-]?token|access[_-]?token)
        [^A-Za-z0-9]{1,20}
        ([A-Za-z0-9_\-]{16,200})
        """,
    ),
]


def _extract_named_secret_values(s: str) -> list[tuple[str, str]]:
    """
    Extract (value, evidence) from variable-name-style secret assignments.

    These rules are intentionally Medium confidence because variable names like
    API_KEY can point to non-sensitive values in some projects.
    """
    out: list[tuple[str, str]] = []
    for rx in GENERIC_NAME_PATTERNS:
        for m in rx.finditer(s):
            # First capture group is the candidate secret value.
            val = m.group(1).strip()
            if len(val) < 16:
                continue
            out.append((val, f"Named variable assignment matched: {rx.pattern}"))
    return out


def scan_apk_for_api_keys(apk_path: str, max_bytes_per_file: int = 5_000_000) -> list[ApiKeyFinding]:
    apk = APK(apk_path)
    findings: dict[str, ApiKeyFinding] = {}

    # Scan selected raw files inside APK. Binary-heavy files are limited.
    for name in apk.get_files():
        # Skip extremely large payloads by extension; we still catch most leaks via dex/arsc.
        if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mp3", ".ogg", ".wav")):
            continue

        try:
            blob = apk.get_file(name)
        except Exception:
            continue

        if not blob:
            continue

        data = blob[:max_bytes_per_file]
        for s in _iter_ascii_strings(data, min_len=12):
            for pat in PATTERNS:
                for m in pat.regex.finditer(s):
                    val = m.group(0)
                    fp = _fingerprint(val)
                    if fp in findings:
                        continue
                    findings[fp] = ApiKeyFinding(
                        provider=pat.provider,
                        kind=pat.kind,
                        redacted=_redact(val),
                        fingerprint=fp,
                        source=name,
                        evidence=f"Matched regex: {pat.regex.pattern}",
                        confidence=pat.confidence,
                    )
            # Generic variable-name patterns: API_KEY, SECRET_KEY, ACCESS_TOKEN...
            for val, ev in _extract_named_secret_values(s):
                fp = _fingerprint(val)
                if fp in findings:
                    continue
                findings[fp] = ApiKeyFinding(
                    provider="generic",
                    kind="secret",
                    redacted=_redact(val),
                    fingerprint=fp,
                    source=name,
                    evidence=ev,
                    confidence="Medium",
                )

    return list(findings.values())


def extract_full_tokens_for_verification(
    apk_path: str,
    allow_providers: set[str],
    max_bytes_per_file: int = 5_000_000,
) -> list[tuple[str, str, str, str]]:
    """
    Extract full token values for verification.

    Returns list of (fingerprint, provider, kind, full_value).
    Only returns tokens for providers included in allow_providers.
    """

    apk = APK(apk_path)
    out: dict[str, tuple[str, str, str, str]] = {}

    allowed_patterns = [p for p in PATTERNS if p.provider in allow_providers]
    if not allowed_patterns:
        return []

    for name in apk.get_files():
        if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mp3", ".ogg", ".wav")):
            continue
        try:
            blob = apk.get_file(name) or b""
        except Exception:
            continue

        data = blob[:max_bytes_per_file]
        for s in _iter_ascii_strings(data, min_len=12):
            for pat in allowed_patterns:
                for m in pat.regex.finditer(s):
                    val = m.group(0)
                    fp = _fingerprint(val)
                    if fp not in out:
                        out[fp] = (fp, pat.provider, pat.kind, val)

    return list(out.values())


def verify_api_keys(
    findings: list[ApiKeyFinding],
    allow_providers: set[str],
    timeout_s: float = 6.0,
) -> list[ApiKeyFinding]:
    """
    Best-effort verification for a limited set of providers.

    Important: this function expects the *real* key values to verify, but our
    findings store only redacted values by design. Therefore, verification is
    intentionally limited and should be implemented by re-scanning with capture
    of full tokens only when explicitly allowed.
    """

    # This is intentionally a no-op for safety: without the full key, we cannot verify.
    # The CLI uses a separate "unsafe" path that carries full values only when
    # --i-own-these-keys is set.
    _ = (timeout_s, allow_providers)
    return findings


def verify_full_tokens(
    tokens: list[tuple[str, str, str, str]],
    allow_providers: set[str],
    timeout_s: float = 6.0,
) -> dict[str, tuple[bool, str]]:
    """
    Verify tokens using minimal provider APIs.

    tokens: list of (fingerprint, provider, kind, full_value)
    returns: fingerprint -> (verified, detail)
    """

    results: dict[str, tuple[bool, str]] = {}

    def _http_json(url: str, headers: dict[str, str]) -> tuple[int, str]:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                code = getattr(resp, "status", 200)
                body = resp.read(5120).decode("utf-8", errors="replace")
                return code, body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
            return int(getattr(e, "code", 0) or 0), body
        except Exception as e:
            return 0, f"{type(e).__name__}: {e}"

    for fp, provider, kind, val in tokens:
        if provider not in allow_providers:
            continue

        # Basic rate limiting to be polite.
        time.sleep(0.15)

        if provider == "github" and kind == "token":
            code, body = _http_json(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {val}",
                    "User-Agent": "our_scanner",
                    "Accept": "application/vnd.github+json",
                },
            )
            if code == 200:
                results[fp] = (True, "GitHub API accepted token (GET /user => 200).")
            elif code in (401, 403):
                results[fp] = (False, f"GitHub rejected token (HTTP {code}).")
            else:
                results[fp] = (False, f"GitHub verify error (HTTP {code}).")
            continue

        if provider == "stripe" and kind == "api_key":
            code, body = _http_json(
                "https://api.stripe.com/v1/account",
                headers={"Authorization": f"Bearer {val}"},
            )
            if code == 200:
                results[fp] = (True, "Stripe API accepted key (GET /v1/account => 200).")
            elif code in (401, 403):
                results[fp] = (False, f"Stripe rejected key (HTTP {code}).")
            else:
                results[fp] = (False, f"Stripe verify error (HTTP {code}).")
            continue

        if provider == "slack" and kind == "token":
            # Slack "auth.test" uses form-encoded POST normally; keep to GET for minimal support.
            url = f"https://slack.com/api/auth.test?token={urllib.parse.quote(val)}"
            code, body = _http_json(url, headers={"User-Agent": "our_scanner"})
            if code == 200 and '"ok":true' in body.replace(" ", ""):
                results[fp] = (True, "Slack API accepted token (auth.test ok=true).")
            elif code == 200:
                results[fp] = (False, "Slack auth.test returned ok=false.")
            else:
                results[fp] = (False, f"Slack verify error (HTTP {code}).")
            continue

        results[fp] = (False, "Verification not implemented for this provider.")

    return results

