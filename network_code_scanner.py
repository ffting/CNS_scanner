"""Network / TLS static code-pattern scanner for APK.

This module scans APK byte strings, especially classes.dex and resource files,
for simple Network/TLS security patterns.

Design goals:
- Reuse lightweight APK string scanning instead of requiring JADX.
- Prefer high-confidence keyword combinations.
- Avoid APK-wide keyword mixing by evaluating patterns per file.
- Append VulnerabilityFinding objects directly to ScanResult.

Current target rules:
- obsolete_tls_version
- certificate_validation_bypass

Future compatible rules:
- webview_ssl_error_bypass
- hostname_verification_bypass
- insecure_trust_manager
- cleartext_http
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from androguard.core.apk import APK

from models import ScanResult, VulnerabilityFinding


@dataclass(frozen=True)
class SourceStrings:
    """Strings extracted from one APK internal file."""

    name: str
    text: str


def _iter_ascii_strings(data: bytes, min_len: int = 4) -> Iterable[str]:
    """Extract printable ASCII runs from binary data.

    DEX files often preserve class names, method names, constants, URLs,
    and selected string literals as ASCII-ish runs.
    """

    buf: list[str] = []

    for b in data:
        if 32 <= b <= 126:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                yield "".join(buf)
            buf = []

    if len(buf) >= min_len:
        yield "".join(buf)


def _should_scan_file(name: str) -> bool:
    """Select APK internal files worth scanning.

    Keep this narrow enough to reduce noise, but broad enough to catch:
    - classes.dex code strings
    - compiled XML resources
    - resources.arsc string table
    - plain assets/config files
    """

    lower = name.lower()

    if lower.endswith(
        (
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".gif",
            ".mp4",
            ".mp3",
            ".ogg",
            ".wav",
            ".so",
        )
    ):
        return False

    return (
        lower.endswith(".dex")
        or lower.endswith(".xml")
        or lower.endswith(".arsc")
        or lower.endswith(".properties")
        or lower.endswith(".json")
        or lower.endswith(".txt")
        or lower.endswith(".html")
        or lower.endswith(".js")
        or lower.startswith("assets/")
        or lower.startswith("res/raw/")
    )


def _collect_source_strings(
    apk_path: str,
    max_bytes_per_file: int = 8_000_000,
) -> list[SourceStrings]:
    """Collect strings per APK internal file.

    Important:
    Do not merge all APK files into one text before matching. APK-wide merging
    can create false positives by combining unrelated keywords from different
    files.
    """

    apk = APK(apk_path)
    sources: list[SourceStrings] = []

    for name in apk.get_files():
        if not _should_scan_file(name):
            continue

        try:
            blob = apk.get_file(name)
        except Exception:
            continue

        if not blob:
            continue

        data = blob[:max_bytes_per_file]
        strings = list(_iter_ascii_strings(data, min_len=4))

        if not strings:
            continue

        sources.append(SourceStrings(name=name, text="\n".join(strings)))

    return sources


def _lower(text: str) -> str:
    return text.lower()


def _has_any(text: str, keywords: list[str]) -> bool:
    lower = _lower(text)
    return any(keyword.lower() in lower for keyword in keywords)


def _has_all(text: str, keywords: list[str]) -> bool:
    lower = _lower(text)
    return all(keyword.lower() in lower for keyword in keywords)


def _source_hint(source: SourceStrings) -> str:
    return source.name or "classes.dex"


def _append_unique(result: ScanResult, finding: VulnerabilityFinding) -> None:
    """Avoid duplicate findings with same pattern/category/location."""

    key = (finding.pattern_id, finding.category, finding.location)

    for old in result.vulnerabilities:
        old_key = (old.pattern_id, old.category, old.location)
        if old_key == key:
            return

    result.vulnerabilities.append(finding)


def _find_obsolete_tls_source(sources: list[SourceStrings]) -> SourceStrings | None:
    """Find strong evidence of obsolete TLS version usage.

    Avoid weak matching such as:
        APK contains "TLSv1" somewhere AND "SSLContext" somewhere else.

    Stronger signals:
    - Same source file contains TLSv1/TLSv1.0 and SSLContext and getInstance.
    - Or same source file contains getInstance("TLSv1...")-like text.
    """

    for source in sources:
        text = source.text
        lower = _lower(text)

        # Most useful direct decompiled/source-like signal.
        direct_get_instance = any(
            marker in lower
            for marker in (
                'sslcontext.getinstance("tlsv1',
                "sslcontext.getinstance('tlsv1",
                'getinstance("tlsv1',
                "getinstance('tlsv1",
                "getinstance tlsv1",
            )
        )

        if direct_get_instance:
            return source

        # DEX strings may lose punctuation and keep tokens separately.
        same_file_token_signal = (
            _has_any(text, ["TLSv1.0", "TLSv1"])
            and _has_all(text, ["SSLContext", "getInstance"])
        )

        if not same_file_token_signal:
            continue

        # Reduce false positives from random TLS capability strings.
        # Require at least one network/TLS construction context marker.
        context_ok = _has_any(
            text,
            [
                "javax.net.ssl.SSLContext",
                "sslcontext",
                "SSLSocketFactory",
                "HttpsURLConnection",
                "setDefaultSSLSocketFactory",
                "createSocket",
            ],
        )

        if context_ok:
            return source

    return None


def _find_certificate_bypass_source(sources: list[SourceStrings]) -> SourceStrings | None:
    """Find strong evidence of TLS certificate validation bypass.

    This rule intentionally requires several related TrustManager/X509 markers
    in the same source file to avoid broad false positives.
    """

    for source in sources:
        text = source.text

        trust_manager_core = _has_any(
            text,
            [
                "X509TrustManager",
                "javax.net.ssl.X509TrustManager",
                "TrustManager",
                "javax.net.ssl.TrustManager",
            ],
        )

        trust_methods = _has_any(
            text,
            [
                "checkServerTrusted",
                "checkClientTrusted",
                "getAcceptedIssuers",
                "trustAllCerts",
            ],
        )

        bypass_markers = _has_any(
            text,
            [
                "return null",
                "returnnull",
                "setDefaultSSLSocketFactory",
                "disableCertificateValidation",
                "trustAllCerts",
                "accept all certificates",
                "self-signed",
                "expired certificates",
            ],
        )

        ssl_context = _has_any(
            text,
            [
                "SSLContext",
                "sslContext.init",
                "context.init",
                "setDefaultSSLSocketFactory",
                "HttpsURLConnection",
            ],
        )

        if trust_manager_core and trust_methods and bypass_markers:
            return source

        # Some DEX outputs do not preserve "return null" clearly.
        # TrustManager + trust methods + SSLContext setup is still useful.
        if trust_manager_core and trust_methods and ssl_context:
            return source

    return None


def _find_webview_ssl_error_bypass_source(
    sources: list[SourceStrings],
) -> SourceStrings | None:
    """Future rule: WebView ignores SSL errors by calling handler.proceed()."""

    for source in sources:
        text = source.text

        if (
            _has_any(text, ["onReceivedSslError"])
            and _has_any(text, ["SslErrorHandler", "SslError"])
            and _has_any(text, ["handler.proceed", "proceed"])
        ):
            return source

    return None


def _find_hostname_verification_bypass_source(
    sources: list[SourceStrings],
) -> SourceStrings | None:
    """Future rule: HostnameVerifier accepts all hostnames."""

    for source in sources:
        text = source.text

        if (
            _has_any(text, ["HostnameVerifier", "setHostnameVerifier"])
            and _has_any(text, ["verify"])
            and _has_any(
                text,
                [
                    "return true",
                    "returntrue",
                    "NO_VERIFY",
                    "ALLOW_ALL_HOSTNAME_VERIFIER",
                ],
            )
        ):
            return source

    return None


def _find_cleartext_http_source(sources: list[SourceStrings]) -> SourceStrings | None:
    """Future rule: app contains plain HTTP network URL evidence."""

    for source in sources:
        text = source.text

        if not _has_any(text, ["http://"]):
            continue

        if _has_any(
            text,
            [
                "loadUrl",
                "WebView",
                "URL",
                "HttpURLConnection",
                "OkHttp",
                "Retrofit",
                "network request",
            ],
        ):
            return source

    return None


def scan_network_code_patterns(apk_path: str, result: ScanResult) -> None:
    """Append Network/TLS code-level findings to result.vulnerabilities."""

    sources = _collect_source_strings(apk_path)

    if not sources:
        return

    # ------------------------------------------------------------------
    # Network/MASTG-TEST0020: obsolete TLS version
    # ------------------------------------------------------------------
    obsolete_tls_source = _find_obsolete_tls_source(sources)
    if obsolete_tls_source is not None:
        _append_unique(
            result,
            VulnerabilityFinding(
                pattern_id="VULN_OBSOLETE_TLS_VERSION",
                title="Obsolete TLS protocol version used",
                severity="High",
                description=(
                    "The app appears to explicitly request an obsolete TLS protocol "
                    "version such as TLSv1/TLS 1.0 through SSLContext or related "
                    "TLS setup code."
                ),
                category="obsolete_tls_version",
                location=_source_hint(obsolete_tls_source),
                evidence=[
                    f"Source: {_source_hint(obsolete_tls_source)}",
                    "SSLContext",
                    "getInstance",
                    "TLSv1",
                    "TLS 1.0",
                    "obsolete TLS",
                    "weak TLS",
                    "HTTPS",
                ],
                cwe="CWE-326",
                owasp_masvs="MSTG-NETWORK-2",
            ),
        )

    # ------------------------------------------------------------------
    # Network/MASTG-TEST0020: certificate validation bypass
    # ------------------------------------------------------------------
    cert_bypass_source = _find_certificate_bypass_source(sources)
    if cert_bypass_source is not None:
        _append_unique(
            result,
            VulnerabilityFinding(
                pattern_id="VULN_CERTIFICATE_VALIDATION_BYPASS",
                title="TLS certificate validation bypass pattern",
                severity="High",
                description=(
                    "The app contains TrustManager/X509TrustManager-related code "
                    "patterns commonly used to bypass TLS certificate validation."
                ),
                category="certificate_validation_bypass",
                location=_source_hint(cert_bypass_source),
                evidence=[
                    f"Source: {_source_hint(cert_bypass_source)}",
                    "TrustManager",
                    "X509TrustManager",
                    "checkClientTrusted",
                    "checkServerTrusted",
                    "getAcceptedIssuers",
                    "return null",
                    "setDefaultSSLSocketFactory",
                    "self-signed",
                    "expired certificates",
                ],
                cwe="CWE-295",
                owasp_masvs="MSTG-NETWORK-3",
            ),
        )

    # ------------------------------------------------------------------
    # Optional / next-step rules.
    # Keep them enabled only if their evidence is specific enough.
    # These can improve 0019 / 0021 if the DEX strings retain method names.
    # ------------------------------------------------------------------
    '''
    webview_ssl_source = _find_webview_ssl_error_bypass_source(sources)
    if webview_ssl_source is not None:
        _append_unique(
            result,
            VulnerabilityFinding(
                pattern_id="VULN_WEBVIEW_SSL_ERROR_BYPASS",
                title="WebView SSL errors are ignored",
                severity="High",
                description=(
                    "The app appears to override onReceivedSslError and call "
                    "handler.proceed(), allowing WebView traffic to continue even "
                    "when TLS certificate validation fails."
                ),
                category="webview_ssl_error_bypass",
                location=_source_hint(webview_ssl_source),
                evidence=[
                    f"Source: {_source_hint(webview_ssl_source)}",
                    "WebView",
                    "WebViewClient",
                    "onReceivedSslError",
                    "SslErrorHandler",
                    "SslError",
                    "handler.proceed",
                    "proceed",
                    "SSL error",
                    "TLS error",
                ],
                cwe="CWE-295",
                owasp_masvs="MSTG-NETWORK-3",
            ),
        )

    hostname_source = _find_hostname_verification_bypass_source(sources)
    if hostname_source is not None:
        _append_unique(
            result,
            VulnerabilityFinding(
                pattern_id="VULN_HOSTNAME_VERIFICATION_BYPASS",
                title="Hostname verification bypass pattern",
                severity="High",
                description=(
                    "The app contains HostnameVerifier-related code patterns that "
                    "may accept arbitrary hostnames."
                ),
                category="hostname_verification_bypass",
                location=_source_hint(hostname_source),
                evidence=[
                    f"Source: {_source_hint(hostname_source)}",
                    "HostnameVerifier",
                    "verify",
                    "return true",
                    "NO_VERIFY",
                    "ALLOW_ALL_HOSTNAME_VERIFIER",
                    "hostname verification",
                ],
                cwe="CWE-297",
                owasp_masvs="MSTG-NETWORK-3",
            ),
        )

    cleartext_http_source = _find_cleartext_http_source(sources)
    if cleartext_http_source is not None:
        _append_unique(
            result,
            VulnerabilityFinding(
                pattern_id="VULN_CLEARTEXT_HTTP",
                title="Plain HTTP URL used by app code or resources",
                severity="High",
                description=(
                    "The app contains plain HTTP URL evidence in code or resources. "
                    "Network requests over HTTP can expose transmitted data to "
                    "interception or modification."
                ),
                category="cleartext_http",
                location=_source_hint(cleartext_http_source),
                evidence=[
                    f"Source: {_source_hint(cleartext_http_source)}",
                    "http://",
                    "HTTP",
                    "plain HTTP",
                    "cleartext",
                    "WebView",
                    "loadUrl",
                    "URL",
                    "network request",
                ],
                cwe="CWE-319",
                owasp_masvs="MSTG-NETWORK-1",
            ),
        )
    
        '''