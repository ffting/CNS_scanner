"""Network / TLS static code-pattern scanner for APK.

This module scans APK internals for Network/TLS security patterns.

Design goals:
- Use lightweight DEX string scanning for broad but conservative evidence.
- Use Androguard method-level instruction scanning for obsolete TLS version.
- Avoid APK-wide keyword mixing.
- Append VulnerabilityFinding objects directly to ScanResult.

Current enabled rules:
- obsolete_tls_version
- certificate_validation_bypass

Prepared but disabled rules:
- webview_ssl_error_bypass
- hostname_verification_bypass
- cleartext_http
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK

from models import ScanResult, VulnerabilityFinding


# ============================================================================
# Config
# ============================================================================

# Keep this False for now.
# Turn on only after you check case-level FP/FN.
ENABLE_EXPERIMENTAL_0021_RULES = False

# Keep this False for now.
# cleartext_http is especially easy to over-report from URLs in libraries/resources.
ENABLE_CLEARTEXT_HTTP_RULE = False


# ============================================================================
# Data model
# ============================================================================

@dataclass(frozen=True)
class SourceStrings:
    """Strings extracted from one APK internal file."""

    name: str
    text: str


@dataclass(frozen=True)
class MethodText:
    """Instruction text extracted from one DEX method."""

    name: str
    text: str


# ============================================================================
# String extraction
# ============================================================================

def _iter_ascii_strings(data: bytes, min_len: int = 4) -> Iterable[str]:
    """Extract printable ASCII runs from binary data.

    DEX files often preserve class names, method names, constants, URLs,
    and selected string literals as ASCII-ish runs.

    This is intentionally simple. It is not a replacement for JADX or
    full method-level semantic analysis.
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


def _should_scan_file(filename: str) -> bool:
    """Return whether an APK internal file should be scanned.

    For code-level Network/TLS pattern matching, only scan DEX files.

    Do NOT scan:
    - res/*.xml
    - resources.arsc
    - assets/*
    - META-INF/*
    - arbitrary APK-wide bytes

    XML-level Network Security Config rules should be handled by
    vulnerability_patterns.py.
    """

    filename = filename.lower()
    return filename.endswith(".dex")


def _collect_source_strings(
    apk_path: str,
    max_bytes_per_file: int = 8_000_000,
) -> list[SourceStrings]:
    """Collect strings per APK internal DEX file.

    Do not merge all APK files into one text before matching.
    APK-wide merging can create false positives.
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


def _collect_method_texts(apk_path: str) -> list[MethodText]:
    """Collect instruction text per DEX method using Androguard.

    This is more precise than scanning whole classes.dex strings because
    evidence is kept within the same method.

    Main purpose:
    - Detect SSLContext.getInstance("TLSv1")-style obsolete TLS usage.
    - Avoid false positives from unrelated TLS keywords in the same DEX file.
    """

    methods: list[MethodText] = []

    try:
        _apk, dex_list, _dx = AnalyzeAPK(apk_path)
    except Exception:
        return methods

    if dex_list is None:
        return methods

    if not isinstance(dex_list, list):
        dex_list = [dex_list]

    for dex in dex_list:
        try:
            classes = dex.get_classes()
        except Exception:
            continue

        for cls in classes:
            try:
                class_name = cls.get_name()
            except Exception:
                class_name = "<unknown-class>"

            try:
                class_methods = cls.get_methods()
            except Exception:
                continue

            for method in class_methods:
                try:
                    code = method.get_code()
                except Exception:
                    code = None

                if code is None:
                    continue

                try:
                    method_name = method.get_name()
                except Exception:
                    method_name = "<unknown-method>"

                try:
                    descriptor = method.get_descriptor()
                except Exception:
                    descriptor = ""

                try:
                    instructions = method.get_instructions()
                except Exception:
                    continue

                instruction_lines: list[str] = []

                for ins in instructions:
                    try:
                        instruction_lines.append(
                            f"{ins.get_name()} {ins.get_output()}"
                        )
                    except Exception:
                        continue

                if not instruction_lines:
                    continue

                methods.append(
                    MethodText(
                        name=f"{class_name}->{method_name}{descriptor}",
                        text="\n".join(instruction_lines),
                    )
                )

    return methods


# ============================================================================
# Helper functions
# ============================================================================

def _lower(text: str) -> str:
    return text.lower()


def _has_any(text: str, keywords: list[str]) -> bool:
    lower = _lower(text)
    return any(keyword.lower() in lower for keyword in keywords)


def _has_all(text: str, keywords: list[str]) -> bool:
    lower = _lower(text)
    return all(keyword.lower() in lower for keyword in keywords)


def _matched_keywords(text: str, keywords: list[str]) -> list[str]:
    lower = _lower(text)
    return [keyword for keyword in keywords if keyword.lower() in lower]


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


# ============================================================================
# Rule 1: obsolete TLS version, method-level
# ============================================================================

def _find_obsolete_tls_method(methods: list[MethodText]) -> MethodText | None:
    """Find obsolete TLS usage inside the same method.

    Intended to detect patterns like:
        SSLContext.getInstance("TLSv1")

    This avoids false positives where classes.dex contains unrelated:
        TLSv1 + SSLContext + getInstance
    somewhere in the global string pool.
    """

    obsolete_tls_markers = [
        '"TLSv1"',
        "'TLSv1'",
        "TLSv1",
        '"TLSv1.0"',
        "'TLSv1.0'",
        "TLSv1.0",
        '"SSLv3"',
        "'SSLv3'",
        "SSLv3",
    ]

    ssl_context_get_instance_markers = [
        "Ljavax/net/ssl/SSLContext;->getInstance",
        "javax/net/ssl/SSLContext",
        "SSLContext;->getInstance",
        "SSLContext.getInstance",
    ]

    set_enabled_protocols_markers = [
        "setEnabledProtocols",
    ]

    for method in methods:
        text = method.text

        has_obsolete_tls = _has_any(text, obsolete_tls_markers)
        if not has_obsolete_tls:
            continue

        has_sslcontext_getinstance = _has_any(
            text,
            ssl_context_get_instance_markers,
        )

        has_set_enabled_protocols = _has_any(
            text,
            set_enabled_protocols_markers,
        )

        if has_sslcontext_getinstance:
            return method

        if has_set_enabled_protocols:
            return method

    return None


# ============================================================================
# Rule 2: certificate validation bypass, DEX string-level
# ============================================================================

def _find_certificate_bypass_source(sources: list[SourceStrings]) -> SourceStrings | None:
    """Find evidence of TLS certificate validation bypass.

    Conservative but not too strict:
    - TrustManager + checkServerTrusted only is not enough.
    - getAcceptedIssuers + SSLContext only is not enough.
    - Stronger fallback requires both checkServerTrusted and checkClientTrusted.
    """

    trust_manager_markers = [
        "X509TrustManager",
        "javax.net.ssl.X509TrustManager",
        "TrustManager",
        "javax.net.ssl.TrustManager",
    ]

    explicit_bypass_markers = [
        "return null",
        "returnnull",
        "return true",
        "returntrue",
        "trustAllCerts",
        "TrustAll",
        "trust all",
        "accept all certificates",
        "acceptAllCerts",
        "allowAllCerts",
        "disableCertificateValidation",
        "NullX509TrustManager",
        "NaiveTrustManager",
        "UnsafeTrustManager",
        "DummyTrustManager",
        "FakeTrustManager",
    ]

    dangerous_socket_markers = [
        "setDefaultSSLSocketFactory",
        "setSSLSocketFactory",
    ]

    ssl_context_markers = [
        "SSLContext",
        "javax.net.ssl.SSLContext",
        "sslContext.init",
        "context.init",
        "HttpsURLConnection",
    ]

    for source in sources:
        text = source.text

        has_trust_manager = _has_any(text, trust_manager_markers)

        has_check_server = _has_any(text, ["checkServerTrusted"])
        has_check_client = _has_any(text, ["checkClientTrusted"])
        has_any_check_method = has_check_server or has_check_client

        has_get_accepted_issuers = _has_any(text, ["getAcceptedIssuers"])
        has_explicit_bypass = _has_any(text, explicit_bypass_markers)
        has_dangerous_socket_setup = _has_any(text, dangerous_socket_markers)
        has_ssl_context = _has_any(text, ssl_context_markers)

        # Strong evidence:
        # custom TrustManager + trust-check method + explicit bypass marker.
        if has_trust_manager and has_any_check_method and has_explicit_bypass:
            return source

        # Strong evidence:
        # custom TrustManager + trust-check method + global socket override.
        if has_trust_manager and has_any_check_method and has_dangerous_socket_setup:
            return source

        # Conservative fallback:
        # both server/client trust checks exist, accepted issuers exists,
        # and SSLContext setup exists.
        #
        # This is stricter than:
        # TrustManager + checkServerTrusted + getAcceptedIssuers + SSLContext
        #
        # because that broader pattern caused FP in MASTG-TEST0022.
        if (
            has_trust_manager
            and has_check_server
            and has_check_client
            and has_get_accepted_issuers
            and has_ssl_context
        ):
            return source

    return None


# ============================================================================
# Prepared rule: WebView SSL error bypass
# ============================================================================

def _find_webview_ssl_error_bypass_source(
    sources: list[SourceStrings],
) -> SourceStrings | None:
    """Find WebView SSL error bypass.

    Target candidates:
    - Network/MASTG-TEST0019
    - Network/MASTG-TEST0021

    Disabled by default because DEX string scanning may not reliably prove
    that handler.proceed() is inside onReceivedSslError().
    """

    for source in sources:
        text = source.text

        has_callback = _has_any(text, ["onReceivedSslError"])
        has_handler = _has_any(text, ["SslErrorHandler", "android.webkit.SslErrorHandler"])
        has_ssl_error = _has_any(text, ["SslError", "android.net.http.SslError"])
        has_proceed = _has_any(text, ["handler.proceed", ".proceed", "proceed"])

        if has_callback and has_handler and has_ssl_error and has_proceed:
            return source

    return None


# ============================================================================
# Prepared rule: hostname verification bypass
# ============================================================================

def _find_hostname_verification_bypass_source(
    sources: list[SourceStrings],
) -> SourceStrings | None:
    """Find HostnameVerifier bypass.

    Target candidates:
    - Network/MASTG-TEST0019
    - Network/MASTG-TEST0021

    Disabled by default because string-level matching cannot always prove
    verify() returns true unconditionally.
    """

    verifier_markers = [
        "HostnameVerifier",
        "javax.net.ssl.HostnameVerifier",
        "setHostnameVerifier",
    ]

    bypass_markers = [
        "return true",
        "returntrue",
        "NO_VERIFY",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "AllowAllHostnameVerifier",
    ]

    for source in sources:
        text = source.text

        has_verifier = _has_any(text, verifier_markers)
        has_verify = _has_any(text, ["verify"])
        has_bypass = _has_any(text, bypass_markers)

        if has_verifier and has_verify and has_bypass:
            return source

    return None


# ============================================================================
# Prepared rule: cleartext HTTP
# ============================================================================

def _find_cleartext_http_source(sources: list[SourceStrings]) -> SourceStrings | None:
    """Find plain HTTP URL evidence.

    Disabled by default.

    Reason:
    `http://` can appear in:
    - library constants
    - documentation strings
    - test URLs
    - tracking endpoints
    - fallback URLs
    - resources unrelated to actual network request execution

    Prefer manifest/XML rule usesCleartextTraffic first.
    """

    network_context_markers = [
        "loadUrl",
        "WebView",
        "URL",
        "HttpURLConnection",
        "OkHttp",
        "Retrofit",
        "Request.Builder",
        "openConnection",
    ]

    for source in sources:
        text = source.text

        if not _has_any(text, ["http://"]):
            continue

        if _has_any(text, network_context_markers):
            return source

    return None


# ============================================================================
# Finding builders
# ============================================================================

def _append_obsolete_tls_method_finding(
    result: ScanResult,
    method: MethodText,
) -> None:
    text = method.text

    evidence = [
        f"Method: {method.name}",
    ]

    evidence.extend(
        _matched_keywords(
            text,
            [
                "TLSv1.0",
                "TLSv1",
                "SSLv3",
                "SSLContext",
                "getInstance",
                "Ljavax/net/ssl/SSLContext;->getInstance",
                "setEnabledProtocols",
            ],
        )
    )

    _append_unique(
        result,
        VulnerabilityFinding(
            pattern_id="VULN_OBSOLETE_TLS_VERSION",
            title="Obsolete TLS protocol version used",
            severity="High",
            description=(
                "The app appears to explicitly request an obsolete TLS protocol "
                "version such as TLSv1/TLS 1.0/SSLv3 through SSLContext or "
                "related TLS setup code."
            ),
            category="obsolete_tls_version",
            location=method.name,
            evidence=evidence,
            cwe="CWE-326",
            owasp_masvs="MSTG-NETWORK-2",
        ),
    )


def _append_certificate_bypass_finding(
    result: ScanResult,
    source: SourceStrings,
) -> None:
    text = source.text

    evidence = [
        f"Source: {_source_hint(source)}",
    ]

    evidence.extend(
        _matched_keywords(
            text,
            [
                "TrustManager",
                "X509TrustManager",
                "checkClientTrusted",
                "checkServerTrusted",
                "getAcceptedIssuers",
                "return null",
                "trustAllCerts",
                "setDefaultSSLSocketFactory",
                "SSLContext",
                "HttpsURLConnection",
                "self-signed",
                "expired certificates",
            ],
        )
    )

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
            location=_source_hint(source),
            evidence=evidence,
            cwe="CWE-295",
            owasp_masvs="MSTG-NETWORK-3",
        ),
    )


def _append_webview_ssl_error_bypass_finding(
    result: ScanResult,
    source: SourceStrings,
) -> None:
    text = source.text

    evidence = [
        f"Source: {_source_hint(source)}",
    ]

    evidence.extend(
        _matched_keywords(
            text,
            [
                "WebView",
                "WebViewClient",
                "onReceivedSslError",
                "SslErrorHandler",
                "SslError",
                "handler.proceed",
                "proceed",
            ],
        )
    )

    _append_unique(
        result,
        VulnerabilityFinding(
            pattern_id="VULN_WEBVIEW_SSL_ERROR_BYPASS",
            title="WebView SSL errors are ignored",
            severity="High",
            description=(
                "The app appears to override onReceivedSslError and continue "
                "loading by calling proceed(), which can bypass TLS certificate "
                "error handling in WebView."
            ),
            category="webview_ssl_error_bypass",
            location=_source_hint(source),
            evidence=evidence,
            cwe="CWE-295",
            owasp_masvs="MSTG-NETWORK-3",
        ),
    )


def _append_hostname_verification_bypass_finding(
    result: ScanResult,
    source: SourceStrings,
) -> None:
    text = source.text

    evidence = [
        f"Source: {_source_hint(source)}",
    ]

    evidence.extend(
        _matched_keywords(
            text,
            [
                "HostnameVerifier",
                "setHostnameVerifier",
                "verify",
                "return true",
                "NO_VERIFY",
                "ALLOW_ALL_HOSTNAME_VERIFIER",
                "AllowAllHostnameVerifier",
            ],
        )
    )

    _append_unique(
        result,
        VulnerabilityFinding(
            pattern_id="VULN_HOSTNAME_VERIFICATION_BYPASS",
            title="Hostname verification bypass pattern",
            severity="High",
            description=(
                "The app contains HostnameVerifier-related code patterns that "
                "may accept arbitrary hostnames, weakening TLS hostname checks."
            ),
            category="hostname_verification_bypass",
            location=_source_hint(source),
            evidence=evidence,
            cwe="CWE-297",
            owasp_masvs="MSTG-NETWORK-3",
        ),
    )


def _append_cleartext_http_finding(
    result: ScanResult,
    source: SourceStrings,
) -> None:
    text = source.text

    evidence = [
        f"Source: {_source_hint(source)}",
    ]

    evidence.extend(
        _matched_keywords(
            text,
            [
                "http://",
                "loadUrl",
                "WebView",
                "URL",
                "HttpURLConnection",
                "OkHttp",
                "Retrofit",
                "openConnection",
            ],
        )
    )

    _append_unique(
        result,
        VulnerabilityFinding(
            pattern_id="VULN_CLEARTEXT_HTTP",
            title="Plain HTTP URL used by app code",
            severity="High",
            description=(
                "The app contains plain HTTP URL evidence in DEX strings. "
                "Network requests over HTTP can expose transmitted data to "
                "interception or modification."
            ),
            category="cleartext_http",
            location=_source_hint(source),
            evidence=evidence,
            cwe="CWE-319",
            owasp_masvs="MSTG-NETWORK-1",
        ),
    )


# ============================================================================
# Public entry
# ============================================================================

def scan_network_code_patterns(apk_path: str, result: ScanResult) -> None:
    """Append Network/TLS code-level findings to result.vulnerabilities.

    Current strategy:
    1. Collect per-DEX strings for certificate validation bypass.
    2. Collect per-method instruction text for obsolete TLS.
    3. Append unique findings.

    Enabled by default:
    - obsolete_tls_version
    - certificate_validation_bypass

    Disabled by default:
    - webview_ssl_error_bypass
    - hostname_verification_bypass
    - cleartext_http
    """

    sources = _collect_source_strings(apk_path)
    methods = _collect_method_texts(apk_path)

    if not sources and not methods:
        return

    # ------------------------------------------------------------------
    # Network/MASTG-TEST0020: obsolete TLS version
    # Use method-level analysis instead of whole DEX string matching.
    # ------------------------------------------------------------------
    obsolete_tls_method = _find_obsolete_tls_method(methods)
    if obsolete_tls_method is not None:
        _append_obsolete_tls_method_finding(result, obsolete_tls_method)

    # ------------------------------------------------------------------
    # Network/MASTG-TEST0020: certificate validation bypass
    # Keep DEX string-level rule because it currently works for 0020 and
    # no longer triggers the previous 0022 certificate bypass FP.
    # ------------------------------------------------------------------
    cert_bypass_source = _find_certificate_bypass_source(sources)
    if cert_bypass_source is not None:
        _append_certificate_bypass_finding(result, cert_bypass_source)

    # ------------------------------------------------------------------
    # Experimental rules for 0019 / 0021.
    # Keep disabled until we verify FP behavior.
    # ------------------------------------------------------------------
    if ENABLE_EXPERIMENTAL_0021_RULES:
        webview_ssl_source = _find_webview_ssl_error_bypass_source(sources)
        if webview_ssl_source is not None:
            _append_webview_ssl_error_bypass_finding(result, webview_ssl_source)

        hostname_source = _find_hostname_verification_bypass_source(sources)
        if hostname_source is not None:
            _append_hostname_verification_bypass_finding(result, hostname_source)

    # ------------------------------------------------------------------
    # Experimental cleartext HTTP rule.
    # Keep disabled because this is easy to over-report.
    # ------------------------------------------------------------------
    if ENABLE_CLEARTEXT_HTTP_RULE:
        cleartext_http_source = _find_cleartext_http_source(sources)
        if cleartext_http_source is not None:
            _append_cleartext_http_finding(result, cleartext_http_source)