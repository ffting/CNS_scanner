# Evaluation Report

## Settings

- Must-detect only: `True`
- Ignore third-party findings: `True`
- Scope filter enabled: `True`
- Top-k: `5`
- High confidence threshold: `8`
- High severity threshold: `8`
- Minimum severity score filter: `None`
- Minimum confidence score filter: `None`

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 | High-Conf Precision | High-Priority Precision | Severity MAE | Confidence MAE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| our_scanner | 5 | 16 | 9 | 9 | 6 | 3 | 10 | 0.6667 | 0.3750 | 0.4800 | 0.6667 | 0.5000 | N/A | N/A |

## Per-case Results

### our_scanner

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Network/MASTG-TEST0019 | 5 | 2 | 2 | 0 | 3 | 1.0000 | 0.4000 | 0.5714 | 1.0000 | 1.0000 | N/A |
| Network/MASTG-TEST0020 | 2 | 3 | 2 | 1 | 0 | 0.6667 | 1.0000 | 0.8000 | 0.6667 | 0.6667 | 1.0000 |
| Network/MASTG-TEST0021 | 5 | 1 | 1 | 0 | 4 | 1.0000 | 0.2000 | 0.3333 | 1.0000 | 1.0000 | N/A |
| Network/MASTG-TEST0022 | 2 | 3 | 1 | 2 | 1 | 0.3333 | 0.5000 | 0.4000 | 0.3333 | 0.3333 | 0.0000 |
| Network/MASTG-TEST0023 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |

## Matched Details

### our_scanner

#### Network/MASTG-TEST0019

- GT `GT-0019-2` `uses_cleartext_traffic` matched by `VULN_USES_CLEARTEXT_TRAFFIC` `uses_cleartext_traffic` score=(7, 10) type=`medium` title=Cleartext traffic explicitly enabled in manifest
- GT `GT-0019-5` `low_min_sdk_network_security_bypass` matched by `VULN_LOW_MIN_SDK_NETWORK_SECURITY_BYPASS` `low_min_sdk_network_security_bypass` score=(5, 10) type=`medium` title=Low minSdk may weaken network security defaults

#### Network/MASTG-TEST0020

- GT `GT-0020-1` `obsolete_tls_version` matched by `VULN_OBSOLETE_TLS_VERSION` `obsolete_tls_version` score=(7, 10) type=`medium` title=Obsolete TLS protocol version used
- GT `GT-0020-2` `certificate_validation_bypass` matched by `VULN_CERTIFICATE_VALIDATION_BYPASS` `certificate_validation_bypass` score=(8, 10) type=`medium` title=TLS certificate validation bypass pattern

#### Network/MASTG-TEST0021

- GT `GT-0021-1` `low_target_sdk_network_security` matched by `VULN_LOW_TARGET_SDK_NETWORK_SECURITY` `low_target_sdk_network_security` score=(5, 10) type=`medium` title=Low targetSdk weakens Network Security Configuration defaults

#### Network/MASTG-TEST0022

- GT `GT-0022-2` `certificate_pinning_configuration` matched by `VULN_CERTIFICATE_PINNING_CONFIGURATION` `certificate_pinning_configuration` score=(3, 10) type=`medium` title=Certificate pinning configured in Network Security Configuration

## Unmatched Details

This section helps inspect false negatives and false positives.

### our_scanner

#### Network/MASTG-TEST0019

Unmatched expected vulnerabilities:

- `cleartext_http` id=`GT-0019-1` component=`` location=`` description=The app makes network requests to plain HTTP URLs instead of HTTPS, exposing transmitted data to interception or modification.
- `hostname_verification_bypass` id=`GT-0019-3` component=`` location=`` description=The app skips hostname verification, which can allow man-in-the-middle attackers to present certificates for the wrong host.
- `tls_error_handling_disabled` id=`GT-0019-4` component=`` location=`` description=The app disables TLS or SSL error handling, allowing connections to proceed even when certificate validation fails.

#### Network/MASTG-TEST0020

Unmatched findings:

- `uses_cleartext_traffic` id=`VULN_USES_CLEARTEXT_TRAFFIC` severity=`High` sev_score=`7` conf_score=`10` title=Cleartext traffic explicitly enabled in manifest evidence=android:usescleartexttraffic=true androidmanifest.xml application cleartext cleartext traffic

#### Network/MASTG-TEST0021

Unmatched expected vulnerabilities:

- `user_ca_trust_enabled` id=`GT-0021-2` component=`` location=`` description=The app may trust user-provided certificate authorities through insecure Network Security Configuration trust anchors, allowing malicious user-installed CAs to intercept TLS traffic.
- `webview_ssl_error_bypass` id=`GT-0021-3` component=`` location=`` description=The app ignores TLS certificate errors in WebView by overriding onReceivedSslError and calling handler.proceed(), allowing the WebView to continue loading pages even when certificate validation fails.
- `hostname_verification_bypass` id=`GT-0021-4` component=`` location=`` description=The app disables hostname verification by using a HostnameVerifier that always returns true, allowing TLS connections to succeed even when the server certificate does not match the requested hostname.
- `insecure_trust_manager` id=`GT-0021-5` component=`` location=`` description=The app lacks proper certificate validation through TrustManager or may use an insecure TrustManager pattern that accepts certificates without checking whether they are trusted, expired, or self-signed.

#### Network/MASTG-TEST0022

Unmatched expected vulnerabilities:

- `missing_certificate_pinning` id=`GT-0022-1` component=`` location=`` description=The app includes a network request path that connects to www.example.com without certificate pinning, making the connection more exposed to interception if a malicious or user-installed CA is trusted.

Unmatched findings:

- `certificate_validation_bypass` id=`VULN_CERTIFICATE_VALIDATION_BYPASS` severity=`High` sev_score=`8` conf_score=`10` title=TLS certificate validation bypass pattern evidence=source: classes.dex trustmanager x509trustmanager checkclienttrusted checkservertrusted getacceptedissuers return null setdefaultsslsocketfactory self-signed expired certificates
- `obsolete_tls_version` id=`VULN_OBSOLETE_TLS_VERSION` severity=`High` sev_score=`7` conf_score=`10` title=Obsolete TLS protocol version used evidence=source: classes.dex sslcontext getinstance tlsv1 tls 1.0 obsolete tls weak tls https

#### Network/MASTG-TEST0023

Unmatched expected vulnerabilities:

- `missing_security_provider_update` id=`GT-0023-1` component=`` location=`` description=The app does not update the Android security provider through Google Play Services ProviderInstaller. Without updating the provider, the app may continue using an outdated TLS/SSL implementation that is vulnerable to known SSL/TLS issues.
- `missing_google_play_services_dependency` id=`GT-0023-2` component=`` location=`` description=The app does not include the Google Play Services dependency required for using ProviderInstaller, such as com.google.android.gms:play-services-gcm. As a result, the app cannot perform the recommended security provider update checks.
