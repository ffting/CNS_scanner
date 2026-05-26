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
| mobsf | 5 | 16 | 42 | 37 | 0 | 37 | 16 | 0.0000 | 0.0000 | N/A | 0.0000 | N/A | N/A | N/A |
| our_scanner | 5 | 16 | 0 | 0 | 0 | 0 | 16 | N/A | 0.0000 | N/A | N/A | N/A | N/A | N/A |

## Per-case Results

### mobsf

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Network/MASTG-TEST0019 | 5 | 6 | 0 | 6 | 5 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | N/A |
| Network/MASTG-TEST0020 | 2 | 5 | 0 | 5 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | N/A |
| Network/MASTG-TEST0021 | 5 | 8 | 0 | 8 | 5 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | N/A |
| Network/MASTG-TEST0022 | 2 | 11 | 0 | 11 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | N/A |
| Network/MASTG-TEST0023 | 2 | 7 | 0 | 7 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | N/A |

### our_scanner

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Network/MASTG-TEST0019 | 5 | 0 | 0 | 0 | 5 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Network/MASTG-TEST0020 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Network/MASTG-TEST0021 | 5 | 0 | 0 | 0 | 5 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Network/MASTG-TEST0022 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Network/MASTG-TEST0023 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |

## Matched Details

### mobsf

### our_scanner

## Unmatched Details

This section helps inspect false negatives and false positives.

### mobsf

#### Network/MASTG-TEST0019

Unmatched expected vulnerabilities:

- `cleartext_http` id=`GT-0019-1` component=`` location=`` description=The app makes network requests to plain HTTP URLs instead of HTTPS, exposing transmitted data to interception or modification.
- `uses_cleartext_traffic` id=`GT-0019-2` component=`` location=`` description=The AndroidManifest.xml explicitly enables cleartext traffic by setting android:usesCleartextTraffic="true" in the application tag.
- `hostname_verification_bypass` id=`GT-0019-3` component=`` location=`` description=The app skips hostname verification, which can allow man-in-the-middle attackers to present certificates for the wrong host.
- `tls_error_handling_disabled` id=`GT-0019-4` component=`` location=`` description=The app disables TLS or SSL error handling, allowing connections to proceed even when certificate validation fails.
- `low_min_sdk_network_security_bypass` id=`GT-0019-5` component=`` location=`` description=The app uses a low minimum SDK version, minSdk = 19, which can weaken or bypass protections expected from newer Android network security defaults.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 4.4-4.4.4, [minSdk=19] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 4.4-4.4.4, [minsdk=19] component=["4.4-4.4.4", "19"] description=this application ca...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `manifest` id=`MOBSF_MANIFEST_CLEAR_TEXT_TRAFFIC` severity=`High` sev_score=`7` conf_score=`7` title=Clear text traffic is Enabled For App[android:usesCleartextTraffic=true] evidence=rule=clear_text_traffic title=clear text traffic is enabled for app[android:usescleartexttraffic=true] description=the app intends to use cleartext network traffic, such as clearte...
- `webview` id=`MOBSF_CODE_ANDROID_WEBVIEW_IGNORE_SSL` severity=`High` sev_score=`7` conf_score=`7` title=Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MI... evidence=rule=android_webview_ignore_ssl description=insecure webview implementation. webview ignores ssl certificate errors and accept any ssl certificate. this application is vulnerable t...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_VULNERABLE_TO_JANUS_VULNERABILITY` severity=`Medium` sev_score=`5` conf_score=`8` title=Application vulnerable to Janus Vulnerability evidence=title=application vulnerable to janus vulnerability description=application is signed with v1 signature scheme, making it vulnerable to janus vulnerability on android 5.0-8.0, if s...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate

#### Network/MASTG-TEST0020

Unmatched expected vulnerabilities:

- `obsolete_tls_version` id=`GT-0020-1` component=`` location=`` description=The app explicitly uses an outdated TLS protocol version, TLS 1.0, for HTTPS connections. Obsolete TLS versions are insecure and should be replaced with modern versions such as TLS 1.2 or TLS 1.3.
- `certificate_validation_bypass` id=`GT-0020-2` component=`` location=`` description=The app disables SSL/TLS certificate validation by installing a custom TrustManager that trusts all certificates, including self-signed or expired certificates.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_MISSING_CODE_SIGNING_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Missing Code Signing certificate evidence=title=missing code signing certificate description=code signing certificate not found
- `manifest` id=`MOBSF_MANIFEST_CLEAR_TEXT_TRAFFIC` severity=`High` sev_score=`7` conf_score=`7` title=Clear text traffic is Enabled For App[android:usesCleartextTraffic=true] evidence=rule=clear_text_traffic title=clear text traffic is enabled for app[android:usescleartexttraffic=true] description=the app intends to use cleartext network traffic, such as clearte...
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0020/mainactivity.java:13,14,14,15
- `android_api` id=`MOBSF_ANDROID_API_API_HTTPS_CONNECTION` severity=`Low` sev_score=`2` conf_score=`6` title=HTTPS Connection evidence=rule=api_https_connection description=https connection com/example/mastg_test0020/mainactivity.java:19,71,89,19

#### Network/MASTG-TEST0021

Unmatched expected vulnerabilities:

- `low_target_sdk_network_security` id=`GT-0021-1` component=`` location=`` description=The app targets Android API level 23, which is lower than 24. Apps targeting below Android 7.0 do not benefit from the newer default Network Security Configuration behavior that avoids trusting user-supplied CAs by default.
- `user_ca_trust_enabled` id=`GT-0021-2` component=`` location=`` description=The app may trust user-provided certificate authorities through insecure Network Security Configuration trust anchors, allowing malicious user-installed CAs to intercept TLS traffic.
- `webview_ssl_error_bypass` id=`GT-0021-3` component=`` location=`` description=The app ignores TLS certificate errors in WebView by overriding onReceivedSslError and calling handler.proceed(), allowing the WebView to continue loading pages even when certificate validation fails.
- `hostname_verification_bypass` id=`GT-0021-4` component=`` location=`` description=The app disables hostname verification by using a HostnameVerifier that always returns true, allowing TLS connections to succeed even when the server certificate does not match the requested hostname.
- `insecure_trust_manager` id=`GT-0021-5` component=`` location=`` description=The app lacks proper certificate validation through TrustManager or may use an insecure TrustManager pattern that accepts certificates without checking whether they are trusted, expired, or self-signed.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 4.4W-4.4W.2, [minSdk=20] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 4.4w-4.4w.2, [minsdk=20] component=["4.4w-4.4w.2", "20"] description=this applicatio...
- `exported_activity` id=`MOBSF_MANIFEST_TASK_HIJACKING2` severity=`High` sev_score=`7` conf_score=`8` title=Activity (com.example.mastg_test0021.MainActivity) is vulnerable to StrandHogg 2.0 evidence=rule=task_hijacking2 title=activity (com.example.mastg_test0021.mainactivity) is vulnerable to strandhogg 2.0 component=["com.example.mastg_test0021.mainactivity"] description=acti...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `webview` id=`MOBSF_CODE_ANDROID_WEBVIEW_IGNORE_SSL` severity=`High` sev_score=`7` conf_score=`7` title=Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MI... evidence=rule=android_webview_ignore_ssl description=insecure webview implementation. webview ignores ssl certificate errors and accept any ssl certificate. this application is vulnerable t...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_VULNERABLE_TO_JANUS_VULNERABILITY` severity=`Medium` sev_score=`5` conf_score=`8` title=Application vulnerable to Janus Vulnerability evidence=title=application vulnerable to janus vulnerability description=application is signed with v1 signature scheme, making it vulnerable to janus vulnerability on android 5.0-8.0, if s...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0021/mainactivity.java:31
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0021/mainactivity.java:3,31

#### Network/MASTG-TEST0022

Unmatched expected vulnerabilities:

- `missing_certificate_pinning` id=`GT-0022-1` component=`` location=`` description=The app includes a network request path that connects to www.example.com without certificate pinning, making the connection more exposed to interception if a malicious or user-installed CA is trusted.
- `certificate_pinning_configuration` id=`GT-0022-2` component=`` location=`` description=The app implements certificate pinning through Network Security Configuration. The scanner should identify the presence of pinning-related configuration such as pin-set entries and extract relevant evidence for review.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `manifest` id=`MOBSF_MANIFEST_HAS_NETWORK_SECURITY` severity=`Low` sev_score=`2` conf_score=`7` title=App has a Network Security Configuration[android:networkSecurityConfig=@xml/network_security_config] evidence=rule=has_network_security title=app has a network security configuration[android:networksecurityconfig=@xml/network_security_config] component=["@xml/network_security_config"] desc...
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_TCP` severity=`Low` sev_score=`2` conf_score=`6` title=TCP Socket evidence=rule=api_tcp description=tcp socket okio/deprecatedokio.java:7,18,67,92,7 okio/okio.java:10,85,101,10 okio/okio__jvmokiokt.java:11,26,48,50,50,56,58,58,11 okio/socketasynctimeout.j...
- `android_api` id=`MOBSF_ANDROID_API_API_MESSAGE_DIGEST` severity=`Low` sev_score=`2` conf_score=`6` title=Message Digest evidence=rule=api_message_digest description=message digest okio/buffer.java:14,521,521,14 okio/bytestring.java:16,164,164,16 okio/c0008segmentedbytestring.java:10,73,73,10 okio/hashingsink...
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0022/mainactivity.java:14,15,15,16,16,17 okio/asynctimeout.java:3,4,4,5 okio/buffer.java:4,5,5,6,...
- `android_api` id=`MOBSF_ANDROID_API_API_JAVA_REFLECTION` severity=`Low` sev_score=`2` conf_score=`6` title=Java Reflection evidence=rule=api_java_reflection description=java reflection okio/bytestring.java:12 okio/filesystem.java:279
- `android_api` id=`MOBSF_ANDROID_API_API_HTTP_CONNECTION` severity=`Low` sev_score=`2` conf_score=`6` title=HTTP Connection evidence=rule=api_http_connection description=http connection com/example/mastg_test0022/mainactivity.java:18,118,136,143,157,118
- `android_api` id=`MOBSF_ANDROID_API_API_CRYPTO` severity=`Low` sev_score=`2` conf_score=`6` title=Crypto evidence=rule=api_crypto description=crypto okio/buffer.java:521,15,16 okio/bytestring.java:164,18,19 okio/c0008segmentedbytestring.java:73,11,12 okio/ciphersink.java:5 okio/ciphersource.ja...

#### Network/MASTG-TEST0023

Unmatched expected vulnerabilities:

- `missing_security_provider_update` id=`GT-0023-1` component=`` location=`` description=The app does not update the Android security provider through Google Play Services ProviderInstaller. Without updating the provider, the app may continue using an outdated TLS/SSL implementation that is vulnerable to known SSL/TLS issues.
- `missing_google_play_services_dependency` id=`GT-0023-2` component=`` location=`` description=The app does not include the Google Play Services dependency required for using ProviderInstaller, such as com.google.android.gms:play-services-gcm. As a result, the app cannot perform the recommended security provider update checks.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0023/mainactivity.java:46
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0023/mainactivity.java:15,16,16,17,17,18,18,19,19,20,94,195,195,196,197
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0023/mainactivity.java:3,46

### our_scanner

#### Network/MASTG-TEST0019

Unmatched expected vulnerabilities:

- `cleartext_http` id=`GT-0019-1` component=`` location=`` description=The app makes network requests to plain HTTP URLs instead of HTTPS, exposing transmitted data to interception or modification.
- `uses_cleartext_traffic` id=`GT-0019-2` component=`` location=`` description=The AndroidManifest.xml explicitly enables cleartext traffic by setting android:usesCleartextTraffic="true" in the application tag.
- `hostname_verification_bypass` id=`GT-0019-3` component=`` location=`` description=The app skips hostname verification, which can allow man-in-the-middle attackers to present certificates for the wrong host.
- `tls_error_handling_disabled` id=`GT-0019-4` component=`` location=`` description=The app disables TLS or SSL error handling, allowing connections to proceed even when certificate validation fails.
- `low_min_sdk_network_security_bypass` id=`GT-0019-5` component=`` location=`` description=The app uses a low minimum SDK version, minSdk = 19, which can weaken or bypass protections expected from newer Android network security defaults.

#### Network/MASTG-TEST0020

Unmatched expected vulnerabilities:

- `obsolete_tls_version` id=`GT-0020-1` component=`` location=`` description=The app explicitly uses an outdated TLS protocol version, TLS 1.0, for HTTPS connections. Obsolete TLS versions are insecure and should be replaced with modern versions such as TLS 1.2 or TLS 1.3.
- `certificate_validation_bypass` id=`GT-0020-2` component=`` location=`` description=The app disables SSL/TLS certificate validation by installing a custom TrustManager that trusts all certificates, including self-signed or expired certificates.

#### Network/MASTG-TEST0021

Unmatched expected vulnerabilities:

- `low_target_sdk_network_security` id=`GT-0021-1` component=`` location=`` description=The app targets Android API level 23, which is lower than 24. Apps targeting below Android 7.0 do not benefit from the newer default Network Security Configuration behavior that avoids trusting user-supplied CAs by default.
- `user_ca_trust_enabled` id=`GT-0021-2` component=`` location=`` description=The app may trust user-provided certificate authorities through insecure Network Security Configuration trust anchors, allowing malicious user-installed CAs to intercept TLS traffic.
- `webview_ssl_error_bypass` id=`GT-0021-3` component=`` location=`` description=The app ignores TLS certificate errors in WebView by overriding onReceivedSslError and calling handler.proceed(), allowing the WebView to continue loading pages even when certificate validation fails.
- `hostname_verification_bypass` id=`GT-0021-4` component=`` location=`` description=The app disables hostname verification by using a HostnameVerifier that always returns true, allowing TLS connections to succeed even when the server certificate does not match the requested hostname.
- `insecure_trust_manager` id=`GT-0021-5` component=`` location=`` description=The app lacks proper certificate validation through TrustManager or may use an insecure TrustManager pattern that accepts certificates without checking whether they are trusted, expired, or self-signed.

#### Network/MASTG-TEST0022

Unmatched expected vulnerabilities:

- `missing_certificate_pinning` id=`GT-0022-1` component=`` location=`` description=The app includes a network request path that connects to www.example.com without certificate pinning, making the connection more exposed to interception if a malicious or user-installed CA is trusted.
- `certificate_pinning_configuration` id=`GT-0022-2` component=`` location=`` description=The app implements certificate pinning through Network Security Configuration. The scanner should identify the presence of pinning-related configuration such as pin-set entries and extract relevant evidence for review.

#### Network/MASTG-TEST0023

Unmatched expected vulnerabilities:

- `missing_security_provider_update` id=`GT-0023-1` component=`` location=`` description=The app does not update the Android security provider through Google Play Services ProviderInstaller. Without updating the provider, the app may continue using an outdated TLS/SSL implementation that is vulnerable to known SSL/TLS issues.
- `missing_google_play_services_dependency` id=`GT-0023-2` component=`` location=`` description=The app does not include the Google Play Services dependency required for using ProviderInstaller, such as com.google.android.gms:play-services-gcm. As a result, the app cannot perform the recommended security provider update checks.
