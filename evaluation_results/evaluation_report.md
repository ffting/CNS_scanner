# Evaluation Report

## Settings

- Must-detect only: `True`
- Ignore third-party findings: `True`
- Scope filter enabled: `True`
- Top-k: `5`

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 10 | 25 | 65 | 32 | 9 | 23 | 16 | 0.2812 | 0.3600 | 0.3158 |
| our_scanner | 10 | 25 | 0 | 0 | 0 | 0 | 25 | N/A | 0.0000 | N/A |

## Per-case Results

### mobsf

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 5 | 2 | 3 | 0 | 0.4000 | 1.0000 | 0.5714 | 0.6000 |
| Platform/MASTG-TEST0008 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0024 | 2 | 3 | 0 | 3 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 |
| Platform/MASTG-TEST0028 | 3 | 5 | 3 | 2 | 0 | 0.6000 | 1.0000 | 0.7500 | 0.8000 |
| Platform/MASTG-TEST0030 | 2 | 1 | 0 | 1 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 |
| Platform/MASTG-TEST0031 | 2 | 2 | 0 | 2 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 |
| Platform/MASTG-TEST0032 | 3 | 5 | 1 | 4 | 2 | 0.2000 | 0.3333 | 0.2500 | 0.6000 |
| Platform/MASTG-TEST0033 | 3 | 7 | 3 | 4 | 0 | 0.4286 | 1.0000 | 0.6000 | 0.6000 |
| Platform/MASTG-TEST0035 | 2 | 3 | 0 | 3 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 |
| Platform/MASTG-TEST0037 | 4 | 1 | 0 | 1 | 4 | 0.0000 | 0.0000 | N/A | 0.0000 |

### our_scanner

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0008 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0024 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0028 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0030 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0031 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0032 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0033 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0035 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A |
| Platform/MASTG-TEST0037 | 4 | 0 | 0 | 0 | 4 | N/A | 0.0000 | N/A | N/A |

## Unmatched Details

This section is useful for manually checking false positives and false negatives.

### mobsf

#### Platform/MASTG-TEST0007

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0007/MainActivity.java:78
- `content_provider_usage` severity=`low` confidence=`4` title=api_content_provider evidence=Content Provider com/example/mastg_test0007/MyContentProvider.java:3

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input`: The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification`: The app sends a notification that contains the credit card number and PIN in plaintext.

#### Platform/MASTG-TEST0024

Unmatched expected vulnerabilities:

- `excessive_permissions`: The camera app requests permissions that are not necessary for its core functionality of taking photos and saving them to internal storage.
- `dangerous_permission_requested`: The app requests dangerous permissions such as phone, contacts, and calendar permissions without clear need.

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0024/MainActivity.java:79
- `local_file_io` severity=`low` confidence=`4` title=api_local_file_io evidence=Local File I/O Operations com/example/mastg_test0024/MainActivity.java:16,17,17,18,18,19,84

#### Platform/MASTG-TEST0028

Unmatched findings:

- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0028/MainActivity.java:45,123,203,205
- `local_file_io` severity=`low` confidence=`4` title=api_local_file_io evidence=Local File I/O Operations com/example/mastg_test0028/MainActivity.java:15,16,16,17,17,18,18,19,19,20,20,21,94,200,200,201,202

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent`: The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent`: The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

Unmatched findings:

- `manifest_issue` severity=`medium` confidence=`8` title=App can be installed on a vulnerable Android version 8.0, minSdk=26] evidence=This application can be installed on an older version of android that has multiple vulnerabilities. Support an Android version => 10, API 29 to receive reasonab...

#### Platform/MASTG-TEST0031

Unmatched expected vulnerabilities:

- `webview_javascript_enabled`: The app explicitly enables JavaScript execution in a WebView.
- `user_controlled_webview_content`: The app takes a user search query from an EditText and loads related results into a WebView, making WebView content influenced by user input.

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0031/MainActivity.java:32

#### Platform/MASTG-TEST0032

Unmatched expected vulnerabilities:

- `webview_file_access_enabled`: The WebView may allow file/content access or does not explicitly disable risky protocol handlers.
- `cleartext_traffic_allowed`: The network security configuration permits cleartext traffic for 10.0.2.2.

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...
- `manifest_issue` severity=`low` confidence=`8` title=App has a Network Security Configuration[android:networkSecurityConfig=@xml/network_security_config] evidence=The Network Security Configuration feature lets apps customize their network security settings in a safe, declarative configuration file without modifying app c...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0032/WebViewActivity.java:46
- `local_file_io` severity=`low` confidence=`4` title=api_local_file_io evidence=Local File I/O Operations com/example/mastg_test0032/WebViewActivity.java:45

#### Platform/MASTG-TEST0033

Unmatched findings:

- `manifest_issue` severity=`medium` confidence=`8` title=App can be installed on a vulnerable Android version 8.0, minSdk=26] evidence=This application can be installed on an older version of android that has multiple vulnerabilities. Support an Android version => 10, API 29 to receive reasonab...
- `manifest_issue` severity=`low` confidence=`8` title=App has a Network Security Configuration[android:networkSecurityConfig=@xml/network_security_config] evidence=The Network Security Configuration feature lets apps customize their network security settings in a safe, declarative configuration file without modifying app c...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0033/MainActivity.java:53,55
- `local_file_io` severity=`low` confidence=`4` title=api_local_file_io evidence=Local File I/O Operations com/example/mastg_test0033/MainActivity.java:12,13,13,14,50,50,51,52

#### Platform/MASTG-TEST0035

Unmatched expected vulnerabilities:

- `missing_overlay_touch_filtering`: Sensitive UI elements do not enable touch filtering protections against overlay or tapjacking attacks.
- `missing_obscured_touch_check`: The app does not implement custom touch security checks such as onFilterTouchEventForSecurity or checks for obscured touch flags.

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...
- `logging_sensitive_data` severity=`low` confidence=`7` title=android_logging evidence=The App logs information. Sensitive information should never be logged. com/example/mastg_test0035/MainActivity.java:84,85,175,177
- `local_file_io` severity=`low` confidence=`4` title=api_local_file_io evidence=Local File I/O Operations com/example/mastg_test0035/MainActivity.java:15,16,16,17,17,18,18,19,19,20,70,172,172,173,174

#### Platform/MASTG-TEST0037

Unmatched expected vulnerabilities:

- `webview_storage_not_cleaned`: The app uses WebView storage-related features or may store WebView data without properly deleting WebStorage data.
- `webview_cache_not_cleared`: The app does not fully clear WebView cache, or does not call clearCache with disk-file cleanup.
- `webview_cookies_not_removed`: The app does not remove cookies stored by WebView during cleanup.
- `webview_files_not_deleted`: The app does not manually delete known WebView data directories such as app_webview.

Unmatched findings:

- `manifest_issue` severity=`high` confidence=`8` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security upda...

### our_scanner

#### Platform/MASTG-TEST0007

Unmatched expected vulnerabilities:

- `exported_provider`: The app exposes a ContentProvider that allows other apps to access sensitive stored data through IPC.
- `content_provider_sql_injection`: The ContentProvider query logic is vulnerable to SQL injection through attacker-controlled selection/query input.

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input`: The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification`: The app sends a notification that contains the credit card number and PIN in plaintext.

#### Platform/MASTG-TEST0024

Unmatched expected vulnerabilities:

- `excessive_permissions`: The camera app requests permissions that are not necessary for its core functionality of taking photos and saving them to internal storage.
- `dangerous_permission_requested`: The app requests dangerous permissions such as phone, contacts, and calendar permissions without clear need.

#### Platform/MASTG-TEST0028

Unmatched expected vulnerabilities:

- `insecure_deeplink`: The app exposes deep links through exported intent filters, increasing the attack surface and allowing external intents to reach app functionality.
- `deeplink_auth_bypass`: The app login can be bypassed by generating a crafted intent from the terminal through the deep link entry point.
- `deeplink_webview_input_control`: Externally controlled deep link parameters can modify the content or URL displayed inside a WebView.

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent`: The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent`: The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

#### Platform/MASTG-TEST0031

Unmatched expected vulnerabilities:

- `webview_javascript_enabled`: The app explicitly enables JavaScript execution in a WebView.
- `user_controlled_webview_content`: The app takes a user search query from an EditText and loads related results into a WebView, making WebView content influenced by user input.

#### Platform/MASTG-TEST0032

Unmatched expected vulnerabilities:

- `webview_loads_external_storage_file`: The app loads an HTML file from external storage into a WebView, allowing other apps or users to overwrite the loaded content.
- `webview_file_access_enabled`: The WebView may allow file/content access or does not explicitly disable risky protocol handlers.
- `cleartext_traffic_allowed`: The network security configuration permits cleartext traffic for 10.0.2.2.

#### Platform/MASTG-TEST0033

Unmatched expected vulnerabilities:

- `javascript_interface_exposed`: The app exposes a Java object to JavaScript through addJavascriptInterface.
- `webview_javascript_enabled_with_bridge`: JavaScript is enabled in a WebView that also exposes a JavaScript bridge.
- `exported_activity_with_webview_bridge`: The activity containing the WebView bridge is exported or externally reachable, increasing exploitability.

#### Platform/MASTG-TEST0035

Unmatched expected vulnerabilities:

- `missing_overlay_touch_filtering`: Sensitive UI elements do not enable touch filtering protections against overlay or tapjacking attacks.
- `missing_obscured_touch_check`: The app does not implement custom touch security checks such as onFilterTouchEventForSecurity or checks for obscured touch flags.

#### Platform/MASTG-TEST0037

Unmatched expected vulnerabilities:

- `webview_storage_not_cleaned`: The app uses WebView storage-related features or may store WebView data without properly deleting WebStorage data.
- `webview_cache_not_cleared`: The app does not fully clear WebView cache, or does not call clearCache with disk-file cleanup.
- `webview_cookies_not_removed`: The app does not remove cookies stored by WebView during cleanup.
- `webview_files_not_deleted`: The app does not manually delete known WebView data directories such as app_webview.
