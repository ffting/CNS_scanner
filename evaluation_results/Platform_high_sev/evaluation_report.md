# Evaluation Report

## Settings

- Must-detect only: `True`
- Ignore third-party findings: `True`
- Scope filter enabled: `True`
- Top-k: `5`
- High confidence threshold: `8`
- High severity threshold: `8`
- Minimum severity score filter: `8`
- Minimum confidence score filter: `None`

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 | High-Conf Precision | High-Priority Precision | Severity MAE | Confidence MAE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mobsf | 10 | 25 | 85 | 0 | 0 | 0 | 25 | N/A | 0.0000 | N/A | N/A | N/A | N/A | N/A |
| our_scanner | 10 | 25 | 0 | 0 | 0 | 0 | 25 | N/A | 0.0000 | N/A | N/A | N/A | N/A | N/A |

## Per-case Results

### mobsf

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0008 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0024 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0028 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0030 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0031 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0032 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0033 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0035 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0037 | 4 | 0 | 0 | 0 | 4 | N/A | 0.0000 | N/A | N/A | N/A | N/A |

### our_scanner

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0008 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0024 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0028 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0030 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0031 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0032 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0033 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0035 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0037 | 4 | 0 | 0 | 0 | 4 | N/A | 0.0000 | N/A | N/A | N/A | N/A |

## Matched Details

### mobsf

### our_scanner

## Unmatched Details

This section helps inspect false negatives and false positives.

### mobsf

#### Platform/MASTG-TEST0007

Unmatched expected vulnerabilities:

- `exported_provider` id=`GT-0007-1` component=`` location=`` description=The app exposes a ContentProvider that allows other apps to access sensitive stored data through IPC.
- `content_provider_sql_injection` id=`GT-0007-2` component=`` location=`` description=The ContentProvider query logic is vulnerable to SQL injection through attacker-controlled selection/query input.

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input` id=`GT-0008-1` component=`` location=`` description=The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification` id=`GT-0008-2` component=`` location=`` description=The app sends a notification that contains the credit card number and PIN in plaintext.

#### Platform/MASTG-TEST0024

Unmatched expected vulnerabilities:

- `excessive_permissions` id=`GT-0024-1` component=`` location=`` description=The camera app requests permissions that are not necessary for its core functionality of taking photos and saving them to internal storage.
- `dangerous_permission_requested` id=`GT-0024-2` component=`` location=`` description=The app requests dangerous permissions such as phone, contacts, and calendar permissions without clear need.

#### Platform/MASTG-TEST0028

Unmatched expected vulnerabilities:

- `insecure_deeplink` id=`GT-0028-1` component=`` location=`` description=The app exposes deep links through exported intent filters, increasing the attack surface and allowing external intents to reach app functionality.
- `deeplink_auth_bypass` id=`GT-0028-2` component=`` location=`` description=The app login can be bypassed by generating a crafted intent from the terminal through the deep link entry point.
- `deeplink_webview_input_control` id=`GT-0028-3` component=`` location=`` description=Externally controlled deep link parameters can modify the content or URL displayed inside a WebView.

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent` id=`GT-0030-1` component=`` location=`` description=The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent` id=`GT-0030-2` component=`` location=`` description=The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

#### Platform/MASTG-TEST0031

Unmatched expected vulnerabilities:

- `webview_javascript_enabled` id=`GT-0031-1` component=`` location=`` description=The app explicitly enables JavaScript execution in a WebView.
- `user_controlled_webview_content` id=`GT-0031-2` component=`` location=`` description=The app takes a user search query from an EditText and loads related results into a WebView, making WebView content influenced by user input.

#### Platform/MASTG-TEST0032

Unmatched expected vulnerabilities:

- `webview_loads_external_storage_file` id=`GT-0032-1` component=`` location=`` description=The app loads an HTML file from external storage into a WebView, allowing other apps or users to overwrite the loaded content.
- `webview_file_access_enabled` id=`GT-0032-2` component=`` location=`` description=The WebView may allow file/content access or does not explicitly disable risky protocol handlers.
- `cleartext_traffic_allowed` id=`GT-0032-3` component=`` location=`` description=The network security configuration permits cleartext traffic for 10.0.2.2.

#### Platform/MASTG-TEST0033

Unmatched expected vulnerabilities:

- `javascript_interface_exposed` id=`GT-0033-1` component=`` location=`` description=The app exposes a Java object to JavaScript through addJavascriptInterface.
- `webview_javascript_enabled_with_bridge` id=`GT-0033-2` component=`` location=`` description=JavaScript is enabled in a WebView that also exposes a JavaScript bridge.
- `exported_activity_with_webview_bridge` id=`GT-0033-3` component=`` location=`` description=The activity containing the WebView bridge is exported or externally reachable, increasing exploitability.

#### Platform/MASTG-TEST0035

Unmatched expected vulnerabilities:

- `missing_overlay_touch_filtering` id=`GT-0035-1` component=`` location=`` description=Sensitive UI elements do not enable touch filtering protections against overlay or tapjacking attacks.
- `missing_obscured_touch_check` id=`GT-0035-2` component=`` location=`` description=The app does not implement custom touch security checks such as onFilterTouchEventForSecurity or checks for obscured touch flags.

#### Platform/MASTG-TEST0037

Unmatched expected vulnerabilities:

- `webview_storage_not_cleaned` id=`GT-0037-1` component=`` location=`` description=The app uses WebView storage-related features or may store WebView data without properly deleting WebStorage data.
- `webview_cache_not_cleared` id=`GT-0037-2` component=`` location=`` description=The app does not fully clear WebView cache, or does not call clearCache with disk-file cleanup.
- `webview_cookies_not_removed` id=`GT-0037-3` component=`` location=`` description=The app does not remove cookies stored by WebView during cleanup.
- `webview_files_not_deleted` id=`GT-0037-4` component=`` location=`` description=The app does not manually delete known WebView data directories such as app_webview.

### our_scanner

#### Platform/MASTG-TEST0007

Unmatched expected vulnerabilities:

- `exported_provider` id=`GT-0007-1` component=`` location=`` description=The app exposes a ContentProvider that allows other apps to access sensitive stored data through IPC.
- `content_provider_sql_injection` id=`GT-0007-2` component=`` location=`` description=The ContentProvider query logic is vulnerable to SQL injection through attacker-controlled selection/query input.

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input` id=`GT-0008-1` component=`` location=`` description=The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification` id=`GT-0008-2` component=`` location=`` description=The app sends a notification that contains the credit card number and PIN in plaintext.

#### Platform/MASTG-TEST0024

Unmatched expected vulnerabilities:

- `excessive_permissions` id=`GT-0024-1` component=`` location=`` description=The camera app requests permissions that are not necessary for its core functionality of taking photos and saving them to internal storage.
- `dangerous_permission_requested` id=`GT-0024-2` component=`` location=`` description=The app requests dangerous permissions such as phone, contacts, and calendar permissions without clear need.

#### Platform/MASTG-TEST0028

Unmatched expected vulnerabilities:

- `insecure_deeplink` id=`GT-0028-1` component=`` location=`` description=The app exposes deep links through exported intent filters, increasing the attack surface and allowing external intents to reach app functionality.
- `deeplink_auth_bypass` id=`GT-0028-2` component=`` location=`` description=The app login can be bypassed by generating a crafted intent from the terminal through the deep link entry point.
- `deeplink_webview_input_control` id=`GT-0028-3` component=`` location=`` description=Externally controlled deep link parameters can modify the content or URL displayed inside a WebView.

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent` id=`GT-0030-1` component=`` location=`` description=The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent` id=`GT-0030-2` component=`` location=`` description=The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

#### Platform/MASTG-TEST0031

Unmatched expected vulnerabilities:

- `webview_javascript_enabled` id=`GT-0031-1` component=`` location=`` description=The app explicitly enables JavaScript execution in a WebView.
- `user_controlled_webview_content` id=`GT-0031-2` component=`` location=`` description=The app takes a user search query from an EditText and loads related results into a WebView, making WebView content influenced by user input.

#### Platform/MASTG-TEST0032

Unmatched expected vulnerabilities:

- `webview_loads_external_storage_file` id=`GT-0032-1` component=`` location=`` description=The app loads an HTML file from external storage into a WebView, allowing other apps or users to overwrite the loaded content.
- `webview_file_access_enabled` id=`GT-0032-2` component=`` location=`` description=The WebView may allow file/content access or does not explicitly disable risky protocol handlers.
- `cleartext_traffic_allowed` id=`GT-0032-3` component=`` location=`` description=The network security configuration permits cleartext traffic for 10.0.2.2.

#### Platform/MASTG-TEST0033

Unmatched expected vulnerabilities:

- `javascript_interface_exposed` id=`GT-0033-1` component=`` location=`` description=The app exposes a Java object to JavaScript through addJavascriptInterface.
- `webview_javascript_enabled_with_bridge` id=`GT-0033-2` component=`` location=`` description=JavaScript is enabled in a WebView that also exposes a JavaScript bridge.
- `exported_activity_with_webview_bridge` id=`GT-0033-3` component=`` location=`` description=The activity containing the WebView bridge is exported or externally reachable, increasing exploitability.

#### Platform/MASTG-TEST0035

Unmatched expected vulnerabilities:

- `missing_overlay_touch_filtering` id=`GT-0035-1` component=`` location=`` description=Sensitive UI elements do not enable touch filtering protections against overlay or tapjacking attacks.
- `missing_obscured_touch_check` id=`GT-0035-2` component=`` location=`` description=The app does not implement custom touch security checks such as onFilterTouchEventForSecurity or checks for obscured touch flags.

#### Platform/MASTG-TEST0037

Unmatched expected vulnerabilities:

- `webview_storage_not_cleaned` id=`GT-0037-1` component=`` location=`` description=The app uses WebView storage-related features or may store WebView data without properly deleting WebStorage data.
- `webview_cache_not_cleared` id=`GT-0037-2` component=`` location=`` description=The app does not fully clear WebView cache, or does not call clearCache with disk-file cleanup.
- `webview_cookies_not_removed` id=`GT-0037-3` component=`` location=`` description=The app does not remove cookies stored by WebView during cleanup.
- `webview_files_not_deleted` id=`GT-0037-4` component=`` location=`` description=The app does not manually delete known WebView data directories such as app_webview.
