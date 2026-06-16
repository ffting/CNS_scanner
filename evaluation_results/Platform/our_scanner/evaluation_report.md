# Evaluation Report

## Settings

- Must-detect only: `True`
- Ignore third-party findings: `True`
- Scope filter enabled: `True`
- Top-k: `5`
- High confidence threshold: `8`
- High severity threshold: `8`
- High-priority subset: Top-N navigation list (nav = priority_weight + severity×confidence, N=`10`)
- Minimum severity score filter: `None`
- Minimum confidence score filter: `None`

## Overall Summary

| Tool | Cases | Expected | Raw Findings | Scoped Findings | TP | FP | FN | Precision | Recall | F1 | High-Conf Precision | High-Priority Precision | Severity MAE | Confidence MAE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| our_scanner | 10 | 25 | 7 | 6 | 5 | 1 | 20 | 0.8333 | 0.2000 | 0.3226 | 1.0000 | 0.8333 | N/A | N/A |

## Per-case Results

### our_scanner

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 1 | 1 | 0 | 1 | 1.0000 | 0.5000 | 0.6667 | 1.0000 | 1.0000 | 1.0000 |
| Platform/MASTG-TEST0008 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0024 | 2 | 2 | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | N/A | 1.0000 |
| Platform/MASTG-TEST0028 | 3 | 2 | 2 | 0 | 1 | 1.0000 | 0.6667 | 0.8000 | 1.0000 | N/A | 1.0000 |
| Platform/MASTG-TEST0030 | 2 | 1 | 0 | 1 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | N/A | 0.0000 |
| Platform/MASTG-TEST0031 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0032 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0033 | 3 | 0 | 0 | 0 | 3 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0035 | 2 | 0 | 0 | 0 | 2 | N/A | 0.0000 | N/A | N/A | N/A | N/A |
| Platform/MASTG-TEST0037 | 4 | 0 | 0 | 0 | 4 | N/A | 0.0000 | N/A | N/A | N/A | N/A |

## Matched Details

### our_scanner

#### Platform/MASTG-TEST0007

- GT `GT-0007-1` `exported_provider` matched by `VULN_EXPORTED_PROVIDER_LEAK` `exported_provider` score=(9, 10) type=`medium` title=Exported ContentProvider with weak protection

#### Platform/MASTG-TEST0024

- GT `GT-0024-1` `excessive_permissions` matched by `VULN_EXCESSIVE_PERMISSIONS` `excessive_permissions` score=(5, 5) type=`medium` title=Application requests excessive permissions
- GT `GT-0024-2` `dangerous_permission_requested` matched by `VULN_DANGEROUS_PERMISSION_REQUESTED` `dangerous_permission` score=(5, 5) type=`medium` title=Application requests dangerous permissions

#### Platform/MASTG-TEST0028

- GT `GT-0028-1` `insecure_deeplink` matched by `VULN_INSECURE_DEEPLINK` `insecure_deeplink` score=(7, 5) type=`medium` title=Externally reachable deep link handler
- GT `GT-0028-2` `deeplink_auth_bypass` matched by `VULN_INSECURE_DEEPLINK` `insecure_deeplink` score=(7, 5) type=`medium` title=Externally reachable browsable deep link

## Unmatched Details

This section helps inspect false negatives and false positives.

### our_scanner

#### Platform/MASTG-TEST0007

Unmatched expected vulnerabilities:

- `content_provider_sql_injection` id=`GT-0007-2` component=`` location=`` description=The ContentProvider query logic is vulnerable to SQL injection through attacker-controlled selection/query input.

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input` id=`GT-0008-1` component=`` location=`` description=The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification` id=`GT-0008-2` component=`` location=`` description=The app sends a notification that contains the credit card number and PIN in plaintext.

#### Platform/MASTG-TEST0028

Unmatched expected vulnerabilities:

- `deeplink_webview_input_control` id=`GT-0028-3` component=`` location=`` description=Externally controlled deep link parameters can modify the content or URL displayed inside a WebView.

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent` id=`GT-0030-1` component=`` location=`` description=The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent` id=`GT-0030-2` component=`` location=`` description=The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

Unmatched findings:

- `dangerous_permission` id=`VULN_DANGEROUS_PERMISSION_REQUESTED` severity=`Medium` sev_score=`5` conf_score=`5` title=Application requests dangerous permissions evidence=uses-permission androidmanifest.xml dangerous permission android.permission android.permission.call_phone

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
