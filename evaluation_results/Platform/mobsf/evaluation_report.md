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
| mobsf | 10 | 25 | 85 | 73 | 3 | 70 | 22 | 0.0411 | 0.1200 | 0.0612 | 0.0625 | 0.0429 | N/A | N/A |

## Per-case Results

### mobsf

| Case | Expected | Findings | TP | FP | FN | Precision | Recall | F1 | Top-5 Precision | High-Conf Precision | High-Priority Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Platform/MASTG-TEST0007 | 2 | 7 | 2 | 5 | 0 | 0.2857 | 1.0000 | 0.4444 | 0.4000 | 0.2500 | 0.2857 |
| Platform/MASTG-TEST0008 | 2 | 4 | 0 | 4 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0024 | 2 | 6 | 0 | 6 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0028 | 3 | 9 | 0 | 9 | 3 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0030 | 2 | 7 | 0 | 7 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0031 | 2 | 4 | 0 | 4 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0032 | 3 | 10 | 0 | 10 | 3 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0033 | 3 | 13 | 1 | 12 | 2 | 0.0769 | 0.3333 | 0.1250 | 0.2000 | 0.2500 | 0.1000 |
| Platform/MASTG-TEST0035 | 2 | 8 | 0 | 8 | 2 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |
| Platform/MASTG-TEST0037 | 4 | 5 | 0 | 5 | 4 | 0.0000 | 0.0000 | N/A | 0.0000 | 0.0000 | 0.0000 |

## Matched Details

### mobsf

#### Platform/MASTG-TEST0007

- GT `GT-0007-1` `exported_provider` matched by `MOBSF_MANIFEST_EXPLICITLY_EXPORTED` `exported_provider` score=(5, 8) type=`medium` title=Content Provider (com.example.mastg_test0007.MyContentProvider) is not Protected. [android:exported=true]
- GT `GT-0007-2` `content_provider_sql_injection` matched by `MOBSF_CODE_ANDROID_SQL_RAW_QUERY` `sql_injection` score=(5, 7) type=`medium` title=App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.

#### Platform/MASTG-TEST0033

- GT `GT-0033-3` `exported_activity_with_webview_bridge` matched by `MOBSF_MANIFEST_EXPLICITLY_EXPORTED` `exported_activity` score=(5, 8) type=`medium` title=Activity (com.example.mastg_test0033.SupportedWebView) is not Protected. [android:exported=true]

## Unmatched Details

This section helps inspect false negatives and false positives.

### mobsf

#### Platform/MASTG-TEST0007

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_CONTENT_PROVIDER` severity=`Low` sev_score=`2` conf_score=`6` title=Content Provider evidence=rule=api_content_provider description=content provider com/example/mastg_test0007/mycontentprovider.java:3

#### Platform/MASTG-TEST0008

Unmatched expected vulnerabilities:

- `unmasked_sensitive_input` id=`GT-0008-1` component=`` location=`` description=The app asks for sensitive values such as credit card number and PIN, but the input fields are not obscured during entry.
- `sensitive_data_in_notification` id=`GT-0008-2` component=`` location=`` description=The app sends a notification that contains the credit card number and PIN in plaintext.

Unmatched findings:

- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `android_api` id=`MOBSF_ANDROID_API_API_GET_SYSTEM_SERVICE` severity=`Low` sev_score=`2` conf_score=`6` title=Get System Service evidence=rule=api_get_system_service description=get system service com/example/mastg_test0008/mainactivity.java:26
- `android_api` id=`MOBSF_ANDROID_API_API_NOTIFICATIONS` severity=`Low` sev_score=`2` conf_score=`6` title=Android Notifications evidence=rule=api_notifications description=android notifications com/example/mastg_test0008/mainactivity.java:4,14,35

#### Platform/MASTG-TEST0024

Unmatched expected vulnerabilities:

- `excessive_permissions` id=`GT-0024-1` component=`` location=`` description=The camera app requests permissions that are not necessary for its core functionality of taking photos and saving them to internal storage.
- `dangerous_permission_requested` id=`GT-0024-2` component=`` location=`` description=The app requests dangerous permissions such as phone, contacts, and calendar permissions without clear need.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_MISSING_CODE_SIGNING_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Missing Code Signing certificate evidence=title=missing code signing certificate description=code signing certificate not found
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0024/mainactivity.java:4,37,56,58,65
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0024/mainactivity.java:16,17,17,18,18,19,84
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0024/mainactivity.java:58

#### Platform/MASTG-TEST0028

Unmatched expected vulnerabilities:

- `insecure_deeplink` id=`GT-0028-1` component=`` location=`` description=The app exposes deep links through exported intent filters, increasing the attack surface and allowing external intents to reach app functionality.
- `deeplink_auth_bypass` id=`GT-0028-2` component=`` location=`` description=The app login can be bypassed by generating a crafted intent from the terminal through the deep link entry point.
- `deeplink_webview_input_control` id=`GT-0028-3` component=`` location=`` description=Externally controlled deep link parameters can modify the content or URL displayed inside a WebView.

Unmatched findings:

- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION2` severity=`Medium` sev_score=`5` conf_score=`9` title=App can be installed on a vulnerable Android version 8.0, minSdk=26] evidence=rule=vulnerable_os_version2 title=app can be installed on a vulnerable android version 8.0, minsdk=26] component=["8.0", "26"] description=this application can be installed on an o...
- `exported_activity` id=`MOBSF_MANIFEST_EXPLICITLY_EXPORTED` severity=`Medium` sev_score=`5` conf_score=`8` title=Activity (com.example.mastg_test0028.WebViewActivity) is not Protected. [android:exported=true] evidence=rule=explicitly_exported title=activity (com.example.mastg_test0028.webviewactivity) is not protected. [android:exported=true] component=["activity", "com.example.mastg_test0028.we...
- `webview` id=`MOBSF_CODE_ANDROID_WEBVIEW_ALLOW_FILE_FROM_URL` severity=`Medium` sev_score=`5` conf_score=`7` title=Ensure that user controlled URLs never reaches the Webview. Enabling file access from URLs in WebView can leak sensitive information from th... evidence=rule=android_webview_allow_file_from_url description=ensure that user controlled urls never reaches the webview. enabling file access from urls in webview can leak sensitive inform...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0028/mainactivity.java:3,47 com/example/mastg_test0028/webviewactivity.java:32
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0028/mainactivity.java:15,16,16,17,17,18,18,19,19,20,20,21,94,200,200,201,202
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0028/mainactivity.java:47

#### Platform/MASTG-TEST0030

Unmatched expected vulnerabilities:

- `mutable_pending_intent` id=`GT-0030-1` component=`` location=`` description=The app creates a PendingIntent using the MUTABLE flag, allowing the intent to be modified after creation.
- `implicit_pending_intent` id=`GT-0030-2` component=`` location=`` description=The base intent used by the PendingIntent is implicit or not restricted to an exact package, action, and component.

Unmatched findings:

- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION2` severity=`Medium` sev_score=`5` conf_score=`9` title=App can be installed on a vulnerable Android version 8.0, minSdk=26] evidence=rule=vulnerable_os_version2 title=app can be installed on a vulnerable android version 8.0, minsdk=26] component=["8.0", "26"] description=this application can be installed on an o...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `android_api` id=`MOBSF_ANDROID_API_API_GET_SYSTEM_SERVICE` severity=`Low` sev_score=`2` conf_score=`6` title=Get System Service evidence=rule=api_get_system_service description=get system service com/example/mastg_test0030/mainactivity.java:46
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0030/mainactivity.java:5,6,38,38,38,39,39,47
- `android_api` id=`MOBSF_ANDROID_API_API_NOTIFICATIONS` severity=`Low` sev_score=`2` conf_score=`6` title=Android Notifications evidence=rule=api_notifications description=android notifications com/example/mastg_test0030/mainactivity.java:4,15,53
- `android_api` id=`MOBSF_ANDROID_API_API_SEND_BROADCAST` severity=`Low` sev_score=`2` conf_score=`6` title=Sending Broadcast evidence=rule=api_send_broadcast description=sending broadcast com/example/mastg_test0030/mainactivity.java:52

#### Platform/MASTG-TEST0031

Unmatched expected vulnerabilities:

- `webview_javascript_enabled` id=`GT-0031-1` component=`` location=`` description=The app explicitly enables JavaScript execution in a WebView.
- `user_controlled_webview_content` id=`GT-0031-2` component=`` location=`` description=The app takes a user search query from an EditText and loads related results into a WebView, making WebView content influenced by user input.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...

#### Platform/MASTG-TEST0032

Unmatched expected vulnerabilities:

- `webview_loads_external_storage_file` id=`GT-0032-1` component=`` location=`` description=The app loads an HTML file from external storage into a WebView, allowing other apps or users to overwrite the loaded content.
- `webview_file_access_enabled` id=`GT-0032-2` component=`` location=`` description=The WebView may allow file/content access or does not explicitly disable risky protocol handlers.
- `cleartext_traffic_allowed` id=`GT-0032-3` component=`` location=`` description=The network security configuration permits cleartext traffic for 10.0.2.2.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `storage` id=`MOBSF_CODE_ANDROID_READ_WRITE_EXTERNAL` severity=`Medium` sev_score=`5` conf_score=`7` title=App can read/write to External Storage. Any App can read data written to External Storage. evidence=rule=android_read_write_external description=app can read/write to external storage. any app can read data written to external storage. cwe=cwe-276: incorrect default permissions m...
- `webview` id=`MOBSF_CODE_ANDROID_WEBVIEW_ALLOW_FILE_FROM_URL` severity=`Medium` sev_score=`5` conf_score=`7` title=Ensure that user controlled URLs never reaches the Webview. Enabling file access from URLs in WebView can leak sensitive information from th... evidence=rule=android_webview_allow_file_from_url description=ensure that user controlled urls never reaches the webview. enabling file access from urls in webview can leak sensitive inform...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `manifest` id=`MOBSF_MANIFEST_HAS_NETWORK_SECURITY` severity=`Low` sev_score=`2` conf_score=`7` title=App has a Network Security Configuration[android:networkSecurityConfig=@xml/network_security_config] evidence=rule=has_network_security title=app has a network security configuration[android:networksecurityconfig=@xml/network_security_config] component=["@xml/network_security_config"] desc...
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0032/mainactivity.java:3,44
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0032/webviewactivity.java:45
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0032/mainactivity.java:44

#### Platform/MASTG-TEST0033

Unmatched expected vulnerabilities:

- `javascript_interface_exposed` id=`GT-0033-1` component=`` location=`` description=The app exposes a Java object to JavaScript through addJavascriptInterface.
- `webview_javascript_enabled_with_bridge` id=`GT-0033-2` component=`` location=`` description=JavaScript is enabled in a WebView that also exposes a JavaScript bridge.

Unmatched findings:

- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION2` severity=`Medium` sev_score=`5` conf_score=`9` title=App can be installed on a vulnerable Android version 8.0, minSdk=26] evidence=rule=vulnerable_os_version2 title=app can be installed on a vulnerable android version 8.0, minsdk=26] component=["8.0", "26"] description=this application can be installed on an o...
- `webview` id=`MOBSF_CODE_ANDROID_WEBVIEW` severity=`Medium` sev_score=`5` conf_score=`7` title=Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole. evidence=rule=android_webview description=insecure webview implementation. execution of user controlled code in webview is a critical security hole. cwe=cwe-749: exposed dangerous method or...
- `hardcoded_secret` id=`MOBSF_CODE_ANDROID_HARDCODED` severity=`Medium` sev_score=`5` conf_score=`5` title=Files may contain hardcoded sensitive information like usernames, passwords, keys etc. evidence=rule=android_hardcoded description=files may contain hardcoded sensitive information like usernames, passwords, keys etc. cwe=cwe-312: cleartext storage of sensitive information ma...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `manifest` id=`MOBSF_MANIFEST_HAS_NETWORK_SECURITY` severity=`Low` sev_score=`2` conf_score=`7` title=App has a Network Security Configuration[android:networkSecurityConfig=@xml/network_security_config] evidence=rule=has_network_security title=app has a network security configuration[android:networksecurityconfig=@xml/network_security_config] component=["@xml/network_security_config"] desc...
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0033/mainactivity.java:3,34,34 com/example/mastg_test0033/supportedwebview.java:38
- `android_api` id=`MOBSF_ANDROID_API_API_JAVASCRIPT_INTERFACE_METHODS` severity=`Low` sev_score=`2` conf_score=`6` title=JavaScript Interface Methods evidence=rule=api_javascript_interface_methods description=javascript interface methods com/example/mastg_test0033/myjavascriptinterface.java:16,21
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0033/mainactivity.java:12,13,13,14,50,50,51,52
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0033/mainactivity.java:36
- `android_api` id=`MOBSF_ANDROID_API_API_WEBVIEW` severity=`Low` sev_score=`2` conf_score=`6` title=WebView JavaScript Interface evidence=rule=api_webview description=webview javascript interface com/example/mastg_test0033/supportedwebview.java:6,7,17,27,32,32,33,33,37,5,6,7

#### Platform/MASTG-TEST0035

Unmatched expected vulnerabilities:

- `missing_overlay_touch_filtering` id=`GT-0035-1` component=`` location=`` description=Sensitive UI elements do not enable touch filtering protections against overlay or tapjacking attacks.
- `missing_obscured_touch_check` id=`GT-0035-2` component=`` location=`` description=The app does not implement custom touch security checks such as onFilterTouchEventForSecurity or checks for obscured touch flags.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 5.0-5.0.2, [minSdk=21] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 5.0-5.0.2, [minsdk=21] component=["5.0-5.0.2", "21"] description=this application ca...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_VULNERABLE_TO_JANUS_VULNERABILITY` severity=`Medium` sev_score=`5` conf_score=`8` title=Application vulnerable to Janus Vulnerability evidence=title=application vulnerable to janus vulnerability description=application is signed with v1 signature scheme, making it vulnerable to janus vulnerability on android 5.0-8.0, if s...
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `logging` id=`MOBSF_CODE_ANDROID_LOGGING` severity=`Low` sev_score=`2` conf_score=`7` title=The App logs information. Sensitive information should never be logged. evidence=rule=android_logging description=the app logs information. sensitive information should never be logged. cwe=cwe-532: insertion of sensitive information into log file masvs=mstg-st...
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0035/mainactivity.java:3,44
- `android_api` id=`MOBSF_ANDROID_API_API_LOCAL_FILE_IO` severity=`Low` sev_score=`2` conf_score=`6` title=Local File I/O Operations evidence=rule=api_local_file_io description=local file i/o operations com/example/mastg_test0035/mainactivity.java:15,16,16,17,17,18,18,19,19,20,70,172,172,173,174
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0035/mainactivity.java:44

#### Platform/MASTG-TEST0037

Unmatched expected vulnerabilities:

- `webview_storage_not_cleaned` id=`GT-0037-1` component=`` location=`` description=The app uses WebView storage-related features or may store WebView data without properly deleting WebStorage data.
- `webview_cache_not_cleared` id=`GT-0037-2` component=`` location=`` description=The app does not fully clear WebView cache, or does not call clearCache with disk-file cleanup.
- `webview_cookies_not_removed` id=`GT-0037-3` component=`` location=`` description=The app does not remove cookies stored by WebView during cleanup.
- `webview_files_not_deleted` id=`GT-0037-4` component=`` location=`` description=The app does not manually delete known WebView data directories such as app_webview.

Unmatched findings:

- `platform_version` id=`MOBSF_MANIFEST_VULNERABLE_OS_VERSION` severity=`High` sev_score=`7` conf_score=`9` title=App can be installed on a vulnerable unpatched Android version 7.0, [minSdk=24] evidence=rule=vulnerable_os_version title=app can be installed on a vulnerable unpatched android version 7.0, [minsdk=24] component=["7.0", "24"] description=this application can be install...
- `certificate` id=`MOBSF_CERTIFICATE_APPLICATION_SIGNED_WITH_DEBUG_CERTIFICATE` severity=`High` sev_score=`7` conf_score=`8` title=Application signed with debug certificate evidence=title=application signed with debug certificate description=application signed with a debug certificate. production application must not be shipped with a debug certificate.
- `certificate` id=`MOBSF_CERTIFICATE_SIGNED_APPLICATION` severity=`Low` sev_score=`2` conf_score=`8` title=Signed Application evidence=title=signed application description=application is signed with a code signing certificate
- `android_api` id=`MOBSF_ANDROID_API_API_IPC` severity=`Low` sev_score=`2` conf_score=`6` title=Inter Process Communication evidence=rule=api_ipc description=inter process communication com/example/mastg_test0037/mainactivity.java:3,31
- `android_api` id=`MOBSF_ANDROID_API_API_START_ACTIVITY` severity=`Low` sev_score=`2` conf_score=`6` title=Starting Activity evidence=rule=api_start_activity description=starting activity com/example/mastg_test0037/mainactivity.java:31
