# CNS APK Scanner 交接文件

本文件用於交接給隊友或下一個 GPT 聊天室，說明目前 CNS APK Scanner 專案已完成內容、目前評估結果、Network 類別進度，以及 Platform 類別後續待辦。

---

## 1. 專案目標

本專案是一個 Android APK 靜態安全掃描器，主要用於 CNS Final Project。

目標是分析 APK 中的：

- `AndroidManifest.xml`
- XML resources / Network Security Configuration
- DEX strings / code-level pattern
- exported components / ContentProvider / deep links
- Network / TLS / certificate validation pattern
- API key / token leakage

並將結果 normalize 後，與手動整理的 `ground_truth.json` 比對，計算：

- TP
- FP
- FN
- precision
- recall
- F1
- high-confidence precision
- high-priority precision

目前已有 MobSF baseline，並且可以比較 `mobsf` 與 `our_scanner`。

---

## 2. 主要檔案與職責

### `our_scanner.py`

CLI 入口，負責呼叫 scanner pipeline。

### `scanner.py`

核心掃描流程。

目前 pipeline 順序：

```python
_scan_api_keys(apk_path, result)
apply_risk_analysis(result)
attach_poc_commands(result)
detect_vulnerabilities(result)
scan_network_code_patterns(apk_path, result)
apply_scoring(result)
```

重點：

- `detect_vulnerabilities(result)`：處理 manifest / XML-level 規則。
- `scan_network_code_patterns(apk_path, result)`：補 DEX code/string-level Network/TLS 規則。
- `apply_scoring(result)`：最後統一補 severity_score / confidence_score。

### `manifest_parser.py`

解析 APK metadata 與 Manifest component。

目前支援：

- package name
- minSdk / targetSdk
- debuggable
- allowBackup
- usesCleartextTraffic
- exported / implicit exported components
- provider authorities
- intent-filter / deep link data
- custom permissions

目前沒有抓 `android:networkSecurityConfig` 的 resource path，所以 Network Security Config 目前是在 `vulnerability_patterns.py` 中用 fallback 掃 `res/*.xml`。

### `vulnerability_patterns.py`

負責：

- manifest-level vulnerabilities
- XML-level Network rules
- app-level config risks
- attack-chain composition

目前 Network manifest/XML-level rules 包含：

- `uses_cleartext_traffic`
- `low_min_sdk_network_security_bypass`
- `low_target_sdk_network_security`
- `certificate_pinning_configuration`
- `user_ca_trust_enabled`

這份檔案最近新增了 `user_ca_trust_enabled` 相關邏輯。

### `network_code_scanner.py`

負責 DEX-level Network/TLS pattern。

目前 enabled rules：

- `obsolete_tls_version`
- `certificate_validation_bypass`

目前 prepared 但預設關閉：

- `webview_ssl_error_bypass`
- `hostname_verification_bypass`
- `cleartext_http`

目前 `ENABLE_EXPERIMENTAL_0021_RULES = False`，不建議直接打開，因為 string-level matching 容易 FP。

### `scoring.py`

為 findings 和 attack chains 補：

- `severity_score`
- `confidence_score`
- test priority
- navigation sort
- summary counts

目前已支援 Network 相關 pattern：

- `VULN_OBSOLETE_TLS_VERSION`
- `VULN_CERTIFICATE_VALIDATION_BYPASS`
- `VULN_INSECURE_TRUST_MANAGER`
- `VULN_WEBVIEW_SSL_ERROR_BYPASS`
- `VULN_HOSTNAME_VERIFICATION_BYPASS`
- `VULN_USER_CA_TRUST_ENABLED`
- `VULN_CLEARTEXT_HTTP`

### `evaluation.py`

負責將 normalized reports 與 `ground_truth.json` 比對。

目前 matching 邏輯：

- strong match：category + component/location/authority/deeplink
- medium match：category + evidence keyword
- weak match：keyword only，但只有 GT 沒 category 時才用

最近更新：

- `DEFAULT_SCOPE_CATEGORIES` 已新增：
  - `user_ca_trust_enabled`
  - `trust_user_ca`
  - `custom_trust_anchors`
- 輸出層已改成保留原有 category-level 檔案，並額外輸出 per-tool 子資料夾與 comparison report。

---

## 3. 目前輸出結構

重跑 evaluation 後，輸出會長這樣：

```text
evaluation_results/
  Platform/
    summary.json
    summary_results.csv
    case_results.json
    case_results.csv
    evaluation_report.md
    comparison_report.md
    mobsf/
      summary.json
      summary_results.csv
      case_results.json
      case_results.csv
      evaluation_report.md
    our_scanner/
      summary.json
      summary_results.csv
      case_results.json
      case_results.csv
      evaluation_report.md

  Network/
    summary.json
    summary_results.csv
    case_results.json
    case_results.csv
    evaluation_report.md
    comparison_report.md
    mobsf/
      summary.json
      summary_results.csv
      case_results.json
      case_results.csv
      evaluation_report.md
    our_scanner/
      summary.json
      summary_results.csv
      case_results.json
      case_results.csv
      evaluation_report.md
```

原本的檔案沒有刪掉，舊流程仍可用：

```bash
cat evaluation_results/Network/summary.json | jq '.our_scanner'
```

新增的 per-tool folder 是為了方便單獨看 MobSF 或 our_scanner 結果。

---

## 4. 常用指令

### 掃描 Network benchmark

```bash
./run_scanner.sh Network
```

### 評估 Network，包含 MobSF 與 our_scanner

```bash
python evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool mobsf=./reports/normalized/mobsf \
  --tool our_scanner=./reports/normalized/our_scanner \
  --output-dir ./evaluation_results \
  --category Network
```

### 評估 Platform，包含 MobSF 與 our_scanner

```bash
python evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool mobsf=./reports/normalized/mobsf \
  --tool our_scanner=./reports/normalized/our_scanner \
  --output-dir ./evaluation_results \
  --category Platform
```

### 查看 Network summary

```bash
cat evaluation_results/Network/summary.json | jq '.our_scanner'
```

### 查看 Platform summary

```bash
cat evaluation_results/Platform/summary.json | jq '.our_scanner'
```

### 查看特定 case

```bash
cat evaluation_results/Network/case_results.json | jq '.our_scanner[] | select(.case_id=="Network/MASTG-TEST0021") | {
  case_id,
  tp,
  fp,
  fn,
  matches,
  unmatched_expected,
  unmatched_findings
}'
```

### 語法檢查

```bash
python -m py_compile vulnerability_patterns.py evaluation.py network_code_scanner.py
```

---

## 5. 目前 Network 進度

Network category 共有 5 cases：

```text
Network/MASTG-TEST0019
Network/MASTG-TEST0020
Network/MASTG-TEST0021
Network/MASTG-TEST0022
Network/MASTG-TEST0023
```

目前 our_scanner 最新結果：

```json
{
  "cases": 5,
  "expected": 16,
  "raw_findings": 9,
  "scoped_findings": 8,
  "tp": 7,
  "fp": 1,
  "fn": 9,
  "precision": 0.875,
  "recall": 0.4375,
  "f1": 0.5833333333333334,
  "high_confidence_findings": 8,
  "high_confidence_precision": 0.875,
  "high_priority_findings": 8,
  "high_priority_precision": 0.875
}
```

MobSF 在 Network 類別目前結果：

```json
{
  "cases": 5,
  "expected": 16,
  "raw_findings": 42,
  "scoped_findings": 37,
  "tp": 0,
  "fp": 37,
  "fn": 16,
  "precision": 0.0,
  "recall": 0.0,
  "f1": null
}
```

可用於報告的說法：

> In the Network category, our scanner significantly outperformed MobSF. MobSF produced 37 scoped findings but none matched the ground truth, resulting in zero precision and zero recall. Our scanner produced 8 scoped findings, 7 of which matched the ground truth, achieving 0.875 precision, 0.4375 recall, and an F1 score of 0.5833. This indicates that our Network-specific rules are more aligned with the MASTG benchmark requirements.

---

## 6. Network 已完成規則

### 6.1 `uses_cleartext_traffic`

來源：`vulnerability_patterns.py`

偵測：

```text
android:usesCleartextTraffic="true"
```

finding：

```text
pattern_id = VULN_USES_CLEARTEXT_TRAFFIC
category = uses_cleartext_traffic
```

目前命中：

```text
Network/MASTG-TEST0019
```

### 6.2 `low_min_sdk_network_security_bypass`

來源：`vulnerability_patterns.py`

條件：

```text
minSdk <= 19
```

finding：

```text
pattern_id = VULN_LOW_MIN_SDK_NETWORK_SECURITY_BYPASS
category = low_min_sdk_network_security_bypass
```

目前命中：

```text
Network/MASTG-TEST0019
```

### 6.3 `low_target_sdk_network_security`

來源：`vulnerability_patterns.py`

條件：

```text
targetSdk < 24
```

finding：

```text
pattern_id = VULN_LOW_TARGET_SDK_NETWORK_SECURITY
category = low_target_sdk_network_security
```

目前命中：

```text
Network/MASTG-TEST0021
```

### 6.4 `user_ca_trust_enabled`

來源：`vulnerability_patterns.py`

目前有兩種偵測邏輯。

#### A. XML-level explicit rule

偵測 Network Security Config 裡明確信任 user CAs：

```xml
<trust-anchors>
  <certificates src="user" />
</trust-anchors>
```

finding：

```text
pattern_id = VULN_USER_CA_TRUST_ENABLED
category = user_ca_trust_enabled
```

#### B. Legacy targetSdk inferred rule

針對 `Network/MASTG-TEST0021`：

條件：

```text
targetSdk < 24
且沒有 explicit Network Security Config XML
```

原因：

```text
Android apps targeting below API 24 do not benefit from newer default Network Security Configuration behavior that avoids trusting user-installed CAs by default.
```

目前命中：

```text
Network/MASTG-TEST0021
```

注意：這條不是從 XML 明文看到 `src="user"`，而是從 legacy targetSdk default behavior 推論。

### 6.5 `certificate_pinning_configuration`

來源：`vulnerability_patterns.py`

偵測 Network Security Config 中 pinning evidence：

```text
network-security-config
pin-set
pin
digest / SHA-256
```

finding：

```text
pattern_id = VULN_CERTIFICATE_PINNING_CONFIGURATION
category = certificate_pinning_configuration
```

目前命中：

```text
Network/MASTG-TEST0022
```

特殊狀況：

`MASTG-TEST0022` 的 XML 不是標準路徑：

```text
res/xml/network_security_config.xml
```

而是 compiled / renamed XML：

```text
res/8G.xml
```

所以目前 `_network_security_config_text()` 會 fallback 掃所有 `res/*.xml`。

### 6.6 `obsolete_tls_version`

來源：`network_code_scanner.py`

目前是 method-level Androguard instruction scanning。

條件：同一個 method 裡有：

```text
TLSv1 / TLSv1.0 / SSLv3
```

搭配：

```text
SSLContext.getInstance
或 setEnabledProtocols
```

finding：

```text
pattern_id = VULN_OBSOLETE_TLS_VERSION
category = obsolete_tls_version
```

目前命中：

```text
Network/MASTG-TEST0020
```

目前仍有一個 FP：

```text
Network/MASTG-TEST0022
VULN_OBSOLETE_TLS_VERSION
```

這是目前 Network 唯一 FP。

### 6.7 `certificate_validation_bypass`

來源：`network_code_scanner.py`

目前是 per-DEX string-level rule，不是 method-level。

偵測 TrustManager / X509TrustManager 相關 bypass pattern：

```text
X509TrustManager
TrustManager
checkServerTrusted
checkClientTrusted
getAcceptedIssuers
return null
trustAllCerts
setDefaultSSLSocketFactory
SSLContext
HttpsURLConnection
```

finding：

```text
pattern_id = VULN_CERTIFICATE_VALIDATION_BYPASS
category = certificate_validation_bypass
```

目前命中：

```text
Network/MASTG-TEST0020
```

---

## 7. Network 尚未完成 / 下一步

### 7.1 Network/MASTG-TEST0019 尚未命中

目前 0019 已命中：

```text
uses_cleartext_traffic
low_min_sdk_network_security_bypass
```

尚未命中：

```text
cleartext_http
hostname_verification_bypass
tls_error_handling_disabled
```

建議優先順序：

1. `hostname_verification_bypass`
2. `webview_ssl_error_bypass` / `tls_error_handling_disabled`
3. `cleartext_http`

`cleartext_http` 很容易 FP，建議不要太早開。

### 7.2 Network/MASTG-TEST0021 尚未命中

目前 0021 已命中：

```text
low_target_sdk_network_security
user_ca_trust_enabled
```

尚未命中：

```text
webview_ssl_error_bypass
hostname_verification_bypass
insecure_trust_manager
```

這三個屬於 code-level detection。

不建議直接把：

```python
ENABLE_EXPERIMENTAL_0021_RULES = True
```

打開，因為現在 prepared rules 主要是 DEX string-level，可能導致 FP。

建議改成更嚴格：

```text
webview_ssl_error_bypass:
  method-level，同一個 method 同時有 onReceivedSslError + SslErrorHandler + proceed

hostname_verification_bypass:
  method-level 或 class-level，同一個 verify method 中有 return true / NO_VERIFY / ALLOW_ALL_HOSTNAME_VERIFIER

insecure_trust_manager:
  class-level，class implements X509TrustManager，且 checkServerTrusted/checkClientTrusted 沒有實質驗證，或 getAcceptedIssuers return null / empty array
```

### 7.3 Network/MASTG-TEST0022 尚未命中

目前 0022 已命中：

```text
certificate_pinning_configuration
```

尚未命中：

```text
missing_certificate_pinning
```

目前 FP：

```text
obsolete_tls_version
```

建議先修 FP，再考慮補 `missing_certificate_pinning`。

`missing_certificate_pinning` 是比較難的 rule，因為同一個 app 可能同時有 pinning config 和沒 pinning 的 request path。

### 7.4 Network/MASTG-TEST0023 尚未完成

尚未命中：

```text
missing_security_provider_update
missing_google_play_services_dependency
```

這兩條是 absence-based rules。

不建議現在硬做，因為容易變成：

```text
沒看到 ProviderInstaller 就報漏洞
```

比較好的條件應該是：

```text
app 有 network/TLS usage
且沒有 ProviderInstaller.installIfNeeded / installIfNeededAsync
且沒有 Google Play Services dependency evidence
```

但 APK 裡不一定保留 Gradle dependency evidence，因此實作需要謹慎。

---

## 8. Platform 目前結果

Platform category 目前有 10 cases，expected 25。

MobSF 結果：

```json
{
  "cases": 10,
  "expected": 25,
  "raw_findings": 85,
  "scoped_findings": 73,
  "tp": 3,
  "fp": 70,
  "fn": 22,
  "precision": 0.0410958904109589,
  "recall": 0.12,
  "f1": 0.061224489795918366
}
```

our_scanner 結果：

```json
{
  "cases": 10,
  "expected": 25,
  "raw_findings": 2,
  "scoped_findings": 2,
  "tp": 1,
  "fp": 1,
  "fn": 24,
  "precision": 0.5,
  "recall": 0.04,
  "f1": 0.07407407407407407
}
```

可以說明：

```text
MobSF 在 Platform 類別 finding 很多，但 FP 很高。
our_scanner 在 Platform 類別比較保守，precision 較高，但 coverage 明顯不足。
```

目前 Platform 是下一個最值得擴充的方向。

---

## 9. Platform 可能待辦清單

以下依建議優先順序排列。

### Priority 1：先補最容易、最像 manifest/static pattern 的 case

#### 9.1 Platform/MASTG-TEST0007：ContentProvider IPC exposure / SQL injection

Ground truth：

```text
exported_provider
content_provider_sql_injection
```

目前 our_scanner 可能已能部分偵測 exported provider，但 SQL injection 尚未完成。

建議：

- 先確認 `VULN_EXPORTED_PROVIDER_LEAK` 是否命中。
- 若沒命中，檢查 provider exported / permission / readPermission / writePermission。
- `content_provider_sql_injection` 需要 code-level pattern：
  - `ContentProvider`
  - `query(...)`
  - `SQLiteDatabase`
  - `rawQuery`
  - `SQLiteQueryBuilder`
  - `selection`
  - `appendWhere`
  - `Uri.getPathSegments`
  - SQL string concatenation

可能新增 scanner：

```text
platform_code_scanner.py
或 code_pattern_scanner.py
```

#### 9.2 Platform/MASTG-TEST0028：Deep Links

Ground truth：

```text
insecure_deeplink
deeplink_auth_bypass
deeplink_webview_input_control
```

目前已有 deep link parser：

- `deep_link.py`
- `manifest_parser.py`
- `risk_rules.py`
- `vulnerability_patterns.py`

建議先補：

```text
insecure_deeplink
```

條件可能是：

```text
Activity 有 intent-filter
包含 android.intent.action.VIEW
包含 android.intent.category.BROWSABLE
有 data scheme/host/path
且 exported=true 或 implicit exported
```

finding category 建議用：

```text
insecure_deeplink
```

或 ground truth acceptable categories 中的：

```text
deep_link_exposure
browsable_intent_filter
manifest_deeplink
```

後續 code-level 再補：

```text
deeplink_auth_bypass:
  getIntent / getData / getQueryParameter / login / admin / bypass pattern

deeplink_webview_input_control:
  getQueryParameter / getData -> WebView.loadUrl
```

#### 9.3 Platform/MASTG-TEST0024：Excessive Permissions

Ground truth：

```text
excessive_permissions
dangerous_permission_requested
```

這個相對容易從 Manifest 做。

需要在 `manifest_parser.py` 加上 uses-permission collection，或新增 function 解析 root 中：

```xml
<uses-permission android:name="..." />
```

然後在 `vulnerability_patterns.py` 或新檔案中報：

```text
VULN_EXCESSIVE_PERMISSIONS
category = excessive_permissions

VULN_DANGEROUS_PERMISSION_REQUESTED
category = dangerous_permission
```

dangerous permission keyword：

```text
READ_CONTACTS
WRITE_CALENDAR
CALL_PHONE
ANSWER_PHONE_CALLS
CAMERA
RECORD_AUDIO
ACCESS_FINE_LOCATION
READ_SMS
```

但 excessive permission 需要知道 app purpose，benchmark 是 camera app，可能先針對 MASTG-TEST0024 的 suspicious permission list 做 rule。

---

### Priority 2：WebView 類別

#### 9.4 Platform/MASTG-TEST0031：JavaScript Execution in WebViews

Ground truth：

```text
webview_javascript_enabled
user_controlled_webview_content
```

可偵測 DEX strings：

```text
WebView
WebSettings
getSettings
setJavaScriptEnabled
loadUrl
EditText
getText
search
query
```

第一階段可先報：

```text
webview_javascript_enabled
```

條件：同一個 DEX/class/method 附近有：

```text
WebSettings
setJavaScriptEnabled
true
```

第二階段再做 user-controlled flow。

#### 9.5 Platform/MASTG-TEST0032：WebView Protocol Handlers

Ground truth：

```text
webview_loads_external_storage_file
webview_file_access_enabled
cleartext_traffic_allowed
```

可偵測：

```text
WebView
loadUrl
file://
getExternalStorageDirectory
setAllowFileAccess
setAllowContentAccess
setAllowFileAccessFromFileURLs
setAllowUniversalAccessFromFileURLs
```

`cleartext_traffic_allowed` 可能從 Network Security Config XML 偵測：

```xml
<domain-config cleartextTrafficPermitted="true">
  <domain>10.0.2.2</domain>
</domain-config>
```

#### 9.6 Platform/MASTG-TEST0033：JavaScript Interface Exposed

Ground truth：

```text
javascript_interface_exposed
webview_javascript_enabled_with_bridge
exported_activity_with_webview_bridge
```

可偵測：

```text
addJavascriptInterface
@JavascriptInterface
setJavaScriptEnabled
WebView
android:exported=true
```

這題可以做成 combined rule：

```text
如果同一 app 同時有 addJavascriptInterface + setJavaScriptEnabled
→ webview_javascript_enabled_with_bridge

如果包含該 WebView 的 Activity exported=true
→ exported_activity_with_webview_bridge
```

但 Activity 對應 method/class 需要更完整 class mapping，可以先用 app-level heuristic。

---

### Priority 3：PendingIntent / UI / Overlay / Cleanup

#### 9.7 Platform/MASTG-TEST0030：PendingIntent

Ground truth：

```text
mutable_pending_intent
implicit_pending_intent
```

可偵測：

```text
PendingIntent
getActivity
getService
getBroadcast
FLAG_MUTABLE
FLAG_IMMUTABLE
new Intent
setPackage
setComponent
setClass
```

第一階段可以做：

```text
FLAG_MUTABLE -> mutable_pending_intent
```

`implicit_pending_intent` 需要判斷 base Intent 是否沒有 setPackage / setComponent / setClass，比較難。

#### 9.8 Platform/MASTG-TEST0008：Sensitive UI Disclosure

Ground truth：

```text
unmasked_sensitive_input
sensitive_data_in_notification
```

可偵測：

- layout XML：
  - `EditText`
  - `inputType`
  - `textPassword`
  - `numberPassword`
  - `pin`
  - `credit card`
- DEX strings：
  - `NotificationManager`
  - `NotificationCompat`
  - `setContentText`
  - `notify`
  - `credit card`
  - `pin`

這題需要 layout XML + DEX string/code。可以晚一點。

#### 9.9 Platform/MASTG-TEST0035：Overlay / Tapjacking

Ground truth：

```text
missing_overlay_touch_filtering
missing_obscured_touch_check
```

這是 absence-based rule，容易誤報。

要偵測的是缺少：

```text
filterTouchesWhenObscured
setFilterTouchesWhenObscured
onFilterTouchEventForSecurity
FLAG_WINDOW_IS_OBSCURED
FLAG_WINDOW_IS_PARTIALLY_OBSCURED
```

不建議優先做。

#### 9.10 Platform/MASTG-TEST0037：WebView Cleanup

Ground truth：

```text
webview_storage_not_cleaned
webview_cache_not_cleared
webview_cookies_not_removed
webview_files_not_deleted
```

多數是 absence-based：

```text
WebStorage.deleteAllData
WebView.clearCache(true)
CookieManager.removeAllCookies
app_webview delete
```

不建議優先做。

---

## 10. 建議 Platform 實作順序

最推薦順序：

```text
1. MASTG-TEST0028 insecure_deeplink
2. MASTG-TEST0024 dangerous/excessive permissions
3. MASTG-TEST0031 webview_javascript_enabled
4. MASTG-TEST0033 addJavascriptInterface
5. MASTG-TEST0030 FLAG_MUTABLE PendingIntent
6. MASTG-TEST0007 exported provider / SQL injection
7. MASTG-TEST0032 WebView file access / external storage file
8. MASTG-TEST0008 sensitive UI / notification
9. MASTG-TEST0035 overlay absence-based checks
10. MASTG-TEST0037 WebView cleanup absence-based checks
```

更務實的短期目標：

```text
先讓 Platform 從：
TP=1, FP=1, FN=24, F1=0.074

提升到：
TP=5~8
FP 控制在 3~6
precision >= 0.5
recall >= 0.2
```

不要一開始就追求所有 FN，否則 FP 會爆炸。

---

## 11. 下一個 GPT 聊天室接手 Prompt

可以直接貼以下 prompt 給下一個 GPT：

```text
我正在做 CNS Final Project，專案是 Android APK 靜態安全掃描器 our_scanner，用來掃 OWASP MASTG benchmark，並與 MobSF baseline 比較。

目前架構：
- scanner.py 是 pipeline coordinator
- manifest_parser.py 解析 APK metadata、Manifest、components、deep links
- vulnerability_patterns.py 處理 manifest/XML-level findings 與 attack chains
- network_code_scanner.py 處理 DEX-level Network/TLS pattern
- scoring.py 補 severity_score / confidence_score
- evaluation.py 將 normalized reports 和 ground_truth.json 比對，算 TP/FP/FN/precision/recall/F1

目前 Network 類別已經比較成熟：
our_scanner 最新結果：TP=7, FP=1, FN=9, precision=0.875, recall=0.4375, F1=0.5833。
MobSF 在 Network 類別是 TP=0, FP=37, FN=16。

已完成 Network rules：
- uses_cleartext_traffic
- low_min_sdk_network_security_bypass
- low_target_sdk_network_security
- certificate_pinning_configuration
- user_ca_trust_enabled
- obsolete_tls_version
- certificate_validation_bypass

最近新增：
1. vulnerability_patterns.py 補 user_ca_trust_enabled：
   - XML explicit src="user" rule
   - legacy targetSdk < 24 且沒有 explicit Network Security Config 的 inferred rule
2. evaluation.py 的 DEFAULT_SCOPE_CATEGORIES 已加入 user_ca_trust_enabled / trust_user_ca / custom_trust_anchors
3. evaluation.py 輸出層已改成：保留原本 category-level output，另外在 evaluation_results/<Category>/<tool>/ 底下輸出每個 tool 的 summary/case/evaluation_report，並新增 comparison_report.md

目前 Platform 類別還很弱：
our_scanner Platform 結果：TP=1, FP=1, FN=24, precision=0.5, recall=0.04, F1=0.074。
MobSF Platform 結果：TP=3, FP=70, FN=22, precision=0.041, recall=0.12, F1=0.061。

我想接下來優先擴充 Platform 類別，但要控制 FP，不要亂開很寬的 DEX string rule。

請先帶我從 Platform Priority 1 開始做：
1. MASTG-TEST0028 insecure_deeplink
2. MASTG-TEST0024 dangerous/excessive permissions
3. MASTG-TEST0031 webview_javascript_enabled
4. MASTG-TEST0033 addJavascriptInterface
5. MASTG-TEST0030 FLAG_MUTABLE PendingIntent

請一次只帶我改一個小步驟，並且每次都讓我跑 evaluation 看 TP/FP/FN 是否改善。
```

---