# CNS APK Scanner

本專案是一個針對 Android APK 的靜態安全掃描器，主要用於 CNS Final Project。目標是分析 APK 中的 manifest、XML resource、DEX strings/code patterns，找出與 OWASP MASVS / MASTG benchmark 相關的安全風險，並與 MobSF baseline 做比較。

目前專案重點放在：

* AndroidManifest.xml attack surface
* exported components / ContentProvider / deep links
* Network Security Configuration
* TLS / certificate validation / cleartext traffic
* API key / token static scan
* normalized report 與 evaluation pipeline

---

## 1. Project Structure

主要檔案用途如下：

```text
our_scanner.py
```

CLI 入口，負責呼叫 scanner pipeline。

```text
scanner.py
```

核心掃描流程，依序載入 APK、解析 manifest、抽取 components/deep links、掃 API keys、套用 rules、輸出 findings。

```text
manifest_parser.py
```

解析 APK metadata、AndroidManifest.xml、components、permissions、application flags。

目前已支援：

* package name
* minSdk / targetSdk
* debuggable
* allowBackup
* usesCleartextTraffic
* exported / implicit exported components
* ContentProvider authorities
* intent-filter / deep link data

```text
vulnerability_patterns.py
```

負責 manifest-level / XML-level vulnerabilities 與 attack chain detection。

目前包含：

* exported provider
* implicit exported service
* exported component without permission
* deep link / OAuth / payment callback
* app config risks
* Network manifest/XML-level rules

```text
network_code_scanner.py
```

新增的 Network/TLS DEX string-level scanner。

目前用來偵測：

* obsolete_tls_version
* certificate_validation_bypass
* 部分 WebView SSL error / cleartext HTTP / hostname verifier patterns

注意：這支目前還需要繼續收斂規則，避免 FP。

```text
scoring.py
```

為 findings 與 attack chains 補上：

* severity_score
* confidence_score

目前已支援 Network Priority 1 / Priority 2 的 pattern ID。

```text
api_key_scanner.py
```

掃描 APK 裡可能洩漏的 API key / token，包含 Google、OpenAI、GitHub、Stripe、Slack、AWS、Firebase 等 pattern。

```text
run_scanner.sh
```

批次掃描 benchmark category，並輸出 raw report 與 normalized report。

```text
run_MobSF.py
```

呼叫 MobSF REST API 批次掃描 APK。

```text
normalize_mobsf.py
```

將 MobSF raw report 轉成 evaluation.py 可讀的 normalized 格式。

```text
evaluation.py
```

將 normalized reports 與 ground_truth.json 比對，計算：

* TP
* FP
* FN
* precision
* recall
* F1
* case-level details

---

## 2. Current Workflow

一般開發流程如下：

```bash
source .venv/bin/activate
```

掃描 Network benchmark：

```bash
./run_scanner.sh Network
```

跑 evaluation：

```bash
python evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool our_scanner=./reports/normalized/our_scanner \
  --output-dir ./evaluation_results \
  --category Network
```

查看 summary：

```bash
cat evaluation_results/Network/summary.json | jq '.our_scanner'
```

查看每個 case 的 TP / FP / FN：

```bash
cat evaluation_results/Network/case_results.json | jq '.our_scanner[] | {
  case_id,
  tp,
  fp,
  fn,
  unmatched_findings
}'
```

---

## 3. Current Network Progress

目前 Network category 共 5 個 benchmark cases：

```text
Network/MASTG-TEST0019
Network/MASTG-TEST0020
Network/MASTG-TEST0021
Network/MASTG-TEST0022
Network/MASTG-TEST0023
```

目前最新結果：

```text
cases = 5
expected = 16
raw_findings = 9
scoped_findings = 9
TP = 6
FP = 3
FN = 10
precision = 0.6667
recall = 0.375
F1 = 0.48
```

目前已經比最初版本明顯進步。

初始 Network scanner 幾乎沒有命中：

```text
TP = 0
FP = 0
FN = 16
recall = 0
```

完成 Priority 1 後：

```text
TP = 4
FP = 1
FN = 12
precision = 0.8
recall = 0.25
F1 ≈ 0.381
```

加入部分 Priority 2 DEX string-level rules 後，目前達到：

```text
TP = 6
FP = 3
FN = 10
precision ≈ 0.667
recall = 0.375
F1 = 0.48
```

---

## 4. Implemented Network Rules

### Priority 1: Manifest / XML-level rules

目前已完成：

```text
uses_cleartext_traffic
low_min_sdk_network_security_bypass
low_target_sdk_network_security
certificate_pinning_configuration
```

對應 findings：

```text
VULN_USES_CLEARTEXT_TRAFFIC
VULN_LOW_MIN_SDK_NETWORK_SECURITY_BYPASS
VULN_LOW_TARGET_SDK_NETWORK_SECURITY
VULN_CERTIFICATE_PINNING_CONFIGURATION
```

已成功命中：

```text
MASTG-TEST0019:
- uses_cleartext_traffic
- low_min_sdk_network_security_bypass

MASTG-TEST0021:
- low_target_sdk_network_security

MASTG-TEST0022:
- certificate_pinning_configuration
```

其中 `MASTG-TEST0022` 的 Network Security Config 在 APK 中不是標準路徑：

```text
res/xml/network_security_config.xml
```

而是 compiled / renamed XML：

```text
res/8G.xml
```

所以目前 rule 會掃描所有 `res/*.xml`，找出：

```text
network-security-config
pin-set
pin
digest
SHA-256
expiration
example.com
```

---

### Priority 2: DEX string-level rules

目前部分完成：

```text
obsolete_tls_version
certificate_validation_bypass
```

對應 findings：

```text
VULN_OBSOLETE_TLS_VERSION
VULN_CERTIFICATE_VALIDATION_BYPASS
```

主要目標是打中：

```text
Network/MASTG-TEST0020
```

目前 `MASTG-TEST0020` 已經可以命中：

```text
obsolete_tls_version
certificate_validation_bypass
```

但仍有 FP 需要收斂。

---

## 5. Current Case-level Status

### Network/MASTG-TEST0019

目前：

```text
TP = 2
FP = 0
FN = 3
```

已命中：

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

下一步可用 DEX / source-level patterns 補：

```text
http://
loadUrl
HostnameVerifier
setHostnameVerifier
return true
onReceivedSslError
SslErrorHandler
handler.proceed
TrustManager
X509TrustManager
```

---

### Network/MASTG-TEST0020

目前：

```text
TP = 2
FP = 1
FN = 0
```

已命中：

```text
obsolete_tls_version
certificate_validation_bypass
```

FP：

```text
uses_cleartext_traffic
```

這個 FP 來自 manifest 中真的有：

```text
android:usesCleartextTraffic=true
```

但 ground truth for MASTG-TEST0020 主要聚焦 TLS version 與 certificate validation bypass，所以 evaluation 把它算成 FP。這個 finding 本身不是完全錯誤，只是 benchmark scope 沒有算它。

---

### Network/MASTG-TEST0021

目前：

```text
TP = 1
FP = 0
FN = 4
```

已命中：

```text
low_target_sdk_network_security
```

尚未命中：

```text
user_ca_trust_enabled
webview_ssl_error_bypass
hostname_verification_bypass
insecure_trust_manager
```

這是下一個最值得補的 case。

---

### Network/MASTG-TEST0022

目前：

```text
TP = 1
FP = 2
FN = 1
```

已命中：

```text
certificate_pinning_configuration
```

尚未命中：

```text
missing_certificate_pinning
```

目前 FP：

```text
certificate_validation_bypass
obsolete_tls_version
```

這兩個 FP 代表 `network_code_scanner.py` 的 DEX string-level matching 還是偏寬，會在 0022 的 `classes.dex` 中看到相關 TLS/TrustManager 字串後誤報。

下一步應優先修這裡。

---

### Network/MASTG-TEST0023

目前：

```text
TP = 0
FP = 0
FN = 2
```

尚未命中：

```text
missing_security_provider_update
missing_google_play_services_dependency
```

這類是 absence-based rules，也就是「沒有看到 ProviderInstaller / Google Play Services dependency」。這類 rule 比較容易有爭議，建議最後再做。

---

## 6. Known Issues

### 1. network_code_scanner.py 目前仍偏寬

目前 DEX string-level rules 有時會把 unrelated strings 組合成 finding。

尤其是：

```text
VULN_OBSOLETE_TLS_VERSION
VULN_CERTIFICATE_VALIDATION_BYPASS
```

在 `MASTG-TEST0022` 會造成 FP。

建議下一步先收斂：

* 只掃 `.dex`
* 不掃 `resources.arsc`
* 不掃 `res/*.xml`
* 不掃 assets
* 不要全 APK 字串混在一起判斷
* 儘量要求同一個 source file 有完整 pattern
* 更理想是用 Androguard method/class-level analysis 或 JADX source pattern

---

### 2. cleartext_http rule 容易過寬

如果單純看到：

```text
http://
URL
loadUrl
WebView
```

很容易打到 library / default string / unrelated resource。

目前建議：

* 不要把 `cleartext_http` rule 開太寬
* 優先抓 `usesCleartextTraffic=true`
* 真正的 `cleartext_http` 最好等 JADX/source-level evidence 後再啟用

---

### 3. 0023 ProviderInstaller 是 absence-based detection

`MASTG-TEST0023` 要偵測的是：

```text
missing_security_provider_update
missing_google_play_services_dependency
```

這不是「看到某個危險 pattern」，而是「沒看到應該有的安全更新流程」。

所以需要設計更謹慎的 rule，例如：

```text
如果 app 有 network/TLS usage
且沒有 ProviderInstaller.installIfNeeded / installIfNeededAsync
且沒有 Google Play Services dependency evidence
才報 missing_security_provider_update
```

目前先不要急著硬做。

---

## 7. Recommended Next Steps

### Step 1: 收斂 network_code_scanner.py

優先目標：降低 0022 FP。

目前 0022 FP：

```text
VULN_CERTIFICATE_VALIDATION_BYPASS
VULN_OBSOLETE_TLS_VERSION
```

建議調整：

```text
1. _should_scan_file() 先只允許 .dex
2. 不要掃 XML / ARSC / assets
3. obsolete_tls_version 必須同一個 source 同時有：
   - TLSv1 or TLSv1.0
   - SSLContext
   - getInstance
4. certificate_validation_bypass 必須同一個 source 同時有：
   - X509TrustManager or TrustManager
   - checkServerTrusted or checkClientTrusted
   - 明確 bypass marker，例如 return null / trustAllCerts / setDefaultSSLSocketFactory
5. 如果仍誤報 0022，考慮先把這兩條限制在更強 evidence 才報
```

目標結果：

```text
TP = 6
FP = 1 or 2
FN = 10
precision >= 0.75
recall = 0.375
F1 around 0.5
```

比起盲目提高 recall，目前更重要的是保持 precision。

---

### Step 2: 補 Network/MASTG-TEST0021

優先補：

```text
webview_ssl_error_bypass
hostname_verification_bypass
insecure_trust_manager
user_ca_trust_enabled
```

可偵測 keyword：

```text
webview_ssl_error_bypass:
- WebView
- WebViewClient
- onReceivedSslError
- SslErrorHandler
- handler.proceed
- proceed

hostname_verification_bypass:
- HostnameVerifier
- setHostnameVerifier
- verify
- return true
- NO_VERIFY
- ALLOW_ALL_HOSTNAME_VERIFIER

insecure_trust_manager:
- X509TrustManager
- TrustManager
- checkServerTrusted
- checkClientTrusted
- getAcceptedIssuers
- return null
- trustAllCerts

user_ca_trust_enabled:
- network-security-config
- trust-anchors
- certificates
- src="user"
- user supplied CAs
```

---

### Step 3: 最後再做 Network/MASTG-TEST0023

0023 rules：

```text
missing_security_provider_update
missing_google_play_services_dependency
```

建議等前面 Network code-level scanner 穩定後再做。

可能 rule：

```text
missing_security_provider_update:
- 沒有 ProviderInstaller
- 沒有 installIfNeeded
- 沒有 installIfNeededAsync
- 但 app 有 network/TLS usage

missing_google_play_services_dependency:
- 沒有 com.google.android.gms
- 沒有 play-services-gcm
- 沒有 GoogleApiAvailability
```

---

## 8. Suggested Final Report Framing

可以在報告裡這樣描述目前成果：

```text
The scanner started from manifest-level attack surface analysis and was extended with Network Security Configuration parsing and DEX string-level TLS pattern matching. For the Network benchmark, our scanner improved from 0 true positives to 6 true positives. The current result is TP=6, FP=3, FN=10, precision=0.667, recall=0.375, and F1=0.48.

The strongest improvements came from manifest/XML-level rules such as usesCleartextTraffic, low SDK checks, and certificate pinning configuration. DEX string-level rules further detected obsolete TLS usage and certificate validation bypass in MASTG-TEST0020.

The remaining limitations are mainly caused by broad string matching, which can produce false positives when unrelated TLS keywords appear in classes.dex. Future work should move from APK-wide string matching toward method-level code analysis using JADX or Androguard control-flow information.
```

---

## 9. Current Recommendation

目前不要再盲目加 rule。建議優先順序：

```text
1. Fix FP in MASTG-TEST0022
2. Keep MASTG-TEST0020 TP=2
3. Improve MASTG-TEST0021 with stricter WebView / HostnameVerifier rules
4. Leave MASTG-TEST0023 for last
```

短期目標不是讓 recall 暴增，而是讓 scanner 維持可信：

```text
precision >= 0.75
recall around 0.375 or higher
F1 around 0.5 or higher
```

這樣會比 `TP=9, FP=7` 那種寬鬆版本更適合作為 final demo。
