# USAGE

本文件整理本專案常用指令，請在專案根目錄 `CNS_scanner/` 下執行。

## 啟動 Python 環境

```bash
source .venv/bin/activate
```

如果還沒有安裝套件，先執行：

```bash
pip install -r requirements.txt
```

## 執行 our_scanner 掃描單一 APK

```bash
python3 our_scanner.py -f <APK_PATH> -o <OUTPUT_DIR>
```

範例：

```bash
python3 our_scanner.py \
  -f ./benchmarks/Network/MASTG-TEST0019/MASTG-TEST0019.apk \
  -o ./reports/our_scanner_raw/Network/MASTG-TEST0019
```

輸出內容會包含：

```text
<package_name>.json
<package_name>.md
<package_name>_poc.sh
```

## 執行 our_scanner 掃描整個類別

使用 `run_scanner.sh`：

```bash
./run_scanner.sh <Category>
```

範例：

```bash
./run_scanner.sh Network
./run_scanner.sh Platform
./run_scanner.sh Storage
./run_scanner.sh Code
```

掃描全部 benchmark：

```bash
./run_scanner.sh ALL
```

預設輸出位置：

```text
Raw reports:
./reports/our_scanner_raw/<Category>/<MASTG-TESTxxxx>/

Normalized reports:
./reports/normalized/our_scanner/<Category>/<MASTG-TESTxxxx>.json
```

## 查看 our_scanner normalized 結果

查看某個 case 的 vulnerabilities：

```bash
cat reports/normalized/our_scanner/Network/MASTG-TEST0019.json | jq '.vulnerabilities'
```

查看 metadata：

```bash
cat reports/normalized/our_scanner/Network/MASTG-TEST0019.json | jq '.meta'
```

如果沒有安裝 `jq`：

```bash
sudo apt update
sudo apt install jq
```

## 執行 MobSF 掃描

請先確認 MobSF server 已啟動，通常是：

```text
http://127.0.0.1:8000
```

執行 MobSF 掃描：

```bash
python3 run_MobSF.py <Category> \
  --benchmark-root ./benchmarks \
  --out-root ./reports/mobsf \
  --server http://127.0.0.1:8000 \
  --api-key <YOUR_MOBSF_API_KEY>
```

範例：

```bash
python3 run_MobSF.py Network \
  --benchmark-root ./benchmarks \
  --out-root ./reports/mobsf \
  --server http://127.0.0.1:8000 \
  --api-key <YOUR_MOBSF_API_KEY>
```

## Normalize MobSF reports

MobSF raw report 需要轉成 evaluation 可讀的 normalized 格式。

```bash
python3 normalize_mobsf.py \
  --input-dir ./reports/mobsf/<Category> \
  --out-dir ./reports/normalized/mobsf/<Category>
```

範例：

```bash
python3 normalize_mobsf.py \
  --input-dir ./reports/mobsf/Network \
  --out-dir ./reports/normalized/mobsf/Network
```

## 執行 evaluation

只評估 our_scanner：

```bash
python3 evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool our_scanner=./reports/normalized/our_scanner \
  --output-dir ./evaluation_results \
  --category Network
```

同時比較 our_scanner 和 MobSF：

```bash
python3 evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool our_scanner=./reports/normalized/our_scanner \
  --tool mobsf=./reports/normalized/mobsf \
  --output-dir ./evaluation_results \
  --category Network
```

注意：`--tool` 建議給 scanner 的 normalized 根目錄，不要直接給到 category 子資料夾。

正確：

```bash
--tool our_scanner=./reports/normalized/our_scanner
```

不建議：

```bash
--tool our_scanner=./reports/normalized/our_scanner/Network
```

## 查看 evaluation 結果

查看 summary：

```bash
cat evaluation_results/Network/summary.json | jq '.our_scanner'
```

如果有 MobSF：

```bash
cat evaluation_results/Network/summary.json | jq '.mobsf'
```

查看每個 case 的結果：

```bash
cat evaluation_results/Network/case_results.json | jq '.our_scanner[] | {
  case_id,
  raw_finding_count,
  scoped_finding_count,
  tp,
  fp,
  fn
}'
```

查看 matched / unmatched findings：

```bash
cat evaluation_results/Network/case_results.json | jq '.our_scanner[] | {
  case_id,
  matches,
  unmatched_expected,
  unmatched_findings
}'
```

## 常用完整流程

### 只跑 our_scanner + evaluation

```bash
source .venv/bin/activate

./run_scanner.sh Network

python3 evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool our_scanner=./reports/normalized/our_scanner \
  --output-dir ./evaluation_results \
  --category Network

cat evaluation_results/Network/summary.json | jq '.our_scanner'
```

### 跑 our_scanner + MobSF + evaluation

```bash
source .venv/bin/activate

./run_scanner.sh Network

python3 run_MobSF.py Network \
  --benchmark-root ./benchmarks \
  --out-root ./reports/mobsf \
  --server http://127.0.0.1:8000 \
  --api-key <YOUR_MOBSF_API_KEY>

python3 normalize_mobsf.py \
  --input-dir ./reports/mobsf/Network \
  --out-dir ./reports/normalized/mobsf/Network

python3 evaluation.py \
  --ground-truth ./ground_truth.json \
  --tool our_scanner=./reports/normalized/our_scanner \
  --tool mobsf=./reports/normalized/mobsf \
  --output-dir ./evaluation_results \
  --category Network

cat evaluation_results/Network/summary.json
```
