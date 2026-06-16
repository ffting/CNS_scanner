#!/usr/bin/env bash

set -u

CATEGORY="${1:-}"
BENCHMARK_ROOT="${2:-./benchmarks}"
NORMALIZED_ROOT="${3:-./reports/normalized/our_scanner}"
RAW_REPORT_ROOT="${4:-./reports/our_scanner_raw}"

if [ -z "$CATEGORY" ]; then
    echo "Usage:"
    echo "  ./run_scanner.sh <Category|ALL> [BenchmarkRoot] [NormalizedRoot] [RawReportRoot]"
    echo ""
    echo "Examples:"
    echo "  ./run_scanner.sh Platform"
    echo "  ./run_scanner.sh Network"
    echo "  ./run_scanner.sh Storage"
    echo "  ./run_scanner.sh ALL"
    echo ""
    echo "Output:"
    echo "  normalized: ./reports/normalized/our_scanner/<Category>/<MASTG-TESTxxxx>.json"
    echo "  raw:        ./reports/our_scanner_raw/<Category>/<MASTG-TESTxxxx>/"
    exit 1
fi

if [ ! -d "$BENCHMARK_ROOT" ]; then
    echo "[ERROR] Benchmark root not found: $BENCHMARK_ROOT"
    exit 1
fi

if [ ! -f "./our_scanner.py" ]; then
    echo "[ERROR] our_scanner.py not found in current directory."
    echo "Please run this script from the CNS_scanner project root."
    exit 1
fi

normalize_one_report() {
    local RAW_DIR="$1"
    local NORMALIZED_PATH="$2"
    local CATEGORY_NAME="$3"
    local TEST_NAME="$4"

    python3 - "$RAW_DIR" "$NORMALIZED_PATH" "$CATEGORY_NAME" "$TEST_NAME" <<'PY'
import json
import sys
from pathlib import Path

raw_dir = Path(sys.argv[1])
normalized_path = Path(sys.argv[2])
category = sys.argv[3]
test_name = sys.argv[4]

json_files = sorted(raw_dir.glob("*.json"))

if not json_files:
    print(f"[WARN] No JSON report found in {raw_dir}")
    sys.exit(0)

# our_scanner should normally produce one package-name JSON.
src = json_files[0]

try:
    with src.open("r", encoding="utf-8") as f:
        report = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to read JSON report {src}: {e}")
    sys.exit(1)

# Add fields required / useful for evaluation.py.
report["tool"] = "our_scanner"
report["case_id"] = f"{category}/{test_name}"

# Also add source to each vulnerability, if missing.
for finding in report.get("vulnerabilities", []):
    if isinstance(finding, dict):
        finding.setdefault("source", "our_scanner")

normalized_path.parent.mkdir(parents=True, exist_ok=True)

with normalized_path.open("w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"[OK] Normalized report written: {normalized_path}")
PY
}

run_one_category() {
    local CATEGORY_NAME="$1"
    local CATEGORY_PATH="$BENCHMARK_ROOT/$CATEGORY_NAME"

    echo "========================================"
    echo "Running our_scanner on category: $CATEGORY_NAME"
    echo "Benchmark root:     $BENCHMARK_ROOT"
    echo "Raw report root:    $RAW_REPORT_ROOT"
    echo "Normalized root:    $NORMALIZED_ROOT"
    echo "Category path:      $CATEGORY_PATH"
    echo "========================================"

    if [ ! -d "$CATEGORY_PATH" ]; then
        echo "[ERROR] Category folder not found: $CATEGORY_PATH"
        echo ""
        return 1
    fi

    local APK_COUNT
    APK_COUNT=$(find "$CATEGORY_PATH" -type f -name "*.apk" | wc -l)

    if [ "$APK_COUNT" -eq 0 ]; then
        echo "[WARN] No APK files found under: $CATEGORY_PATH"
        echo ""
        return 0
    fi

    echo "Found $APK_COUNT APK(s)."
    echo ""

    find "$CATEGORY_PATH" -type f -name "*.apk" | sort | while read -r APK_PATH; do
        local TEST_NAME
        local RAW_OUT_DIR
        local NORMALIZED_OUT_PATH

        TEST_NAME="$(basename "$(dirname "$APK_PATH")")"

        RAW_OUT_DIR="$RAW_REPORT_ROOT/$CATEGORY_NAME/$TEST_NAME"
        NORMALIZED_OUT_PATH="$NORMALIZED_ROOT/$CATEGORY_NAME/$TEST_NAME.json"

        echo "----------------------------------------"
        echo "Test: $TEST_NAME"
        echo "APK : $APK_PATH"
        echo "Raw : $RAW_OUT_DIR"
        echo "Norm: $NORMALIZED_OUT_PATH"

        mkdir -p "$RAW_OUT_DIR"
        mkdir -p "$(dirname "$NORMALIZED_OUT_PATH")"

        python3 ./our_scanner.py -f "$APK_PATH" -o "$RAW_OUT_DIR"

        if [ $? -ne 0 ]; then
            echo "[FAIL] Scan failed: $TEST_NAME"
            echo ""
            continue
        fi

        normalize_one_report "$RAW_OUT_DIR" "$NORMALIZED_OUT_PATH" "$CATEGORY_NAME" "$TEST_NAME"

        if [ $? -ne 0 ]; then
            echo "[FAIL] Normalize failed: $TEST_NAME"
        else
            echo "[OK] Scan + normalize finished: $TEST_NAME"
        fi

        echo ""
    done

    echo "========================================"
    echo "All scans completed for category: $CATEGORY_NAME"
    echo "========================================"
    echo ""

    return 0
}

if [ "$CATEGORY" = "ALL" ]; then
    echo "Running all benchmark categories under: $BENCHMARK_ROOT"
    echo ""

    find "$BENCHMARK_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | while read -r CATEGORY_PATH; do
        CATEGORY_NAME="$(basename "$CATEGORY_PATH")"

        if [ "$CATEGORY_NAME" = "evaluation_results" ]; then
            continue
        fi

        run_one_category "$CATEGORY_NAME"
    done

    echo "========================================"
    echo "All category scans completed."
    echo "========================================"
else
    run_one_category "$CATEGORY"
fi