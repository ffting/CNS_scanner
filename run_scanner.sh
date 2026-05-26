#!/usr/bin/env bash

set -u

CATEGORY="${1:-}"
BENCHMARK_ROOT="${2:-./benchmarks}"
REPORT_ROOT="${3:-./reports/our_scanner}"

if [ -z "$CATEGORY" ]; then
    echo "Usage:"
    echo "  ./run_scanner.sh <Category|ALL> [BenchmarkRoot] [ReportRoot]"
    echo ""
    echo "Examples:"
    echo "  ./run_scanner.sh Platform"
    echo "  ./run_scanner.sh Resilience"
    echo "  ./run_scanner.sh Network"
    echo "  ./run_scanner.sh ALL"
    exit 1
fi

if [ ! -d "$BENCHMARK_ROOT" ]; then
    echo "[ERROR] Benchmark root not found: $BENCHMARK_ROOT"
    exit 1
fi

run_one_category() {
    local CATEGORY_NAME="$1"
    local CATEGORY_PATH="$BENCHMARK_ROOT/$CATEGORY_NAME"

    echo "========================================"
    echo "Running our_scanner on category: $CATEGORY_NAME"
    echo "Benchmark root: $BENCHMARK_ROOT"
    echo "Report root: $REPORT_ROOT"
    echo "Category path: $CATEGORY_PATH"
    echo "========================================"

    if [ ! -d "$CATEGORY_PATH" ]; then
        echo "[ERROR] Category folder not found: $CATEGORY_PATH"
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
        local OUT_DIR

        TEST_NAME="$(basename "$(dirname "$APK_PATH")")"
        OUT_DIR="$REPORT_ROOT/$CATEGORY_NAME/$TEST_NAME"

        echo "----------------------------------------"
        echo "Test: $TEST_NAME"
        echo "APK : $APK_PATH"
        echo "Out : $OUT_DIR"

        mkdir -p "$OUT_DIR"

        python3 ./our_scanner.py -f "$APK_PATH" -o "$OUT_DIR"

        if [ $? -ne 0 ]; then
            echo "[FAIL] Scan failed: $TEST_NAME"
        else
            echo "[OK] Scan finished: $TEST_NAME"
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

        # 跳過不是 benchmark 類別的資料夾
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