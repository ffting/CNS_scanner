#!/usr/bin/env bash

set -u

CATEGORY="$1"
BENCHMARK_ROOT="${2:-./benchmarks}"
REPORT_ROOT="${3:-./reports/our_scanner}"

if [ -z "$CATEGORY" ]; then
    echo "Usage:"
    echo "  ./run_our_scanner_folder.sh <Category> [BenchmarkRoot] [ReportRoot]"
    echo ""
    echo "Examples:"
    echo "  ./run_our_scanner_folder.sh Platform"
    echo "  ./run_our_scanner_folder.sh Resilience"
    echo "  ./run_our_scanner_folder.sh Network"
    exit 1
fi

CATEGORY_PATH="$BENCHMARK_ROOT/$CATEGORY"

echo "========================================"
echo "Running our_scanner on category: $CATEGORY"
echo "Benchmark root: $BENCHMARK_ROOT"
echo "Report root: $REPORT_ROOT"
echo "Category path: $CATEGORY_PATH"
echo "========================================"

if [ ! -d "$CATEGORY_PATH" ]; then
    echo "[ERROR] Category folder not found: $CATEGORY_PATH"
    exit 1
fi

APK_COUNT=$(find "$CATEGORY_PATH" -type f -name "*.apk" | wc -l)

if [ "$APK_COUNT" -eq 0 ]; then
    echo "[WARN] No APK files found under: $CATEGORY_PATH"
    exit 0
fi

echo "Found $APK_COUNT APK(s)."
echo ""

find "$CATEGORY_PATH" -type f -name "*.apk" | sort | while read -r APK_PATH; do
    TEST_NAME="$(basename "$(dirname "$APK_PATH")")"
    OUT_DIR="$REPORT_ROOT/$CATEGORY/$TEST_NAME"

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
echo "All scans completed for category: $CATEGORY"
echo "========================================"