#!/bin/bash

# run_benchmarks.sh - Main orchestration script for benchmarking circuits
# Usage: ./run_benchmarks.sh [--config <config_file>] [--clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARKS_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${BENCHMARKS_DIR}/config.json"
CLEAN_ARTIFACTS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --clean)
            CLEAN_ARTIFACTS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--config <config_file>] [--clean]"
            exit 1
            ;;
    esac
done

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

echo "╔════════════════════════════════════════════════╗"
echo "║       PVSS Circuit Benchmark Suite            ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Read configuration
CIRCUITS=$(jq -r '.circuits[]' "$CONFIG_FILE")
ORACLES=$(jq -r '.oracles[]' "$CONFIG_FILE")
OUTPUT_DIR=$(jq -r '.output_dir' "$CONFIG_FILE")
EXAMPLES_DIR=$(jq -r '.examples_dir' "$CONFIG_FILE")

# Create output directories
mkdir -p "${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw"

# Store git info
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

echo "Configuration:"
echo "  Git Branch: $GIT_BRANCH"
echo "  Git Commit: $GIT_COMMIT"
echo "  Circuits: $(echo $CIRCUITS | wc -w | tr -d ' ')"
echo "  Oracles: $(echo $ORACLES)"
echo ""

TOTAL_BENCHMARKS=$(($(echo $CIRCUITS | wc -w | tr -d ' ') * $(echo $ORACLES | wc -w | tr -d ' ')))
CURRENT=0

# Run benchmarks
for CIRCUIT in $CIRCUITS; do
    CIRCUIT_PATH="${BENCHMARKS_DIR}/${EXAMPLES_DIR}/${CIRCUIT}"
    
    if [ ! -d "$CIRCUIT_PATH" ]; then
        echo "⚠️  Warning: Circuit directory not found: $CIRCUIT_PATH"
        echo "    Skipping..."
        echo ""
        continue
    fi
    
    for ORACLE in $ORACLES; do
        CURRENT=$((CURRENT + 1))
        OUTPUT_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw/${CIRCUIT}_${ORACLE}.json"
        
        echo "────────────────────────────────────────────────"
        echo "Benchmark [$CURRENT/$TOTAL_BENCHMARKS]: ${CIRCUIT} with ${ORACLE} oracle"
        echo "────────────────────────────────────────────────"
        
        # Run benchmark
        "${SCRIPT_DIR}/benchmark_circuit.sh" "$CIRCUIT_PATH" "$ORACLE" "$OUTPUT_FILE"
        
        echo ""
    done
done

echo "╔════════════════════════════════════════════════╗"
echo "║       Generating Report...                     ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Generate markdown report
REPORT_FILE="${BENCHMARKS_DIR}/${OUTPUT_DIR}/report.md"
"${SCRIPT_DIR}/generate_report.sh" \
    --input-dir "${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw" \
    --output "${REPORT_FILE}" \
    --git-commit "$GIT_COMMIT" \
    --git-branch "$GIT_BRANCH"

echo "✓ Report generated: ${REPORT_FILE}"
echo ""

# Clean artifacts if requested
if [ "$CLEAN_ARTIFACTS" = true ]; then
    echo "Cleaning circuit artifacts..."
    for CIRCUIT in $CIRCUITS; do
        CIRCUIT_PATH="${BENCHMARKS_DIR}/${EXAMPLES_DIR}/${CIRCUIT}"
        if [ -d "$CIRCUIT_PATH/target" ]; then
            rm -rf "$CIRCUIT_PATH/target"
            echo "  ✓ Cleaned: $CIRCUIT"
        else
            echo "  ⊘ No target dir: $CIRCUIT"
        fi
    done
    echo ""
fi

echo "╔════════════════════════════════════════════════╗"
echo "║       Benchmark Complete!                      ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Results:"
echo "  Raw data: ${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw/"
echo "  Report: ${REPORT_FILE}"
echo ""
echo "To view the report:"
echo "  cat ${REPORT_FILE}"
echo "  # or"
echo "  open ${REPORT_FILE}  # (macOS)"

