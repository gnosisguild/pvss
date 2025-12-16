#!/bin/bash

# run_benchmarks.sh - Main orchestration script for benchmarking circuits
# Usage: ./run_benchmarks.sh [--config <config_file>] [--mode insecure|production] [--skip-compile] [--clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARKS_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${BENCHMARKS_DIR}/config.json"
CLEAN_ARTIFACTS=false
MODE_OVERRIDE=""
SKIP_COMPILE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --mode)
            MODE_OVERRIDE="$2"
            if [ "$MODE_OVERRIDE" != "insecure" ] && [ "$MODE_OVERRIDE" != "production" ]; then
                echo "Error: Mode must be 'insecure' or 'production'"
                exit 1
            fi
            shift 2
            ;;
        --skip-compile|--no-compile)
            SKIP_COMPILE=true
            shift
            ;;
        --clean)
            CLEAN_ARTIFACTS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--config <config_file>] [--mode insecure|production] [--skip-compile] [--clean]"
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
OUTPUT_DIR_BASE=$(jq -r '.output_dir // "results"' "$CONFIG_FILE")
BIN_DIR=$(jq -r '.bin_dir // "../bin"' "$CONFIG_FILE")
MODE=$(jq -r '.mode // "insecure"' "$CONFIG_FILE")

# Override mode if provided via command line
if [ -n "$MODE_OVERRIDE" ]; then
    MODE="$MODE_OVERRIDE"
fi

# Validate mode
if [ "$MODE" != "insecure" ] && [ "$MODE" != "production" ]; then
    echo "Error: Invalid mode '$MODE'. Must be 'insecure' or 'production'"
    exit 1
fi

# Set the base directory for circuits
CIRCUITS_BASE_DIR="${BENCHMARKS_DIR}/${BIN_DIR}/${MODE}"

# Create mode-specific output directory
OUTPUT_DIR="${OUTPUT_DIR_BASE}_${MODE}"
mkdir -p "${BENCHMARKS_DIR}/${OUTPUT_DIR}/raw"

# Store git info
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

echo "Configuration:"
echo "  Mode: $MODE"
if [ "$SKIP_COMPILE" = true ]; then
    echo "  Skip Compilation: Yes (using existing artifacts)"
fi
echo "  Git Branch: $GIT_BRANCH"
echo "  Git Commit: $GIT_COMMIT"
echo "  Circuits: $(echo $CIRCUITS | wc -w | tr -d ' ')"
echo "  Oracles: $(echo $ORACLES)"
echo "  Base Directory: $CIRCUITS_BASE_DIR"
echo "  Output Directory: ${OUTPUT_DIR}"
echo ""

TOTAL_BENCHMARKS=$(($(echo $CIRCUITS | wc -w | tr -d ' ') * $(echo $ORACLES | wc -w | tr -d ' ')))
CURRENT=0

# Run benchmarks
for CIRCUIT in $CIRCUITS; do
    CIRCUIT_PATH="${CIRCUITS_BASE_DIR}/${CIRCUIT}"
    
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
        echo "Benchmark [$CURRENT/$TOTAL_BENCHMARKS]: ${CIRCUIT} (${MODE}) with ${ORACLE} oracle"
        echo "────────────────────────────────────────────────"
        
        # Run benchmark
        BENCHMARK_ARGS=("$CIRCUIT_PATH" "$ORACLE" "$OUTPUT_FILE" "$MODE")
        if [ "$SKIP_COMPILE" = true ]; then
            BENCHMARK_ARGS+=("--skip-compile")
        fi
        "${SCRIPT_DIR}/benchmark_circuit.sh" "${BENCHMARK_ARGS[@]}"
        
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
        CIRCUIT_PATH="${CIRCUITS_BASE_DIR}/${CIRCUIT}"
        if [ -d "$CIRCUIT_PATH/target" ]; then
            rm -rf "$CIRCUIT_PATH/target"
            echo "  ✓ Cleaned: $CIRCUIT (${MODE})"
        else
            echo "  ⊘ No target dir: $CIRCUIT (${MODE})"
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

