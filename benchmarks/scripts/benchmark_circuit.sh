#!/bin/bash

# benchmark_circuit.sh - Benchmarks a single Noir circuit
# Usage: ./benchmark_circuit.sh <circuit_path> <oracle_type> <output_json>

set -e

CIRCUIT_PATH="$1"
ORACLE_TYPE="$2"  # "default" or "keccak"
OUTPUT_JSON="$3"

if [ -z "$CIRCUIT_PATH" ] || [ -z "$ORACLE_TYPE" ] || [ -z "$OUTPUT_JSON" ]; then
    echo "Usage: $0 <circuit_path> <oracle_type> <output_json>"
    exit 1
fi

# Get circuit name from Nargo.toml
CIRCUIT_NAME=$(grep "^name = " "$CIRCUIT_PATH/Nargo.toml" | sed 's/name = "\(.*\)"/\1/')
if [ -z "$CIRCUIT_NAME" ]; then
    CIRCUIT_NAME=$(basename "$CIRCUIT_PATH")
fi

# Clean up circuit path - make it relative from examples directory
CIRCUIT_PATH_CLEAN="examples/$(basename "$CIRCUIT_PATH")"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=================================================="
echo "Benchmarking: $CIRCUIT_NAME"
echo "Oracle: $ORACLE_TYPE"
echo "=================================================="

cd "$CIRCUIT_PATH"

# Clean previous artifacts
rm -rf target/
mkdir -p target/

# Prepare nargo command with oracle flag
NARGO_COMPILE_CMD="nargo compile"
NARGO_EXECUTE_CMD="nargo execute"
BB_GATES_CMD="bb gates"
BB_WRITE_VK_CMD="bb write_vk"
BB_PROVE_CMD="bb prove"
BB_VERIFY_CMD="bb verify"

# Initialize results
COMPILE_TIME=0
COMPILE_SUCCESS="false"
EXECUTE_TIME=0
EXECUTE_SUCCESS="false"
CIRCUIT_SIZE=0
WITNESS_SIZE=0
GATES_OUTPUT=""
TOTAL_GATES=0
ACIR_OPCODES=0
VK_GEN_TIME=0
VK_GEN_SUCCESS="false"
VK_SIZE=0
PROVE_TIME=0
PROVE_SUCCESS="false"
PROOF_SIZE=0
VERIFY_TIME=0
VERIFY_SUCCESS="false"
ERROR_MSG=""

# 1. COMPILE
echo ""
echo "[1/6] Compiling circuit..."
START=$(date +%s.%N)
if $NARGO_COMPILE_CMD > /tmp/compile_output.txt 2>&1; then
    END=$(date +%s.%N)
    COMPILE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
    COMPILE_SUCCESS="true"
    echo "✓ Compilation successful (${COMPILE_TIME}s)"
    
    # Get circuit size
    if [ -f "target/${CIRCUIT_NAME}.json" ]; then
        CIRCUIT_SIZE=$(wc -c < "target/${CIRCUIT_NAME}.json" | tr -d ' ')
    fi
else
    END=$(date +%s.%N)
    COMPILE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
    ERROR_MSG="Compilation failed. Check compilation logs."
    echo "✗ Compilation failed"
    cat /tmp/compile_output.txt
fi

# 2. EXECUTE
if [ "$COMPILE_SUCCESS" = "true" ]; then
    echo ""
    echo "[2/6] Executing circuit..."
    START=$(date +%s.%N)
    if $NARGO_EXECUTE_CMD > /tmp/execute_output.txt 2>&1; then
        END=$(date +%s.%N)
        EXECUTE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        EXECUTE_SUCCESS="true"
        echo "✓ Execution successful (${EXECUTE_TIME}s)"
        
        # Get witness size
        if [ -f "target/${CIRCUIT_NAME}.gz" ]; then
            WITNESS_SIZE=$(wc -c < "target/${CIRCUIT_NAME}.gz" | tr -d ' ')
        fi
    else
        END=$(date +%s.%N)
        EXECUTE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        ERROR_MSG="Execution failed. Check execution logs."
        echo "✗ Execution failed"
        cat /tmp/execute_output.txt
    fi
fi

# 3. GATE COUNT
if [ "$EXECUTE_SUCCESS" = "true" ]; then
    echo ""
    echo "[3/6] Counting gates..."
    if GATES_OUTPUT=$($BB_GATES_CMD -b "./target/${CIRCUIT_NAME}.json" 2>&1); then
        echo "✓ Gate count retrieved"
        echo "$GATES_OUTPUT"
        # Extract circuit_size and acir_opcodes from JSON output (bb gates returns JSON)
        TOTAL_GATES=$(echo "$GATES_OUTPUT" | grep -o '"circuit_size":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)
        if [ -z "$TOTAL_GATES" ]; then
            TOTAL_GATES=0
        fi
        ACIR_OPCODES=$(echo "$GATES_OUTPUT" | grep -o '"acir_opcodes":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' | head -1)
        if [ -z "$ACIR_OPCODES" ]; then
            ACIR_OPCODES=0
        fi
    else
        echo "✗ Gate count failed"
        GATES_OUTPUT="Gate count failed"
        TOTAL_GATES=0
        ACIR_OPCODES=0
    fi
fi

# 4. GENERATE VK
if [ "$EXECUTE_SUCCESS" = "true" ]; then
    echo ""
    echo "[4/6] Generating verification key..."
    START=$(date +%s.%N)
    if $BB_WRITE_VK_CMD -b "./target/${CIRCUIT_NAME}.json" -o ./target > /tmp/vk_output.txt 2>&1; then
        END=$(date +%s.%N)
        VK_GEN_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        VK_GEN_SUCCESS="true"
        echo "✓ VK generation successful (${VK_GEN_TIME}s)"
        
        # Get VK size (bb creates vk file directly in target directory)
        if [ -f "target/vk" ]; then
            VK_SIZE=$(wc -c < "target/vk" | tr -d ' ')
        fi
    else
        END=$(date +%s.%N)
        VK_GEN_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ VK generation failed"
        cat /tmp/vk_output.txt
    fi
fi

# 5. GENERATE PROOF
if [ "$VK_GEN_SUCCESS" = "true" ]; then
    echo ""
    echo "[5/6] Generating proof..."
    START=$(date +%s.%N)
    if $BB_PROVE_CMD -b "./target/${CIRCUIT_NAME}.json" -w "./target/${CIRCUIT_NAME}.gz" -k ./target/vk -o ./target > /tmp/prove_output.txt 2>&1; then
        END=$(date +%s.%N)
        PROVE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        PROVE_SUCCESS="true"
        echo "✓ Proof generation successful (${PROVE_TIME}s)"
        
        # Get proof size (bb creates proof file directly in target directory)
        if [ -f "target/proof" ]; then
            PROOF_SIZE=$(wc -c < "target/proof" | tr -d ' ')
        fi
    else
        END=$(date +%s.%N)
        PROVE_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ Proof generation failed"
        cat /tmp/prove_output.txt
    fi
fi

# 6. VERIFY PROOF
if [ "$PROVE_SUCCESS" = "true" ]; then
    echo ""
    echo "[6/6] Verifying proof..."
    START=$(date +%s.%N)
    # bb verify expects paths to vk, proof, and public inputs (all directly in target directory)
    if $BB_VERIFY_CMD -k ./target/vk -p ./target/proof -i ./target/public_inputs > /tmp/verify_output.txt 2>&1; then
        END=$(date +%s.%N)
        VERIFY_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        VERIFY_SUCCESS="true"
        echo "✓ Verification successful (${VERIFY_TIME}s)"
    else
        END=$(date +%s.%N)
        VERIFY_TIME=$(echo "$END - $START" | bc | awk '{printf "%.9f", $0}')
        echo "✗ Verification failed"
        cat /tmp/verify_output.txt
    fi
fi

# Get system info (escape for JSON)
NARGO_VERSION=$(nargo --version 2>/dev/null | tr '\n' ' ' || echo "unknown")
BB_VERSION=$(bb --version 2>/dev/null | tr '\n' ' ' || echo "unknown")
OS_INFO=$(uname -s)
ARCH_INFO=$(uname -m)

# Get hardware info
if [ "$(uname -s)" = "Darwin" ]; then
    # macOS
    CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
    CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
    RAM_GB=$(echo "scale=2; $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824" | bc)
    [ "$RAM_GB" = "0" ] && RAM_GB="unknown"
elif [ "$(uname -s)" = "Linux" ]; then
    # Linux
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "unknown")
    CPU_CORES=$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo 2>/dev/null || echo "unknown")
    RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    RAM_GB=$(echo "scale=2; $RAM_KB / 1048576" | bc)
    [ "$RAM_GB" = "0" ] && RAM_GB="unknown"
else
    CPU_MODEL="unknown"
    CPU_CORES="unknown"
    RAM_GB="unknown"
fi

# Create JSON output
cat > "$OUTPUT_JSON" <<EOF
{
  "circuit_name": "$CIRCUIT_NAME",
  "circuit_path": "$CIRCUIT_PATH_CLEAN",
  "oracle_type": "$ORACLE_TYPE",
  "timestamp": "$TIMESTAMP",
  "system_info": {
    "os": "$OS_INFO",
    "arch": "$ARCH_INFO",
    "cpu_model": "$CPU_MODEL",
    "cpu_cores": "$CPU_CORES",
    "ram_gb": "$RAM_GB",
    "nargo_version": "$NARGO_VERSION",
    "bb_version": "$BB_VERSION"
  },
  "compilation": {
    "time_seconds": ${COMPILE_TIME:-0},
    "success": $COMPILE_SUCCESS,
    "circuit_size_bytes": ${CIRCUIT_SIZE:-0}
  },
  "execution": {
    "time_seconds": ${EXECUTE_TIME:-0},
    "success": $EXECUTE_SUCCESS,
    "witness_size_bytes": ${WITNESS_SIZE:-0}
  },
  "gates": {
    "total_gates": ${TOTAL_GATES:-0},
    "acir_opcodes": ${ACIR_OPCODES:-0},
    "raw_output": $(echo "$GATES_OUTPUT" | jq -Rs .)
  },
  "vk_generation": {
    "time_seconds": ${VK_GEN_TIME:-0},
    "success": $VK_GEN_SUCCESS,
    "vk_size_bytes": ${VK_SIZE:-0}
  },
  "proof_generation": {
    "time_seconds": ${PROVE_TIME:-0},
    "success": $PROVE_SUCCESS,
    "proof_size_bytes": ${PROOF_SIZE:-0}
  },
  "verification": {
    "time_seconds": ${VERIFY_TIME:-0},
    "success": $VERIFY_SUCCESS
  },
  "error": $(echo "$ERROR_MSG" | jq -Rs .)
}
EOF

echo ""
echo "=================================================="
echo "Benchmark complete!"
echo "Results saved to: $OUTPUT_JSON"
echo "=================================================="