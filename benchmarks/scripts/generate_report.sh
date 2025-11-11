#!/bin/bash

# generate_report.sh - Generates a markdown report from benchmark JSON results
# Usage: ./generate_report.sh --input-dir <dir> --output <file> --git-commit <hash> --git-branch <branch>

set -e

INPUT_DIR=""
OUTPUT_FILE=""
GIT_COMMIT="unknown"
GIT_BRANCH="unknown"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --input-dir)
            INPUT_DIR="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --git-commit)
            GIT_COMMIT="$2"
            shift 2
            ;;
        --git-branch)
            GIT_BRANCH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$INPUT_DIR" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 --input-dir <dir> --output <file> [--git-commit <hash>] [--git-branch <branch>]"
    exit 1
fi

# Helper functions
format_bytes() {
    local bytes=$1
    if [ "$bytes" -eq 0 ]; then
        echo "0 B"
    elif [ "$bytes" -lt 1024 ]; then
        echo "${bytes} B"
    elif [ "$bytes" -lt 1048576 ]; then
        local kb=$(echo "scale=5; $bytes/1024" | bc | awk '{printf "%.2f", $0}')
        echo "${kb} KB"
    else
        local mb=$(echo "scale=5; $bytes/1048576" | bc | awk '{printf "%.2f", $0}')
        echo "${mb} MB"
    fi
}

format_time() {
    local seconds=$1
    # Multiply by 1000 and format to 2 decimal places
    local ms=$(echo "scale=10; $seconds * 1000" | bc | awk '{printf "%.2f", $0}')
    echo "${ms} ms"
}

format_gates() {
    local gates=$1
    if [ "$gates" -ge 1000000 ]; then
        local m=$(echo "scale=5; $gates/1000000" | bc | awk '{printf "%.2f", $0}')
        echo "${m}M"
    elif [ "$gates" -ge 1000 ]; then
        local k=$(echo "scale=5; $gates/1000" | bc | awk '{printf "%.2f", $0}')
        echo "${k}K"
    else
        echo "$gates"
    fi
}

calc_percent_diff() {
    local base=$1
    local compare=$2
    if [ "$base" = "0" ] || [ "$base" = "0.0" ] || [ "$base" = "0.000000000" ]; then
        echo "N/A"
    else
        # Calculate with more precision then format
        local diff=$(echo "scale=5; (($compare - $base) / $base) * 100" | bc | awk '{printf "%.1f", $0}')
        # Check if positive
        if [ "$(echo "$diff >= 0" | bc)" -eq 1 ]; then
            echo "+${diff}%"
        else
            echo "${diff}%"
        fi
    fi
}

# Start building report
TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S UTC")

cat > "$OUTPUT_FILE" << EOF
# PVSS Circuit Benchmarks

**Generated:** ${TIMESTAMP}

**Git Branch:** \`${GIT_BRANCH}\`  
**Git Commit:** \`${GIT_COMMIT}\`

---

## Summary

### Timing Metrics

| Circuit | Oracle | Compile | Execute | Prove | Verify | Status |
|---------|--------|---------|---------|-------|--------|--------|
EOF

# Read all JSON files and generate timing table
for json_file in "$INPUT_DIR"/*.json; do
    [ -f "$json_file" ] || continue
    
    circuit=$(jq -r '.circuit_name' "$json_file")
    oracle=$(jq -r '.oracle_type' "$json_file")
    compile_time=$(jq -r '.compilation.time_seconds' "$json_file")
    execute_time=$(jq -r '.execution.time_seconds' "$json_file")
    prove_time=$(jq -r '.proof_generation.time_seconds' "$json_file")
    verify_time=$(jq -r '.verification.time_seconds' "$json_file")
    success=$(jq -r '.verification.success' "$json_file")
    
    compile_fmt=$(format_time "$compile_time")
    execute_fmt=$(format_time "$execute_time")
    prove_fmt=$(format_time "$prove_time")
    verify_fmt=$(format_time "$verify_time")
    
    if [ "$success" = "true" ]; then
        status="✅"
    else
        status="❌"
    fi
    
    echo "| $circuit | $oracle | $compile_fmt | $execute_fmt | $prove_fmt | $verify_fmt | $status |" >> "$OUTPUT_FILE"
done

# Size & Circuit Metrics table
cat >> "$OUTPUT_FILE" << EOF

### Size & Circuit Metrics

| Circuit | Oracle | Opcodes | Gates | Circuit Size | Witness | VK Size | Proof Size |
|---------|--------|---------|-------|--------------|---------|---------|------------|
EOF

for json_file in "$INPUT_DIR"/*.json; do
    [ -f "$json_file" ] || continue
    
    circuit=$(jq -r '.circuit_name' "$json_file")
    oracle=$(jq -r '.oracle_type' "$json_file")
    opcodes=$(jq -r '.gates.acir_opcodes // 0' "$json_file")
    gates=$(jq -r '.gates.total_gates' "$json_file")
    circuit_size=$(jq -r '.compilation.circuit_size_bytes' "$json_file")
    witness_size=$(jq -r '.execution.witness_size_bytes' "$json_file")
    vk_size=$(jq -r '.vk_generation.vk_size_bytes' "$json_file")
    proof_size=$(jq -r '.proof_generation.proof_size_bytes' "$json_file")
    
    gates_fmt=$(format_gates "$gates")
    circuit_size_fmt=$(format_bytes "$circuit_size")
    witness_size_fmt=$(format_bytes "$witness_size")
    vk_size_fmt=$(format_bytes "$vk_size")
    proof_size_fmt=$(format_bytes "$proof_size")
    
    echo "| $circuit | $oracle | $opcodes | $gates_fmt | $circuit_size_fmt | $witness_size_fmt | $vk_size_fmt | $proof_size_fmt |" >> "$OUTPUT_FILE"
done

# Detailed comparison by circuit
cat >> "$OUTPUT_FILE" << EOF

## Detailed Comparison by Circuit

EOF

# Group by circuit (get unique circuit names)
circuits=$(for json_file in "$INPUT_DIR"/*.json; do
    [ -f "$json_file" ] || continue
    jq -r '.circuit_name' "$json_file"
done | sort -u)

for circuit in $circuits; do
    echo "### $circuit" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Find files for this circuit
    default_file=""
    keccak_file=""
    
    for json_file in "$INPUT_DIR"/*.json; do
        [ -f "$json_file" ] || continue
        c=$(jq -r '.circuit_name' "$json_file")
        o=$(jq -r '.oracle_type' "$json_file")
        if [ "$c" = "$circuit" ]; then
            if [ "$o" = "default" ]; then
                default_file="$json_file"
            elif [ "$o" = "keccak" ]; then
                keccak_file="$json_file"
            fi
        fi
    done
    
    # If we have both oracles, do comparison
    if [ -n "$default_file" ] && [ -n "$keccak_file" ]; then
        cat >> "$OUTPUT_FILE" << EOF
#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
EOF
        
        # Compilation
        def_compile=$(jq -r '.compilation.time_seconds' "$default_file")
        kec_compile=$(jq -r '.compilation.time_seconds' "$keccak_file")
        diff=$(calc_percent_diff "$def_compile" "$kec_compile")
        echo "| Compilation | $(format_time $def_compile) | $(format_time $kec_compile) | $diff |" >> "$OUTPUT_FILE"
        
        # Execution
        def_exec=$(jq -r '.execution.time_seconds' "$default_file")
        kec_exec=$(jq -r '.execution.time_seconds' "$keccak_file")
        diff=$(calc_percent_diff "$def_exec" "$kec_exec")
        echo "| Execution | $(format_time $def_exec) | $(format_time $kec_exec) | $diff |" >> "$OUTPUT_FILE"
        
        # VK Generation
        def_vk=$(jq -r '.vk_generation.time_seconds' "$default_file")
        kec_vk=$(jq -r '.vk_generation.time_seconds' "$keccak_file")
        diff=$(calc_percent_diff "$def_vk" "$kec_vk")
        echo "| VK Generation | $(format_time $def_vk) | $(format_time $kec_vk) | $diff |" >> "$OUTPUT_FILE"
        
        # Proof Generation
        def_prove=$(jq -r '.proof_generation.time_seconds' "$default_file")
        kec_prove=$(jq -r '.proof_generation.time_seconds' "$keccak_file")
        diff=$(calc_percent_diff "$def_prove" "$kec_prove")
        echo "| Proof Generation | $(format_time $def_prove) | $(format_time $kec_prove) | $diff |" >> "$OUTPUT_FILE"
        
        # Verification
        def_verify=$(jq -r '.verification.time_seconds' "$default_file")
        kec_verify=$(jq -r '.verification.time_seconds' "$keccak_file")
        diff=$(calc_percent_diff "$def_verify" "$kec_verify")
        echo "| Verification | $(format_time $def_verify) | $(format_time $kec_verify) | $diff |" >> "$OUTPUT_FILE"
        
        # Size comparison
        cat >> "$OUTPUT_FILE" << EOF

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
EOF
        
        # Circuit size
        def_size=$(jq -r '.compilation.circuit_size_bytes' "$default_file")
        kec_size=$(jq -r '.compilation.circuit_size_bytes' "$keccak_file")
        diff=$(calc_percent_diff "$def_size" "$kec_size")
        echo "| Circuit JSON | $(format_bytes $def_size) | $(format_bytes $kec_size) | $diff |" >> "$OUTPUT_FILE"
        
        # Witness size
        def_witness=$(jq -r '.execution.witness_size_bytes' "$default_file")
        kec_witness=$(jq -r '.execution.witness_size_bytes' "$keccak_file")
        diff=$(calc_percent_diff "$def_witness" "$kec_witness")
        echo "| Witness | $(format_bytes $def_witness) | $(format_bytes $kec_witness) | $diff |" >> "$OUTPUT_FILE"
        
        # VK size
        def_vk_size=$(jq -r '.vk_generation.vk_size_bytes' "$default_file")
        kec_vk_size=$(jq -r '.vk_generation.vk_size_bytes' "$keccak_file")
        diff=$(calc_percent_diff "$def_vk_size" "$kec_vk_size")
        echo "| Verification Key | $(format_bytes $def_vk_size) | $(format_bytes $kec_vk_size) | $diff |" >> "$OUTPUT_FILE"
        
        # Proof size
        def_proof=$(jq -r '.proof_generation.proof_size_bytes' "$default_file")
        kec_proof=$(jq -r '.proof_generation.proof_size_bytes' "$keccak_file")
        diff=$(calc_percent_diff "$def_proof" "$kec_proof")
        echo "| Proof | $(format_bytes $def_proof) | $(format_bytes $kec_proof) | $diff |" >> "$OUTPUT_FILE"
        
        # Gate count
        cat >> "$OUTPUT_FILE" << EOF

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
EOF
        
        def_opcodes=$(jq -r '.gates.acir_opcodes // 0' "$default_file")
        def_gates=$(jq -r '.gates.total_gates' "$default_file")
        kec_opcodes=$(jq -r '.gates.acir_opcodes // 0' "$keccak_file")
        kec_gates=$(jq -r '.gates.total_gates' "$keccak_file")
        
        echo "| Default | $def_opcodes | $def_gates |" >> "$OUTPUT_FILE"
        echo "| Keccak | $kec_opcodes | $kec_gates |" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        
    else
        # Only one oracle - simple display
        json_file="${default_file:-$keccak_file}"
        oracle=$(jq -r '.oracle_type' "$json_file")
        
        echo "**Oracle:** $oracle" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        
        compile=$(jq -r '.compilation.time_seconds' "$json_file")
        execute=$(jq -r '.execution.time_seconds' "$json_file")
        opcodes=$(jq -r '.gates.acir_opcodes // 0' "$json_file")
        gates=$(jq -r '.gates.total_gates' "$json_file")
        vk_gen=$(jq -r '.vk_generation.time_seconds' "$json_file")
        prove=$(jq -r '.proof_generation.time_seconds' "$json_file")
        verify=$(jq -r '.verification.time_seconds' "$json_file")
        circuit_size=$(jq -r '.compilation.circuit_size_bytes' "$json_file")
        proof_size=$(jq -r '.proof_generation.proof_size_bytes' "$json_file")
        
        echo "- **Compilation:** $(format_time $compile)" >> "$OUTPUT_FILE"
        echo "- **Execution:** $(format_time $execute)" >> "$OUTPUT_FILE"
        echo "- **ACIR Opcodes:** $opcodes" >> "$OUTPUT_FILE"
        echo "- **Gates:** $gates" >> "$OUTPUT_FILE"
        echo "- **VK Generation:** $(format_time $vk_gen)" >> "$OUTPUT_FILE"
        echo "- **Proof Generation:** $(format_time $prove)" >> "$OUTPUT_FILE"
        echo "- **Verification:** $(format_time $verify)" >> "$OUTPUT_FILE"
        echo "- **Circuit Size:** $(format_bytes $circuit_size)" >> "$OUTPUT_FILE"
        echo "- **Proof Size:** $(format_bytes $proof_size)" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
done

# System info (from first JSON file)
first_json=$(ls "$INPUT_DIR"/*.json 2>/dev/null | head -1)
if [ -n "$first_json" ]; then
    cat >> "$OUTPUT_FILE" << EOF
## System Information

### Hardware

EOF
    
    cpu_model=$(jq -r '.system_info.cpu_model // "unknown"' "$first_json")
    cpu_cores=$(jq -r '.system_info.cpu_cores // "unknown"' "$first_json")
    ram_gb=$(jq -r '.system_info.ram_gb // "unknown"' "$first_json")
    os=$(jq -r '.system_info.os' "$first_json")
    arch=$(jq -r '.system_info.arch' "$first_json")
    
    echo "- **CPU:** $cpu_model" >> "$OUTPUT_FILE"
    echo "- **CPU Cores:** $cpu_cores" >> "$OUTPUT_FILE"
    echo "- **RAM:** ${ram_gb} GB" >> "$OUTPUT_FILE"
    echo "- **OS:** $os" >> "$OUTPUT_FILE"
    echo "- **Architecture:** $arch" >> "$OUTPUT_FILE"
    
    cat >> "$OUTPUT_FILE" << EOF

### Software

EOF
    
    nargo=$(jq -r '.system_info.nargo_version' "$first_json")
    bb=$(jq -r '.system_info.bb_version' "$first_json")
    
    echo "- **Nargo Version:** $nargo" >> "$OUTPUT_FILE"
    echo "- **Barretenberg Version:** $bb" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi

echo "✓ Report generated successfully: $OUTPUT_FILE"

