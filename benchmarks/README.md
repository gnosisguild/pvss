# PVSS Circuit Benchmarks

Automated benchmarking for PVSS Noir circuits with markdown reports.

## Requirements

- `nargo` - Noir compiler/executor
- `bb` - Barretenberg backend
- `jq` - JSON processor
- `bc`, `awk` - Math operations
- Standard Unix tools: `wc`, `date`, `uname`

## Quick Start

```bash
cd benchmarks
./run_benchmarks.sh
```

This runs all circuits in `config.json` through:

1. `nargo compile` - Compile the circuit
2. `nargo execute` - Execute with provided Prover.toml (please, remember to provide your Prover!)
3. `bb gates` - Count gates and opcodes
4. `bb write_vk` - Generate verification key
5. `bb prove` - Generate proof
6. `bb verify` - Verify proof

Outputs: `results/report.md` with timing, sizes, and comparisons.

## Configuration

Edit `config.json`:

```json
{
  "circuits": ["pk_trbfv", "enc_trbfv"],
  "oracles": ["default", "keccak"],
  "examples_dir": "../examples",
  "output_dir": "results"
}
```

- **circuits**: All the circuits must be inside the `examples` folder at root repository level.
- **oracles**: Oracle types to test (default and/or keccak)
- **examples_dir**: Path to circuit examples
- **output_dir**: Where to save results

## Usage

### Run All Benchmarks

```bash
./run_benchmarks.sh
```

### Custom Config

```bash
./run_benchmarks.sh --config <your-config>.json
```

### Clean Artifacts After

```bash
./run_benchmarks.sh --clean
```

### Single Circuit

```bash
./scripts/benchmark_circuit.sh ../examples/test123 default results/raw/test.json
```

## What Gets Measured

- Timing: Compilation, execution, VK generation, proof generation, verification
- Sizes: Circuit JSON, witness, verification key, proof
- Metrics: ACIR opcodes, total gates
- Metadata: Success/failure, system info, git commit/branch

You will get both raw JSON data and a Markdown report.

You can regenerate the report running `generate_report.sh`.
