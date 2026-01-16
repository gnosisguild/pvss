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

By default, this runs benchmarks for the `insecure` mode. To run for `production`:

```bash
./run_benchmarks.sh --mode production
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
  "circuits": ["pk_trbfv", "greco"],
  "oracles": ["default"],
  "mode": "insecure",
  "bin_dir": "../bin",
  "output_dir": "results"
}
```

- **circuits**: List of circuit names to benchmark (must exist in `bin/insecure` or `bin/production`)
- **oracles**: Oracle types to test (only "default" is used)
- **mode**: Default mode to use ("insecure" or "production"). Can be overridden with `--mode` flag
- **bin_dir**: Path to the bin directory containing insecure/production subdirectories
- **output_dir**: Base directory name for results (will be suffixed with mode, e.g., `results` becomes `results_insecure` or `results_production`)

## Usage

### Run All Benchmarks

```bash
# Run insecure mode (default)
./run_benchmarks.sh

# Run production mode
./run_benchmarks.sh --mode production

# Run insecure mode explicitly
./run_benchmarks.sh --mode insecure

# Skip compilation (use existing compiled circuits)
./run_benchmarks.sh --skip-compile

# Combine flags
./run_benchmarks.sh --mode production --skip-compile
```

### Custom Config

```bash
./run_benchmarks.sh --config <your-config>.json
```

### Override Mode from Config

```bash
# Use production mode even if config.json specifies insecure
./run_benchmarks.sh --mode production
```

### Clean Artifacts After

```bash
./run_benchmarks.sh --clean
```

### Single Circuit

```bash
# Benchmark a single circuit (insecure mode)
./scripts/benchmark_circuit.sh ../bin/insecure/pk_trbfv default results/raw/test.json insecure

# Benchmark a single circuit (production mode)
./scripts/benchmark_circuit.sh ../bin/production/pk_trbfv default results/raw/test.json production

# Skip compilation for a single circuit
./scripts/benchmark_circuit.sh ../bin/insecure/pk_trbfv default results/raw/test.json insecure --skip-compile
```

## What Gets Measured

- Timing: Compilation, execution, VK generation, proof generation, verification
- Sizes: Circuit JSON, witness, verification key, proof
- Metrics: ACIR opcodes, total gates
- Metadata: Success/failure, system info, git commit/branch

You will get both raw JSON data and a Markdown report.

You can regenerate the report running `generate_report.sh`.
