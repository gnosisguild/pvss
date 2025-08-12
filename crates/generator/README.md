# PVSS Generator

A Rust library and CLI tool for generating cryptographic parameters and constants for zero-knowledge proofs in PVSS schemes using BFV homomorphic encryption. Supports multiple circuits with circuit-specific generation logic.

## Features

- **Parameter Generation**: BFV encryption parameters and bounds computation
- **Input Validation**: Vector computation and constraint checking
- **Multiple Outputs**: Noir constants and Prover TOML file generation
- **Circuit-Specific Generation**: Separate generation logic for each circuit (pk_trbfv, pk_pvw, sk_shares)
- **CLI Interface**: User-friendly command-line tool with comprehensive options
- **Library API**: Can be used as a Rust crate in other projects

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
e3-pvss-generator = "0.1.0"
```

## Quick Start

### CLI Usage

```bash
# Generate for specific circuit (required)
cargo run --bin generator -- --circuit pk_trbfv

# Generate for all circuits
cargo run --bin generator -- --circuit pk_trbfv
cargo run --bin generator -- --circuit pk_pvw
cargo run --bin generator -- --circuit sk_shares

# Custom parameters
cargo run --bin generator -- \
  --circuit pk_trbfv \
  --degree 2048 \
  --plaintext-modulus 1032193 \
  --moduli "18014398492704769" \
  --output-dir my_output
```

### Library Usage

```rust
use pvss_generator::{BfvConfig, GeneratorConfig, generate_all_outputs};

let bfv_config = BfvConfig {
    degree: 2048,
    plaintext_modulus: 1032193,
    moduli: vec![18014398492704769],
};

let generator_config = GeneratorConfig {
    output_dir: "output".into(),
    generate_toml: true,
    circuit: "pk_trbfv".to_string(),
};

let results = generate_all_outputs(bfv_config, generator_config)?;
```

## CLI Options

| Option                | Short | Description                                       | Default             |
| --------------------- | ----- | ------------------------------------------------- | ------------------- |
| `--circuit`           | `-c`  | Target circuit name (pk_trbfv, pk_pvw, sk_shares) | **Required**        |
| `--degree`            | `-d`  | Cyclotomic polynomial degree (power of 2)         | `2048`              |
| `--plaintext-modulus` | `-t`  | Plaintext modulus                                 | `1032193`           |
| `--moduli`            | `-q`  | Ciphertext moduli (comma-separated)               | `18014398492704769` |
| `--output-dir`        | `-o`  | Output directory for generated files              | `output`            |
| `--no-toml`           |       | Skip generating Prover.toml file                  | `false`             |

## Generated Files

### Noir Constants (`constants.nr`)

Generated in the circuit-specific directory (e.g., `output/pk_trbfv/constants.nr`).
Contains BFV parameters, input validation bounds, and per-modulus bounds for constraint checking in Noir circuit format.

### Prover TOML (`Prover.toml`)

Generated in the circuit-specific directory (e.g., `output/pk_trbfv/Prover.toml`).
Contains input validation vectors reduced modulo the BN254 scalar field.

## Library API

### Core Types

- `BfvConfig`: BFV encryption parameters
- `GeneratorConfig`: Output generation settings (includes circuit name and output directory)
- `GenerationResults`: Generated files and computed data
- `InputValidationVectors`: Computed validation vectors
- `InputValidationBounds`: Constraint bounds

### Key Functions

- `generate_all_outputs()`: High-level generation function that routes to circuit-specific functions
- `generate_pk_trbfv_outputs()`: Generation logic for pk_trbfv circuit
- `generate_pk_pvw_outputs()`: Generation logic for pk_pvw circuit
- `generate_sk_shares_outputs()`: Generation logic for sk_shares circuit

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
