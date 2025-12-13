# enc_bfv Recursive Proof Aggregation

Linear recursive proof aggregation for enc_bfv circuit using bb.js and Noir's UltraHonk proving system.

## Overview

Combines 32 enc_bfv proofs into a single cryptographic proof through linear aggregation (31 sequential steps).

```
32 Base Proofs → 31 Aggregation Steps → 1 Final Proof
```

**Status**: ✅ Working (100% success rate, ~5 min total time)

See [BENCHMARK.md](./BENCHMARK.md) for detailed performance metrics.

## Quick Start

### Prerequisites

```bash
# Install dependencies
npm install
```

### Run Aggregation

```bash
npm run generate-proof
```

Generates base proof from `../enc_bfv/Prover.toml` and performs 31 aggregation steps (~5 minutes).

## Project Structure

```
enc_bfv_recursion/
├── src/
│   └── main.nr              # Recursion circuit (verifies 2 proofs)
├── target/
│   └── enc_bfv_recursion.json  # Compiled recursion circuit
├── generate-recursion-proofs.ts # Main TypeScript implementation
├── package.json             # Dependencies & scripts
├── BENCHMARK.md             # Performance metrics
├── recursion_linear_js/     # Generated proofs
│   ├── base/
│   │   └── proof_0.json     # Base enc_bfv proof
│   └── recursive/
│       ├── step_1.json      # First aggregation
│       ├── ...
│       └── step_31.json     # Final aggregated proof
└── README.md               # This file
```

## Implementation

- **Recursion Circuit** (`src/main.nr`): Verifies two child proofs using UltraHonk `verify_ultrahonkzk_proof`
- **TypeScript** (`generate-recursion-proofs.ts`): Linear aggregation using bb.js API
- **Strategy**: Sequential aggregation - step 1 combines proof[0]+proof[1], then each step adds the next proof

## Performance

| Metric | Value |
|--------|-------|
| Total Time | ~5 min 19 sec |
| Base Proof Generation | ~30 sec |
| Per-Step Aggregation | ~10 sec |
| Success Rate | 100% (31/31) |

## Technical Notes

- Uses bb.js 3.0.0-nightly.20251104 with `generateProof()` + `deflattenFields()` API
- VK hash currently simplified (uses `vk[0]`)
- Demo mode: uses same base proof 32 times for testing
- Linear aggregation only (no parallelization)

## References

- [Noir Recursion Guide](https://noir-lang.org/docs/how_to/how-to-recursion)
- [bb.js Documentation](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/ts)
