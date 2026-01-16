# PVSS Circuit Benchmarks

**Generated:** 2026-01-13 14:03:42 UTC

**Git Branch:** `connect-circuits`  
**Git Commit:** `6f18a4acc6ada8f26162204d7bae7728ef459de8`

---

## Summary

### Timing Metrics

| Circuit                  | Compile | Execute | Prove  | Verify | Status |
| ------------------------ | ------- | ------- | ------ | ------ | ------ |
| dec_bfv_e_sm             | 0.25 s  | 0.28 s  | 0.31 s | 0.02 s | ✅     |
| dec_bfv_sk               | 0.25 s  | 0.28 s  | 0.30 s | 0.02 s | ✅     |
| dec_shares_agg_trbfv     | 0.52 s  | 0.32 s  | 0.46 s | 0.02 s | ✅     |
| dec_share_trbfv          | 1.51 s  | 0.41 s  | 0.61 s | 0.02 s | ✅     |
| enc_bfv_e_sm             | 1.95 s  | 0.43 s  | 0.84 s | 0.02 s | ✅     |
| enc_bfv_sk               | 1.93 s  | 0.43 s  | 0.83 s | 0.02 s | ✅     |
| greco                    | 1.87 s  | 0.47 s  | 0.57 s | 0.02 s | ✅     |
| pk_agg_trbfv             | 1.41 s  | 0.43 s  | 0.88 s | 0.02 s | ✅     |
| pk_bfv                   | 0.24 s  | 0.25 s  | 0.12 s | 0.03 s | ✅     |
| pk_trbfv                 | 1.10 s  | 0.36 s  | 0.35 s | 0.02 s | ✅     |
| verify_shares_trbfv_e_sm | 2.68 s  | 0.52 s  | 1.59 s | 0.02 s | ✅     |
| verify_shares_trbfv_sk   | 2.49 s  | 0.50 s  | 1.55 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit                  | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| ------------------------ | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv_e_sm             | 2076    | 34.73K  | 159.01 KB    | 139.99 KB | 3.59 KB | 15.88 KB   |
| dec_bfv_sk               | 2076    | 34.73K  | 159.01 KB    | 139.97 KB | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv     | 31544   | 80.18K  | 504.70 KB    | 77.07 KB  | 3.59 KB | 15.88 KB   |
| dec_share_trbfv          | 32836   | 125.96K | 577.54 KB    | 605.47 KB | 3.59 KB | 15.88 KB   |
| enc_bfv_e_sm             | 48327   | 137.59K | 801.19 KB    | 532.48 KB | 3.59 KB | 15.88 KB   |
| enc_bfv_sk               | 48327   | 137.59K | 801.19 KB    | 532.53 KB | 3.59 KB | 15.88 KB   |
| greco                    | 56590   | 106.70K | 846.47 KB    | 706.04 KB | 3.59 KB | 15.88 KB   |
| pk_agg_trbfv             | 47818   | 169.89K | 881.00 KB    | 360.79 KB | 3.59 KB | 15.88 KB   |
| pk_bfv                   | 344     | 6.85K   | 86.76 KB     | 29.08 KB  | 3.59 KB | 15.88 KB   |
| pk_trbfv                 | 27726   | 57.95K  | 517.44 KB    | 422.78 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv_e_sm | 90874   | 339.88K | 1.48 MB      | 472.32 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv_sk   | 90827   | 338.98K | 1.47 MB      | 465.50 KB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv_e_sm

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.25 s    |
| **Execution**        | 0.28 s    |
| **VK Generation**    | 0.10 s    |
| **Proof Generation** | 0.31 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 2076      |
| **Total Gates**      | 34728     |
| **Circuit Size**     | 159.01 KB |
| **Witness Size**     | 139.99 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_bfv_sk

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.25 s    |
| **Execution**        | 0.28 s    |
| **VK Generation**    | 0.10 s    |
| **Proof Generation** | 0.30 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 2076      |
| **Total Gates**      | 34728     |
| **Circuit Size**     | 159.01 KB |
| **Witness Size**     | 139.97 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_share_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.51 s    |
| **Execution**        | 0.41 s    |
| **VK Generation**    | 0.23 s    |
| **Proof Generation** | 0.61 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 32836     |
| **Total Gates**      | 125960    |
| **Circuit Size**     | 577.54 KB |
| **Witness Size**     | 605.47 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_shares_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.52 s    |
| **Execution**        | 0.32 s    |
| **VK Generation**    | 0.18 s    |
| **Proof Generation** | 0.46 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 31544     |
| **Total Gates**      | 80177     |
| **Circuit Size**     | 504.70 KB |
| **Witness Size**     | 77.07 KB  |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_bfv_e_sm

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.95 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.28 s    |
| **Proof Generation** | 0.84 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 48327     |
| **Total Gates**      | 137585    |
| **Circuit Size**     | 801.19 KB |
| **Witness Size**     | 532.48 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_bfv_sk

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.93 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.28 s    |
| **Proof Generation** | 0.83 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 48327     |
| **Total Gates**      | 137585    |
| **Circuit Size**     | 801.19 KB |
| **Witness Size**     | 532.53 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### greco

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.87 s    |
| **Execution**        | 0.47 s    |
| **VK Generation**    | 0.22 s    |
| **Proof Generation** | 0.57 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 56590     |
| **Total Gates**      | 106699    |
| **Circuit Size**     | 846.47 KB |
| **Witness Size**     | 706.04 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.41 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.34 s    |
| **Proof Generation** | 0.88 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 47818     |
| **Total Gates**      | 169886    |
| **Circuit Size**     | 881.00 KB |
| **Witness Size**     | 360.79 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.24 s   |
| **Execution**        | 0.25 s   |
| **VK Generation**    | 0.05 s   |
| **Proof Generation** | 0.12 s   |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 344      |
| **Total Gates**      | 6846     |
| **Circuit Size**     | 86.76 KB |
| **Witness Size**     | 29.08 KB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### pk_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.10 s    |
| **Execution**        | 0.36 s    |
| **VK Generation**    | 0.14 s    |
| **Proof Generation** | 0.35 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 27726     |
| **Total Gates**      | 57945     |
| **Circuit Size**     | 517.44 KB |
| **Witness Size**     | 422.78 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### verify_shares_trbfv_e_sm

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 2.68 s    |
| **Execution**        | 0.52 s    |
| **VK Generation**    | 0.60 s    |
| **Proof Generation** | 1.59 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 90874     |
| **Total Gates**      | 339878    |
| **Circuit Size**     | 1.48 MB   |
| **Witness Size**     | 472.32 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### verify_shares_trbfv_sk

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 2.49 s    |
| **Execution**        | 0.50 s    |
| **VK Generation**    | 0.59 s    |
| **Proof Generation** | 1.55 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 90827     |
| **Total Gates**      | 338979    |
| **Circuit Size**     | 1.47 MB   |
| **Witness Size**     | 465.50 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

## System Information

### Hardware

- **CPU:** Apple M4 Pro
- **CPU Cores:** 14
- **RAM:** 48.00 GB
- **OS:** Darwin
- **Architecture:** arm64

### Software

- **Nargo Version:** nargo version = 1.0.0-beta.16 noirc version = 1.0.0-beta.16+2d46fca7203545cbbfb31a0d0328de6c10a8db95 (git version hash: 2d46fca7203545cbbfb31a0d0328de6c10a8db95, is dirty: false)
- **Barretenberg Version:** 3.0.0-nightly.20251104
