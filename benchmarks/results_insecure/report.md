# PVSS Circuit Benchmarks

**Generated:** 2025-12-16 16:59:52 UTC

**Git Branch:** `refactoring`  
**Git Commit:** `3871d6c687d126b1606f6aaad1565d47c13f9a42`

---

## Summary

### Timing Metrics

| Circuit              | Compile | Execute | Prove  | Verify | Status |
| -------------------- | ------- | ------- | ------ | ------ | ------ |
| dec_bfv              | 46.79 s | 2.51 s  | 6.36 s | 0.03 s | ✅     |
| dec_shares_agg_trbfv | 0.31 s  | 0.30 s  | 0.14 s | 0.02 s | ✅     |
| dec_share_trbfv      | 1.57 s  | 0.45 s  | 0.57 s | 0.03 s | ✅     |
| enc_bfv              | 1.36 s  | 0.41 s  | 0.56 s | 0.02 s | ✅     |
| enc_trbfv            | 2.25 s  | 0.50 s  | 0.60 s | 0.03 s | ✅     |
| pk_bfv               | 0.69 s  | 0.32 s  | 0.24 s | 0.03 s | ✅     |
| pk_trbfv             | 1.01 s  | 0.38 s  | 0.36 s | 0.03 s | ✅     |
| verify_shares_trbfv  | 6.41 s  | 0.59 s  | 1.62 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit              | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| -------------------- | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv              | 606838  | 1.51M   | 8.94 MB      | 3.75 MB   | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv | 2744    | 9.37K   | 101.42 KB    | 6.50 KB   | 3.59 KB | 15.88 KB   |
| dec_share_trbfv      | 30565   | 83.33K  | 529.79 KB    | 522.39 KB | 3.59 KB | 15.88 KB   |
| enc_bfv              | 33760   | 78.64K  | 558.01 KB    | 447.00 KB | 3.59 KB | 15.88 KB   |
| enc_trbfv            | 56590   | 106.70K | 841.87 KB    | 705.81 KB | 3.59 KB | 15.88 KB   |
| pk_bfv               | 14658   | 29.02K  | 332.44 KB    | 204.15 KB | 3.59 KB | 15.88 KB   |
| pk_trbfv             | 25139   | 44.36K  | 470.45 KB    | 384.16 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv  | 92842   | 335.88K | 1.47 MB      | 463.71 KB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 46.79 s  |
| **Execution**        | 2.51 s   |
| **VK Generation**    | 2.83 s   |
| **Proof Generation** | 6.36 s   |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 606838   |
| **Total Gates**      | 1512024  |
| **Circuit Size**     | 8.94 MB  |
| **Witness Size**     | 3.75 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.57 s    |
| **Execution**        | 0.45 s    |
| **VK Generation**    | 0.19 s    |
| **Proof Generation** | 0.57 s    |
| **Verification**     | 0.03 s    |
| **ACIR Opcodes**     | 30565     |
| **Total Gates**      | 83326     |
| **Circuit Size**     | 529.79 KB |
| **Witness Size**     | 522.39 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_shares_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.31 s    |
| **Execution**        | 0.30 s    |
| **VK Generation**    | 0.05 s    |
| **Proof Generation** | 0.14 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 2744      |
| **Total Gates**      | 9373      |
| **Circuit Size**     | 101.42 KB |
| **Witness Size**     | 6.50 KB   |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.36 s    |
| **Execution**        | 0.41 s    |
| **VK Generation**    | 0.19 s    |
| **Proof Generation** | 0.56 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 33760     |
| **Total Gates**      | 78641     |
| **Circuit Size**     | 558.01 KB |
| **Witness Size**     | 447.00 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 2.25 s    |
| **Execution**        | 0.50 s    |
| **VK Generation**    | 0.24 s    |
| **Proof Generation** | 0.60 s    |
| **Verification**     | 0.03 s    |
| **ACIR Opcodes**     | 56590     |
| **Total Gates**      | 106699    |
| **Circuit Size**     | 841.87 KB |
| **Witness Size**     | 705.81 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.69 s    |
| **Execution**        | 0.32 s    |
| **VK Generation**    | 0.09 s    |
| **Proof Generation** | 0.24 s    |
| **Verification**     | 0.03 s    |
| **ACIR Opcodes**     | 14658     |
| **Total Gates**      | 29019     |
| **Circuit Size**     | 332.44 KB |
| **Witness Size**     | 204.15 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.01 s    |
| **Execution**        | 0.38 s    |
| **VK Generation**    | 0.14 s    |
| **Proof Generation** | 0.36 s    |
| **Verification**     | 0.03 s    |
| **ACIR Opcodes**     | 25139     |
| **Total Gates**      | 44359     |
| **Circuit Size**     | 470.45 KB |
| **Witness Size**     | 384.16 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### verify_shares_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 6.41 s    |
| **Execution**        | 0.59 s    |
| **VK Generation**    | 0.63 s    |
| **Proof Generation** | 1.62 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 92842     |
| **Total Gates**      | 335883    |
| **Circuit Size**     | 1.47 MB   |
| **Witness Size**     | 463.71 KB |
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
