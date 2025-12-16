# PVSS Circuit Benchmarks

**Generated:** 2025-12-16 16:47:28 UTC

**Git Branch:** `refactoring`  
**Git Commit:** `92f53c27a8ca0250bb666cc850495ce41710f249`

---

## Summary

### Timing Metrics

| Circuit              | Compile | Execute | Prove  | Verify | Status |
| -------------------- | ------- | ------- | ------ | ------ | ------ |
| dec_bfv              | 0.62 s  | 2.29 s  | 5.74 s | 0.02 s | ✅     |
| dec_shares_agg_trbfv | 0.27 s  | 0.27 s  | 0.13 s | 0.02 s | ✅     |
| dec_share_trbfv      | 0.28 s  | 0.43 s  | 0.53 s | 0.02 s | ✅     |
| enc_bfv              | 0.28 s  | 0.40 s  | 0.51 s | 0.02 s | ✅     |
| enc_trbfv            | 0.30 s  | 0.49 s  | 0.58 s | 0.02 s | ✅     |
| pk_bfv               | 0.27 s  | 0.31 s  | 0.22 s | 0.02 s | ✅     |
| pk_trbfv             | 0.27 s  | 0.36 s  | 0.33 s | 0.03 s | ✅     |
| verify_shares_trbfv  | 0.32 s  | 0.54 s  | 1.58 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit              | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| -------------------- | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv              | 606838  | 1.51M   | 8.93 MB      | 3.75 MB   | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv | 2744    | 9.37K   | 101.27 KB    | 6.50 KB   | 3.59 KB | 15.88 KB   |
| dec_share_trbfv      | 30565   | 83.33K  | 529.79 KB    | 522.39 KB | 3.59 KB | 15.88 KB   |
| enc_bfv              | 33760   | 78.64K  | 558.01 KB    | 447.00 KB | 3.59 KB | 15.88 KB   |
| enc_trbfv            | 56590   | 106.70K | 841.88 KB    | 705.81 KB | 3.59 KB | 15.88 KB   |
| pk_bfv               | 14658   | 29.02K  | 332.44 KB    | 204.15 KB | 3.59 KB | 15.88 KB   |
| pk_trbfv             | 25139   | 44.36K  | 470.45 KB    | 384.16 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv  | 92842   | 335.88K | 1.47 MB      | 463.71 KB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.62 s   |
| **Execution**        | 2.29 s   |
| **VK Generation**    | 2.62 s   |
| **Proof Generation** | 5.74 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 606838   |
| **Total Gates**      | 1512024  |
| **Circuit Size**     | 8.93 MB  |
| **Witness Size**     | 3.75 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.28 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.19 s    |
| **Proof Generation** | 0.53 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 30565     |
| **Total Gates**      | 83326     |
| **Circuit Size**     | 529.79 KB |
| **Witness Size**     | 522.39 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_shares_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.27 s    |
| **Execution**        | 0.27 s    |
| **VK Generation**    | 0.05 s    |
| **Proof Generation** | 0.13 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 2744      |
| **Total Gates**      | 9373      |
| **Circuit Size**     | 101.27 KB |
| **Witness Size**     | 6.50 KB   |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.28 s    |
| **Execution**        | 0.40 s    |
| **VK Generation**    | 0.18 s    |
| **Proof Generation** | 0.51 s    |
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
| **Compilation**      | 0.30 s    |
| **Execution**        | 0.49 s    |
| **VK Generation**    | 0.23 s    |
| **Proof Generation** | 0.58 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 56590     |
| **Total Gates**      | 106699    |
| **Circuit Size**     | 841.88 KB |
| **Witness Size**     | 705.81 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.27 s    |
| **Execution**        | 0.31 s    |
| **VK Generation**    | 0.09 s    |
| **Proof Generation** | 0.22 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 14658     |
| **Total Gates**      | 29019     |
| **Circuit Size**     | 332.44 KB |
| **Witness Size**     | 204.15 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.27 s    |
| **Execution**        | 0.36 s    |
| **VK Generation**    | 0.13 s    |
| **Proof Generation** | 0.33 s    |
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
| **Compilation**      | 0.32 s    |
| **Execution**        | 0.54 s    |
| **VK Generation**    | 0.60 s    |
| **Proof Generation** | 1.58 s    |
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
