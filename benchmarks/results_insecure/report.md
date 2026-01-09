# PVSS Circuit Benchmarks

**Generated:** 2025-12-23 11:07:57 UTC

**Git Branch:** `connect-circuits`  
**Git Commit:** `6344438a2bba0b63981fe97ff5919d838b21ae98`

---

## Summary

### Timing Metrics

| Circuit              | Compile | Execute | Prove  | Verify | Status |
| -------------------- | ------- | ------- | ------ | ------ | ------ |
| dec_bfv              | 0.60 s  | 2.21 s  | 5.84 s | 0.02 s | ✅     |
| dec_shares_agg_trbfv | 0.26 s  | 0.27 s  | 0.14 s | 0.02 s | ✅     |
| dec_share_trbfv      | 0.28 s  | 0.42 s  | 0.64 s | 0.02 s | ✅     |
| enc_bfv              | 0.29 s  | 0.43 s  | 0.82 s | 0.02 s | ✅     |
| enc_trbfv            | 0.29 s  | 0.48 s  | 0.57 s | 0.02 s | ✅     |
| pk_agg_trbfv         | 0.92 s  | 0.42 s  | 0.55 s | 0.02 s | ✅     |
| pk_bfv               | 0.26 s  | 0.31 s  | 0.23 s | 0.02 s | ✅     |
| pk_trbfv             | 0.27 s  | 0.35 s  | 0.33 s | 0.02 s | ✅     |
| verify_shares_trbfv  | 0.32 s  | 0.56 s  | 1.53 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit              | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| -------------------- | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv              | 603086  | 1.53M   | 8.92 MB      | 3.76 MB   | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv | 2744    | 9.37K   | 93.84 KB     | 6.51 KB   | 3.59 KB | 15.88 KB   |
| dec_share_trbfv      | 32836   | 125.96K | 568.14 KB    | 605.43 KB | 3.59 KB | 15.88 KB   |
| enc_bfv              | 48324   | 136.88K | 790.60 KB    | 532.61 KB | 3.59 KB | 15.88 KB   |
| enc_trbfv            | 56590   | 106.70K | 836.46 KB    | 706.73 KB | 3.59 KB | 15.88 KB   |
| pk_agg_trbfv         | 45517   | 120.24K | 790.17 KB    | 226.23 KB | 3.59 KB | 15.88 KB   |
| pk_bfv               | 14662   | 29.09K  | 325.72 KB    | 204.32 KB | 3.59 KB | 15.88 KB   |
| pk_trbfv             | 25142   | 44.36K  | 463.89 KB    | 384.28 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv  | 92875   | 336.94K | 1.49 MB      | 467.35 KB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.60 s   |
| **Execution**        | 2.21 s   |
| **VK Generation**    | 2.62 s   |
| **Proof Generation** | 5.84 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 603086   |
| **Total Gates**      | 1532968  |
| **Circuit Size**     | 8.92 MB  |
| **Witness Size**     | 3.76 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.28 s    |
| **Execution**        | 0.42 s    |
| **VK Generation**    | 0.23 s    |
| **Proof Generation** | 0.64 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 32836     |
| **Total Gates**      | 125960    |
| **Circuit Size**     | 568.14 KB |
| **Witness Size**     | 605.43 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_shares_agg_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.26 s   |
| **Execution**        | 0.27 s   |
| **VK Generation**    | 0.05 s   |
| **Proof Generation** | 0.14 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 2744     |
| **Total Gates**      | 9373     |
| **Circuit Size**     | 93.84 KB |
| **Witness Size**     | 6.51 KB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### enc_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.29 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.27 s    |
| **Proof Generation** | 0.82 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 48324     |
| **Total Gates**      | 136876    |
| **Circuit Size**     | 790.60 KB |
| **Witness Size**     | 532.61 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.29 s    |
| **Execution**        | 0.48 s    |
| **VK Generation**    | 0.22 s    |
| **Proof Generation** | 0.57 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 56590     |
| **Total Gates**      | 106699    |
| **Circuit Size**     | 836.46 KB |
| **Witness Size**     | 706.73 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.92 s    |
| **Execution**        | 0.42 s    |
| **VK Generation**    | 0.24 s    |
| **Proof Generation** | 0.55 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 45517     |
| **Total Gates**      | 120244    |
| **Circuit Size**     | 790.17 KB |
| **Witness Size**     | 226.23 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.26 s    |
| **Execution**        | 0.31 s    |
| **VK Generation**    | 0.09 s    |
| **Proof Generation** | 0.23 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 14662     |
| **Total Gates**      | 29095     |
| **Circuit Size**     | 325.72 KB |
| **Witness Size**     | 204.32 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.27 s    |
| **Execution**        | 0.35 s    |
| **VK Generation**    | 0.13 s    |
| **Proof Generation** | 0.33 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 25142     |
| **Total Gates**      | 44362     |
| **Circuit Size**     | 463.89 KB |
| **Witness Size**     | 384.28 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### verify_shares_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.32 s    |
| **Execution**        | 0.56 s    |
| **VK Generation**    | 0.63 s    |
| **Proof Generation** | 1.53 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 92875     |
| **Total Gates**      | 336936    |
| **Circuit Size**     | 1.49 MB   |
| **Witness Size**     | 467.35 KB |
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
