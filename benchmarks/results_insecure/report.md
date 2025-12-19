# PVSS Circuit Benchmarks

**Generated:** 2025-12-19 17:02:59 UTC

**Git Branch:** `connect-circuits`  
**Git Commit:** `0589d25d597a8fb2f69d8752299ca89583ae60f7`

---

## Summary

### Timing Metrics

| Circuit              | Compile | Execute | Prove  | Verify | Status |
| -------------------- | ------- | ------- | ------ | ------ | ------ |
| dec_bfv              | 46.05 s | 2.26 s  | 6.09 s | 0.03 s | ✅     |
| dec_shares_agg_trbfv | 0.27 s  | 0.27 s  | 0.13 s | 0.02 s | ✅     |
| dec_share_trbfv      | 2.21 s  | 0.43 s  | 0.62 s | 0.02 s | ✅     |
| enc_bfv              | 1.53 s  | 0.40 s  | 0.55 s | 0.02 s | ✅     |
| enc_trbfv            | 2.12 s  | 0.52 s  | 0.59 s | 0.02 s | ✅     |
| pk_bfv               | 0.65 s  | 0.30 s  | 0.22 s | 0.02 s | ✅     |
| pk_trbfv             | 0.95 s  | 0.36 s  | 0.32 s | 0.02 s | ✅     |
| verify_shares_trbfv  | 2.69 s  | 0.54 s  | 1.60 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit              | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| -------------------- | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv              | 603086  | 1.53M   | 8.92 MB      | 3.76 MB   | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv | 2744    | 9.37K   | 93.65 KB     | 6.48 KB   | 3.59 KB | 15.88 KB   |
| dec_share_trbfv      | 32836   | 125.96K | 568.14 KB    | 605.49 KB | 3.59 KB | 15.88 KB   |
| enc_bfv              | 33932   | 91.05K  | 561.93 KB    | 475.51 KB | 3.59 KB | 15.88 KB   |
| enc_trbfv            | 56590   | 106.70K | 836.46 KB    | 706.28 KB | 3.59 KB | 15.88 KB   |
| pk_bfv               | 14662   | 29.09K  | 325.72 KB    | 204.41 KB | 3.59 KB | 15.88 KB   |
| pk_trbfv             | 25142   | 44.36K  | 463.89 KB    | 384.28 KB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv  | 92875   | 336.94K | 1.49 MB      | 467.27 KB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 46.05 s  |
| **Execution**        | 2.26 s   |
| **VK Generation**    | 2.75 s   |
| **Proof Generation** | 6.09 s   |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 603086   |
| **Total Gates**      | 1532968  |
| **Circuit Size**     | 8.92 MB  |
| **Witness Size**     | 3.76 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 2.21 s    |
| **Execution**        | 0.43 s    |
| **VK Generation**    | 0.24 s    |
| **Proof Generation** | 0.62 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 32836     |
| **Total Gates**      | 125960    |
| **Circuit Size**     | 568.14 KB |
| **Witness Size**     | 605.49 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### dec_shares_agg_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.27 s   |
| **Execution**        | 0.27 s   |
| **VK Generation**    | 0.05 s   |
| **Proof Generation** | 0.13 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 2744     |
| **Total Gates**      | 9373     |
| **Circuit Size**     | 93.65 KB |
| **Witness Size**     | 6.48 KB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### enc_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 1.53 s    |
| **Execution**        | 0.40 s    |
| **VK Generation**    | 0.19 s    |
| **Proof Generation** | 0.55 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 33932     |
| **Total Gates**      | 91051     |
| **Circuit Size**     | 561.93 KB |
| **Witness Size**     | 475.51 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 2.12 s    |
| **Execution**        | 0.52 s    |
| **VK Generation**    | 0.23 s    |
| **Proof Generation** | 0.59 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 56590     |
| **Total Gates**      | 106699    |
| **Circuit Size**     | 836.46 KB |
| **Witness Size**     | 706.28 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.65 s    |
| **Execution**        | 0.30 s    |
| **VK Generation**    | 0.09 s    |
| **Proof Generation** | 0.22 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 14662     |
| **Total Gates**      | 29095     |
| **Circuit Size**     | 325.72 KB |
| **Witness Size**     | 204.41 KB |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.95 s    |
| **Execution**        | 0.36 s    |
| **VK Generation**    | 0.13 s    |
| **Proof Generation** | 0.32 s    |
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
| **Compilation**      | 2.69 s    |
| **Execution**        | 0.54 s    |
| **VK Generation**    | 0.62 s    |
| **Proof Generation** | 1.60 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 92875     |
| **Total Gates**      | 336936    |
| **Circuit Size**     | 1.49 MB   |
| **Witness Size**     | 467.27 KB |
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
