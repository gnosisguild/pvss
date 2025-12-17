# PVSS Circuit Benchmarks

**Generated:** 2025-12-17 12:24:36 UTC

**Git Branch:** `refactoring`  
**Git Commit:** `40a821c5de5396e4540a2a06e4641f82a0bcac6b`

---

## Summary

### Timing Metrics

| Circuit              | Compile | Execute | Prove   | Verify | Status |
| -------------------- | ------- | ------- | ------- | ------ | ------ |
| dec_bfv              | 0.00 s  | 16.40 s | 23.42 s | 0.02 s | ✅     |
| dec_shares_agg_trbfv | 0.00 s  | 0.29 s  | 0.14 s  | 0.02 s | ✅     |
| dec_share_trbfv      | 0.00 s  | 5.75 s  | 12.15 s | 0.02 s | ✅     |
| enc_bfv              | 0.00 s  | 4.38 s  | 10.59 s | 0.02 s | ✅     |
| enc_trbfv            | 0.00 s  | 8.02 s  | 13.47 s | 0.02 s | ✅     |
| pk_bfv               | 0.00 s  | 2.06 s  | 3.32 s  | 0.02 s | ✅     |
| pk_trbfv             | 0.00 s  | 3.61 s  | 5.94 s  | 0.02 s | ✅     |
| verify_shares_trbfv  | 0.00 s  | 10.01 s | 37.88 s | 0.02 s | ✅     |

### Size & Circuit Metrics

| Circuit              | Opcodes | Gates   | Circuit Size | Witness  | VK Size | Proof Size |
| -------------------- | ------- | ------- | ------------ | -------- | ------- | ---------- |
| dec_bfv              | 2317214 | 7.42M   | 36.55 MB     | 19.62 MB | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv | 5203    | 15.56K  | 419.89 KB    | 14.58 KB | 3.59 KB | 15.88 KB   |
| dec_share_trbfv      | 1012100 | 3.48M   | 12.98 MB     | 19.31 MB | 3.59 KB | 15.88 KB   |
| enc_bfv              | 938886  | 2.63M   | 11.62 MB     | 13.65 MB | 3.59 KB | 15.88 KB   |
| enc_trbfv            | 1684299 | 4.09M   | 20.74 MB     | 24.11 MB | 3.59 KB | 15.88 KB   |
| pk_bfv               | 406776  | 794.71K | 5.21 MB      | 6.44 MB  | 3.59 KB | 15.88 KB   |
| pk_trbfv             | 743498  | 1.40M   | 9.47 MB      | 12.46 MB | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv  | 2938197 | 11.02M  | 42.27 MB     | 15.38 MB | 3.59 KB | 15.88 KB   |

## Circuit Details

### dec_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 16.40 s  |
| **VK Generation**    | 11.14 s  |
| **Proof Generation** | 23.42 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 2317214  |
| **Total Gates**      | 7424336  |
| **Circuit Size**     | 36.55 MB |
| **Witness Size**     | 19.62 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 5.75 s   |
| **VK Generation**    | 5.18 s   |
| **Proof Generation** | 12.15 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 1012100  |
| **Total Gates**      | 3478813  |
| **Circuit Size**     | 12.98 MB |
| **Witness Size**     | 19.31 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_shares_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.00 s    |
| **Execution**        | 0.29 s    |
| **VK Generation**    | 0.07 s    |
| **Proof Generation** | 0.14 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 5203      |
| **Total Gates**      | 15563     |
| **Circuit Size**     | 419.89 KB |
| **Witness Size**     | 14.58 KB  |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### enc_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 4.38 s   |
| **VK Generation**    | 4.08 s   |
| **Proof Generation** | 10.59 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 938886   |
| **Total Gates**      | 2632029  |
| **Circuit Size**     | 11.62 MB |
| **Witness Size**     | 13.65 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### enc_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 8.02 s   |
| **VK Generation**    | 6.35 s   |
| **Proof Generation** | 13.47 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 1684299  |
| **Total Gates**      | 4088067  |
| **Circuit Size**     | 20.74 MB |
| **Witness Size**     | 24.11 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### pk_bfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 2.06 s   |
| **VK Generation**    | 1.38 s   |
| **Proof Generation** | 3.32 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 406776   |
| **Total Gates**      | 794711   |
| **Circuit Size**     | 5.21 MB  |
| **Witness Size**     | 6.44 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### pk_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 3.61 s   |
| **VK Generation**    | 2.49 s   |
| **Proof Generation** | 5.94 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 743498   |
| **Total Gates**      | 1403258  |
| **Circuit Size**     | 9.47 MB  |
| **Witness Size**     | 12.46 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### verify_shares_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 0.00 s   |
| **Execution**        | 10.01 s  |
| **VK Generation**    | 15.80 s  |
| **Proof Generation** | 37.88 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 2938197  |
| **Total Gates**      | 11023142 |
| **Circuit Size**     | 42.27 MB |
| **Witness Size**     | 15.38 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

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
