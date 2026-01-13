# PVSS Circuit Benchmarks

**Generated:** 2026-01-13 14:59:07 UTC

**Git Branch:** `connect-circuits`  
**Git Commit:** `6f18a4acc6ada8f26162204d7bae7728ef459de8`

---

## Summary

### Timing Metrics

| Circuit                  | Compile  | Execute | Prove   | Verify | Status |
| ------------------------ | -------- | ------- | ------- | ------ | ------ |
| dec_bfv                  | 0.00 s   | 16.40 s | 23.42 s | 0.02 s | ✅     |
| dec_bfv_e_sm             | 44.06 s  | 1.83 s  | 5.57 s  | 0.02 s | ✅     |
| dec_bfv_sk               | 44.45 s  | 1.85 s  | 5.58 s  | 0.02 s | ✅     |
| dec_shares_agg_trbfv     | 0.30 s   | 0.54 s  | 0.80 s  | 0.02 s | ✅     |
| dec_share_trbfv          | 545.48 s | 6.18 s  | 20.34 s | 0.02 s | ✅     |
| enc_bfv                  | 0.00 s   | 4.38 s  | 10.59 s | 0.02 s | ✅     |
| enc_bfv_e_sm             | 589.90 s | 5.19 s  | 12.25 s | 0.03 s | ✅     |
| enc_bfv_sk               | 598.80 s | 5.24 s  | 12.20 s | 0.03 s | ✅     |
| enc_trbfv                | 0.00 s   | 8.02 s  | 13.47 s | 0.02 s | ✅     |
| greco                    | 424.38 s | 7.83 s  | 14.10 s | 0.02 s | ✅     |
| pk_agg_trbfv             | 138.46 s | 7.46 s  | 21.59 s | 0.02 s | ✅     |
| pk_bfv                   | 16.04 s  | 0.51 s  | 1.56 s  | 0.02 s | ✅     |
| pk_trbfv                 | 147.82 s | 4.10 s  | 10.31 s | 0.02 s | ✅     |
| verify_shares_trbfv      | 0.00 s   | 10.01 s | 37.88 s | 0.02 s | ✅     |
| verify_shares_trbfv_e_sm | 180.62 s | 9.86 s  | 38.62 s | 0.02 s | ✅     |
| verify_shares_trbfv_sk   | 155.99 s | 9.64 s  | 38.94 s | 0.03 s | ✅     |

### Size & Circuit Metrics

| Circuit                  | Opcodes | Gates   | Circuit Size | Witness   | VK Size | Proof Size |
| ------------------------ | ------- | ------- | ------------ | --------- | ------- | ---------- |
| dec_bfv                  | 2317214 | 7.42M   | 36.55 MB     | 19.62 MB  | 3.59 KB | 15.88 KB   |
| dec_bfv_e_sm             | 81950   | 1.33M   | 2.65 MB      | 5.57 MB   | 3.59 KB | 15.88 KB   |
| dec_bfv_sk               | 81950   | 1.33M   | 2.65 MB      | 5.57 MB   | 3.59 KB | 15.88 KB   |
| dec_shares_agg_trbfv     | 58528   | 147.11K | 1.18 MB      | 183.43 KB | 3.59 KB | 15.88 KB   |
| dec_share_trbfv          | 1077634 | 4.71M   | 13.97 MB     | 21.60 MB  | 3.59 KB | 15.88 KB   |
| enc_bfv                  | 938886  | 2.63M   | 11.62 MB     | 13.65 MB  | 3.59 KB | 15.88 KB   |
| enc_bfv_e_sm             | 1170998 | 3.56M   | 14.66 MB     | 14.91 MB  | 3.59 KB | 15.88 KB   |
| enc_bfv_sk               | 1170998 | 3.56M   | 14.66 MB     | 14.91 MB  | 3.59 KB | 15.88 KB   |
| enc_trbfv                | 1684299 | 4.09M   | 20.74 MB     | 24.11 MB  | 3.59 KB | 15.88 KB   |
| greco                    | 1684299 | 4.09M   | 20.75 MB     | 24.11 MB  | 3.59 KB | 15.88 KB   |
| pk_agg_trbfv             | 1572876 | 6.13M   | 23.78 MB     | 14.84 MB  | 3.59 KB | 15.88 KB   |
| pk_bfv                   | 14568   | 287.76K | 496.92 KB    | 1.08 MB   | 3.59 KB | 15.88 KB   |
| pk_trbfv                 | 809046  | 2.20M   | 10.59 MB     | 14.39 MB  | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv      | 2938197 | 11.02M  | 42.27 MB     | 15.38 MB  | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv_e_sm | 2916373 | 11.33M  | 42.31 MB     | 16.25 MB  | 3.59 KB | 15.88 KB   |
| verify_shares_trbfv_sk   | 2905804 | 11.14M  | 42.19 MB     | 15.42 MB  | 3.59 KB | 15.88 KB   |

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

### dec_bfv_e_sm

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 44.06 s  |
| **Execution**        | 1.83 s   |
| **VK Generation**    | 1.90 s   |
| **Proof Generation** | 5.57 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 81950    |
| **Total Gates**      | 1327673  |
| **Circuit Size**     | 2.65 MB  |
| **Witness Size**     | 5.57 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_bfv_sk

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 44.45 s  |
| **Execution**        | 1.85 s   |
| **VK Generation**    | 1.92 s   |
| **Proof Generation** | 5.58 s   |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 81950    |
| **Total Gates**      | 1327673  |
| **Circuit Size**     | 2.65 MB  |
| **Witness Size**     | 5.57 MB  |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_share_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 545.48 s |
| **Execution**        | 6.18 s   |
| **VK Generation**    | 7.06 s   |
| **Proof Generation** | 20.34 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 1077634  |
| **Total Gates**      | 4707684  |
| **Circuit Size**     | 13.97 MB |
| **Witness Size**     | 21.60 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### dec_shares_agg_trbfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 0.30 s    |
| **Execution**        | 0.54 s    |
| **VK Generation**    | 0.30 s    |
| **Proof Generation** | 0.80 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 58528     |
| **Total Gates**      | 147112    |
| **Circuit Size**     | 1.18 MB   |
| **Witness Size**     | 183.43 KB |
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

### enc_bfv_e_sm

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 589.90 s |
| **Execution**        | 5.19 s   |
| **VK Generation**    | 5.50 s   |
| **Proof Generation** | 12.25 s  |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 1170998  |
| **Total Gates**      | 3558505  |
| **Circuit Size**     | 14.66 MB |
| **Witness Size**     | 14.91 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### enc_bfv_sk

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 598.80 s |
| **Execution**        | 5.24 s   |
| **VK Generation**    | 5.51 s   |
| **Proof Generation** | 12.20 s  |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 1170998  |
| **Total Gates**      | 3558505  |
| **Circuit Size**     | 14.66 MB |
| **Witness Size**     | 14.91 MB |
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

### greco

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 424.38 s |
| **Execution**        | 7.83 s   |
| **VK Generation**    | 6.65 s   |
| **Proof Generation** | 14.10 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 1684299  |
| **Total Gates**      | 4088067  |
| **Circuit Size**     | 20.75 MB |
| **Witness Size**     | 24.11 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### pk_agg_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 138.46 s |
| **Execution**        | 7.46 s   |
| **VK Generation**    | 9.21 s   |
| **Proof Generation** | 21.59 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 1572876  |
| **Total Gates**      | 6130706  |
| **Circuit Size**     | 23.78 MB |
| **Witness Size**     | 14.84 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### pk_bfv

| Metric               | Value     |
| -------------------- | --------- |
| **Compilation**      | 16.04 s   |
| **Execution**        | 0.51 s    |
| **VK Generation**    | 0.45 s    |
| **Proof Generation** | 1.56 s    |
| **Verification**     | 0.02 s    |
| **ACIR Opcodes**     | 14568     |
| **Total Gates**      | 287763    |
| **Circuit Size**     | 496.92 KB |
| **Witness Size**     | 1.08 MB   |
| **VK Size**          | 3.59 KB   |
| **Proof Size**       | 15.88 KB  |

### pk_trbfv

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 147.82 s |
| **Execution**        | 4.10 s   |
| **VK Generation**    | 3.78 s   |
| **Proof Generation** | 10.31 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 809046   |
| **Total Gates**      | 2198125  |
| **Circuit Size**     | 10.59 MB |
| **Witness Size**     | 14.39 MB |
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

### verify_shares_trbfv_e_sm

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 180.62 s |
| **Execution**        | 9.86 s   |
| **VK Generation**    | 16.39 s  |
| **Proof Generation** | 38.62 s  |
| **Verification**     | 0.02 s   |
| **ACIR Opcodes**     | 2916373  |
| **Total Gates**      | 11334982 |
| **Circuit Size**     | 42.31 MB |
| **Witness Size**     | 16.25 MB |
| **VK Size**          | 3.59 KB  |
| **Proof Size**       | 15.88 KB |

### verify_shares_trbfv_sk

| Metric               | Value    |
| -------------------- | -------- |
| **Compilation**      | 155.99 s |
| **Execution**        | 9.64 s   |
| **VK Generation**    | 16.31 s  |
| **Proof Generation** | 38.94 s  |
| **Verification**     | 0.03 s   |
| **ACIR Opcodes**     | 2905804  |
| **Total Gates**      | 11136831 |
| **Circuit Size**     | 42.19 MB |
| **Witness Size**     | 15.42 MB |
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
