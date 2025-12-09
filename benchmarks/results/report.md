# PVSS Circuit Benchmarks

**Generated:** 2025-12-09 15:24:46 UTC

**Git Branch:** `dummy-parameters`  
**Git Commit:** `0f9d959eaddfbed16d09e3d9d721722929430b04`

---

## Summary

### Timing Metrics

| Circuit | Compile | Execute | Prove | Verify | Status |
|---------|---------|---------|-------|--------|--------|
| dec_bfv_no_hom_add | 41.39 s | 2.38 s | 5.83 s | 0.02 s | ✅ |
| dec_share_agg_trbfv | 0.27 s | 0.25 s | 0.13 s | 0.02 s | ✅ |
| dec_share_trbfv | 1.38 s | 0.38 s | 0.52 s | 0.02 s | ✅ |
| enc_bfv | 1.27 s | 0.38 s | 0.51 s | 0.02 s | ✅ |
| enc_trbfv | 1.96 s | 0.47 s | 0.57 s | 0.02 s | ✅ |
| pk_bfv | 0.63 s | 0.29 s | 0.22 s | 0.02 s | ✅ |
| pk_trbfv | 0.94 s | 0.34 s | 0.33 s | 0.02 s | ✅ |
| sk_share_2 | 5.63 s | 0.50 s | 1.56 s | 0.02 s | ✅ |

### Size & Circuit Metrics

| Circuit | Opcodes | Gates | Circuit Size | Witness | VK Size | Proof Size |
|---------|---------|-------|--------------|---------|---------|------------|
| dec_bfv_no_hom_add | 632505 | 1.54M | 8.99 MB | 3.94 MB | 3.59 KB | 15.88 KB |
| dec_share_agg_trbfv | 2827 | 9.63K | 74.34 KB | 6.73 KB | 3.59 KB | 15.88 KB |
| dec_share_trbfv | 30567 | 83.33K | 509.29 KB | 522.59 KB | 3.59 KB | 15.88 KB |
| enc_bfv | 33760 | 78.57K | 541.99 KB | 447.20 KB | 3.59 KB | 15.88 KB |
| enc_trbfv | 56591 | 106.63K | 829.87 KB | 705.91 KB | 3.59 KB | 15.88 KB |
| pk_bfv | 14659 | 29.02K | 310.32 KB | 204.07 KB | 3.59 KB | 15.88 KB |
| pk_trbfv | 25141 | 44.36K | 448.77 KB | 384.27 KB | 3.59 KB | 15.88 KB |
| sk_share_2 | 92868 | 339.02K | 1.45 MB | 463.77 KB | 3.59 KB | 15.88 KB |

## Circuit Details

### dec_bfv_no_hom_add

| Metric | Value |
|--------|-------|
| **Compilation** | 41.39 s |
| **Execution** | 2.38 s |
| **VK Generation** | 2.66 s |
| **Proof Generation** | 5.83 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 632505 |
| **Total Gates** | 1538812 |
| **Circuit Size** | 8.99 MB |
| **Witness Size** | 3.94 MB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### dec_share_agg_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 0.27 s |
| **Execution** | 0.25 s |
| **VK Generation** | 0.05 s |
| **Proof Generation** | 0.13 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 2827 |
| **Total Gates** | 9634 |
| **Circuit Size** | 74.34 KB |
| **Witness Size** | 6.73 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### dec_share_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 1.38 s |
| **Execution** | 0.38 s |
| **VK Generation** | 0.19 s |
| **Proof Generation** | 0.52 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 30567 |
| **Total Gates** | 83328 |
| **Circuit Size** | 509.29 KB |
| **Witness Size** | 522.59 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### enc_bfv

| Metric | Value |
|--------|-------|
| **Compilation** | 1.27 s |
| **Execution** | 0.38 s |
| **VK Generation** | 0.18 s |
| **Proof Generation** | 0.51 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 33760 |
| **Total Gates** | 78568 |
| **Circuit Size** | 541.99 KB |
| **Witness Size** | 447.20 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### enc_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 1.96 s |
| **Execution** | 0.47 s |
| **VK Generation** | 0.23 s |
| **Proof Generation** | 0.57 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 56591 |
| **Total Gates** | 106631 |
| **Circuit Size** | 829.87 KB |
| **Witness Size** | 705.91 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### pk_bfv

| Metric | Value |
|--------|-------|
| **Compilation** | 0.63 s |
| **Execution** | 0.29 s |
| **VK Generation** | 0.09 s |
| **Proof Generation** | 0.22 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 14659 |
| **Total Gates** | 29020 |
| **Circuit Size** | 310.32 KB |
| **Witness Size** | 204.07 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### pk_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 0.94 s |
| **Execution** | 0.34 s |
| **VK Generation** | 0.12 s |
| **Proof Generation** | 0.33 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 25141 |
| **Total Gates** | 44361 |
| **Circuit Size** | 448.77 KB |
| **Witness Size** | 384.27 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

### sk_share_2

| Metric | Value |
|--------|-------|
| **Compilation** | 5.63 s |
| **Execution** | 0.50 s |
| **VK Generation** | 0.60 s |
| **Proof Generation** | 1.56 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 92868 |
| **Total Gates** | 339024 |
| **Circuit Size** | 1.45 MB |
| **Witness Size** | 463.77 KB |
| **VK Size** | 3.59 KB |
| **Proof Size** | 15.88 KB |

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

