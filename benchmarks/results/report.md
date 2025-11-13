# PVSS Circuit Benchmarks

**Generated:** 2025-11-12 16:29:43 UTC

**Git Branch:** `benchmarks`  
**Git Commit:** `ae1a8af6b32279a665f544101cde3059d2300833`

---

## Summary

### Timing Metrics

| Circuit | Compile | Execute | Prove | Verify | Status |
|---------|---------|---------|-------|--------|--------|
| dec_share_trbfv | 663.39 s | 5.70 s | 13.54 s | 0.02 s | ✅ |
| enc_bfv | 392.92 s | 5.13 s | 11.59 s | 0.02 s | ✅ |
| enc_trbfv | 650.82 s | 8.57 s | 19.29 s | 0.02 s | ✅ |
| pk_bfv | 39.56 s | 2.22 s | 3.49 s | 0.02 s | ✅ |
| pk_trbfv | 93.64 s | 4.00 s | 6.62 s | 0.01 s | ✅ |

### Size & Circuit Metrics

| Circuit | Opcodes | Gates | Circuit Size | Witness | VK Size | Proof Size |
|---------|---------|-------|--------------|---------|---------|------------|
| dec_share_trbfv | 1012169 | 3.63M | 13.63 MB | 23.13 MB | 1.72 KB | 14.25 KB |
| enc_bfv | 927119 | 2.80M | 12.04 MB | 16.34 MB | 1.72 KB | 14.25 KB |
| enc_trbfv | 1651809 | 4.22M | 21.35 MB | 28.06 MB | 1.72 KB | 14.25 KB |
| pk_bfv | 406845 | 816.16K | 5.46 MB | 7.58 MB | 1.72 KB | 14.25 KB |
| pk_trbfv | 743569 | 1.45M | 9.95 MB | 14.68 MB | 1.72 KB | 14.25 KB |

## Circuit Details

### dec_share_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 663.39 s |
| **Execution** | 5.70 s |
| **VK Generation** | 8.87 s |
| **Proof Generation** | 13.54 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 1012169 |
| **Total Gates** | 3631029 |
| **Circuit Size** | 13.63 MB |
| **Witness Size** | 23.13 MB |
| **VK Size** | 1.72 KB |
| **Proof Size** | 14.25 KB |

### enc_bfv

| Metric | Value |
|--------|-------|
| **Compilation** | 392.92 s |
| **Execution** | 5.13 s |
| **VK Generation** | 8.07 s |
| **Proof Generation** | 11.59 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 927119 |
| **Total Gates** | 2799406 |
| **Circuit Size** | 12.04 MB |
| **Witness Size** | 16.34 MB |
| **VK Size** | 1.72 KB |
| **Proof Size** | 14.25 KB |

### enc_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 650.82 s |
| **Execution** | 8.57 s |
| **VK Generation** | 13.48 s |
| **Proof Generation** | 19.29 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 1651809 |
| **Total Gates** | 4220240 |
| **Circuit Size** | 21.35 MB |
| **Witness Size** | 28.06 MB |
| **VK Size** | 1.72 KB |
| **Proof Size** | 14.25 KB |

### pk_bfv

| Metric | Value |
|--------|-------|
| **Compilation** | 39.56 s |
| **Execution** | 2.22 s |
| **VK Generation** | 2.26 s |
| **Proof Generation** | 3.49 s |
| **Verification** | 0.02 s |
| **ACIR Opcodes** | 406845 |
| **Total Gates** | 816163 |
| **Circuit Size** | 5.46 MB |
| **Witness Size** | 7.58 MB |
| **VK Size** | 1.72 KB |
| **Proof Size** | 14.25 KB |

### pk_trbfv

| Metric | Value |
|--------|-------|
| **Compilation** | 93.64 s |
| **Execution** | 4.00 s |
| **VK Generation** | 4.77 s |
| **Proof Generation** | 6.62 s |
| **Verification** | 0.01 s |
| **ACIR Opcodes** | 743569 |
| **Total Gates** | 1449473 |
| **Circuit Size** | 9.95 MB |
| **Witness Size** | 14.68 MB |
| **VK Size** | 1.72 KB |
| **Proof Size** | 14.25 KB |

## System Information

### Hardware

- **CPU:** Apple M4 Pro
- **CPU Cores:** 14
- **RAM:** 48.00 GB
- **OS:** Darwin
- **Architecture:** arm64

### Software

- **Nargo Version:** nargo version = 1.0.0-beta.12 noirc version = 1.0.0-beta.12+9a5b3695b42e391fa27c48e87b9bbb07523d664d (git version hash: 9a5b3695b42e391fa27c48e87b9bbb07523d664d, is dirty: false) 
- **Barretenberg Version:** v0.87.0 

