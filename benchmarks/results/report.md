# PVSS Circuit Benchmarks

**Generated:** 2025-11-10 18:51:54 UTC

**Git Branch:** `benchmarks`  
**Git Commit:** `b8b1108405ab7b1c066d35ac73873a6c6ed09f4f`

---

## Summary

### Timing Metrics

| Circuit | Oracle | Compile | Execute | Prove | Verify | Status |
|---------|--------|---------|---------|-------|--------|--------|
| dec_share_trbfv | default | 652643.57 ms | 5664.84 ms | 12816.91 ms | 15.34 ms | ✅ |
| dec_share_trbfv | keccak | 656963.87 ms | 5665.63 ms | 12942.01 ms | 14.97 ms | ✅ |
| enc_bfv | default | 364779.46 ms | 4621.93 ms | 11160.73 ms | 15.11 ms | ✅ |
| enc_bfv | keccak | 361006.71 ms | 4642.56 ms | 11173.06 ms | 14.90 ms | ✅ |
| enc_trbfv | default | 1051498.32 ms | 8268.12 ms | 20669.09 ms | 19.83 ms | ✅ |
| enc_trbfv | keccak | 1054622.83 ms | 8406.92 ms | 20575.38 ms | 25.15 ms | ✅ |
| pk_bfv | default | 38138.53 ms | 2154.64 ms | 3459.78 ms | 14.76 ms | ✅ |
| pk_bfv | keccak | 37368.73 ms | 2161.16 ms | 3462.52 ms | 15.09 ms | ✅ |
| pk_trbfv | default | 89335.79 ms | 3945.10 ms | 6622.76 ms | 15.91 ms | ✅ |
| pk_trbfv | keccak | 90633.23 ms | 4121.73 ms | 6754.37 ms | 16.72 ms | ✅ |

### Size & Circuit Metrics

| Circuit | Oracle | Opcodes | Gates | Circuit Size | Witness | VK Size | Proof Size |
|---------|--------|---------|-------|--------------|---------|---------|------------|
| dec_share_trbfv | default | 1012169 | 3.63M | 13.63 MB | 23.14 MB | 1.72 KB | 14.25 KB |
| dec_share_trbfv | keccak | 1012169 | 3.63M | 13.63 MB | 23.14 MB | 1.72 KB | 14.25 KB |
| enc_bfv | default | 927847 | 2.81M | 12.05 MB | 16.39 MB | 1.72 KB | 14.25 KB |
| enc_bfv | keccak | 927847 | 2.81M | 12.05 MB | 16.39 MB | 1.72 KB | 14.25 KB |
| enc_trbfv | default | 1680929 | 5.18M | 21.81 MB | 29.44 MB | 1.72 KB | 14.25 KB |
| enc_trbfv | keccak | 1680929 | 5.18M | 21.81 MB | 29.44 MB | 1.72 KB | 14.25 KB |
| pk_bfv | default | 406845 | 816.16K | 5.46 MB | 7.58 MB | 1.72 KB | 14.25 KB |
| pk_bfv | keccak | 406845 | 816.16K | 5.46 MB | 7.58 MB | 1.72 KB | 14.25 KB |
| pk_trbfv | default | 743569 | 1.45M | 9.95 MB | 14.68 MB | 1.72 KB | 14.25 KB |
| pk_trbfv | keccak | 743569 | 1.45M | 9.95 MB | 14.68 MB | 1.72 KB | 14.25 KB |

## Detailed Comparison by Circuit

### dec_share_trbfv

#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
| Compilation | 652643.57 ms | 656963.87 ms | +0.7% |
| Execution | 5664.84 ms | 5665.63 ms | +0.0% |
| VK Generation | 8704.55 ms | 8737.93 ms | +0.4% |
| Proof Generation | 12816.91 ms | 12942.01 ms | +1.0% |
| Verification | 15.34 ms | 14.97 ms | -2.4% |

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
| Circuit JSON | 13.63 MB | 13.63 MB | +0.0% |
| Witness | 23.14 MB | 23.14 MB | +0.0% |
| Verification Key | 1.72 KB | 1.72 KB | +0.0% |
| Proof | 14.25 KB | 14.25 KB | +0.0% |

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
| Default | 1012169 | 3631029 |
| Keccak | 1012169 | 3631029 |

### enc_bfv

#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
| Compilation | 364779.46 ms | 361006.71 ms | -1.0% |
| Execution | 4621.93 ms | 4642.56 ms | +0.4% |
| VK Generation | 7644.75 ms | 7718.32 ms | +1.0% |
| Proof Generation | 11160.73 ms | 11173.06 ms | +0.1% |
| Verification | 15.11 ms | 14.90 ms | -1.4% |

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
| Circuit JSON | 12.05 MB | 12.05 MB | +0.0% |
| Witness | 16.39 MB | 16.39 MB | +0.0% |
| Verification Key | 1.72 KB | 1.72 KB | +0.0% |
| Proof | 14.25 KB | 14.25 KB | +0.0% |

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
| Default | 927847 | 2812878 |
| Keccak | 927847 | 2812878 |

### enc_trbfv

#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
| Compilation | 1051498.32 ms | 1054622.83 ms | +0.3% |
| Execution | 8268.12 ms | 8406.92 ms | +1.7% |
| VK Generation | 13688.38 ms | 13821.74 ms | +1.0% |
| Proof Generation | 20669.09 ms | 20575.38 ms | -0.5% |
| Verification | 19.83 ms | 25.15 ms | +26.8% |

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
| Circuit JSON | 21.81 MB | 21.81 MB | +0.0% |
| Witness | 29.44 MB | 29.44 MB | +0.0% |
| Verification Key | 1.72 KB | 1.72 KB | +0.0% |
| Proof | 14.25 KB | 14.25 KB | +0.0% |

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
| Default | 1680929 | 5184912 |
| Keccak | 1680929 | 5184912 |

### pk_bfv

#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
| Compilation | 38138.53 ms | 37368.73 ms | -2.0% |
| Execution | 2154.64 ms | 2161.16 ms | +0.3% |
| VK Generation | 2231.25 ms | 2223.75 ms | -0.3% |
| Proof Generation | 3459.78 ms | 3462.52 ms | +0.1% |
| Verification | 14.76 ms | 15.09 ms | +2.3% |

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
| Circuit JSON | 5.46 MB | 5.46 MB | +0.0% |
| Witness | 7.58 MB | 7.58 MB | +0.0% |
| Verification Key | 1.72 KB | 1.72 KB | +0.0% |
| Proof | 14.25 KB | 14.25 KB | +0.0% |

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
| Default | 406845 | 816163 |
| Keccak | 406845 | 816163 |

### pk_trbfv

#### Timing Comparison

| Metric | Default Oracle | Keccak Oracle | Difference |
|--------|----------------|---------------|------------|
| Compilation | 89335.79 ms | 90633.23 ms | +1.5% |
| Execution | 3945.10 ms | 4121.73 ms | +4.5% |
| VK Generation | 4730.41 ms | 4859.66 ms | +2.7% |
| Proof Generation | 6622.76 ms | 6754.37 ms | +2.0% |
| Verification | 15.91 ms | 16.72 ms | +5.1% |

#### Size Comparison

| Artifact | Default Oracle | Keccak Oracle | Difference |
|----------|----------------|---------------|------------|
| Circuit JSON | 9.95 MB | 9.95 MB | +0.0% |
| Witness | 14.68 MB | 14.68 MB | +0.0% |
| Verification Key | 1.72 KB | 1.72 KB | +0.0% |
| Proof | 14.25 KB | 14.25 KB | +0.0% |

#### Gate Count & Opcodes

| Oracle | ACIR Opcodes | Total Gates |
|--------|--------------|-------------|
| Default | 743569 | 1449473 |
| Keccak | 743569 | 1449473 |

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

