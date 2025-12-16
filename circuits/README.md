# PVSS-TRBFV Circuit Architecture

## Circuit Flow Diagram
```mermaid
flowchart TD
    subgraph C1["Circuit 1: pk-trbfv"]
        C1_pad[ ]
        C1_desc["Verifies TRBFV public key correctness"]
        C1_out["Output: commit(sk_trbfv)"]
       
    end

    subgraph C2["Circuit 2: pk-bfv"]
        C2_pad[ ]
        C2_desc["Verifies BFV public key correctness"]
        C2_out["Output: commit(sk_bfv)"]

    end

    subgraph C3_sk["Circuit 3a: sk-shares(for sk shares)"]
        C3_sk_pad[ ]
        C3_sk_check["Check: commit(sk_trbfv) == expected"]
        C3_sk_out["Output: commit(sk_share[i][j])<br/>for each party i, modulus j"]

    end

    subgraph C3_e["Circuit 3b: sk-shares (for e_sm shares)"]
        C3_e_pad[ ]
        C3_e_check["Check: commit(e_sm) == expected"]
        C3_e_out["Output: commit(e_sm_share[i][j])<br/>for each party i, modulus j"]
       
    end

    subgraph C4_sk["Circuit 4a: enc-bfv (encrypt sk shares)"]
        C4_sk_pad[ ]
        C4_sk_check["Check: commit(message) == commit(sk_share[i][j])"]
        C4_sk_desc["Verifies BFV encryption of sk shares"]
       
    end

    subgraph C4_e["Circuit 4b: enc-bfv (encrypt e_sm shares)"]
        C4_e_pad[ ]
        C4_e_check["Check: commit(message) == commit(e_sm_share[i][j])"]
        C4_e_desc["Verifies BFV encryption of e_sm shares"]
      
    end

    subgraph C5_sk["Circuit 5a: dec-bfv (decrypt sk shares)"]
        C5_sk_pad[ ]
        C5_sk_check["Check: commit(sk_bfv) == expected"]
        C5_sk_out["Output: commit(aggregated_sk_shares)"]
        
    end

    subgraph C5_e["Circuit 5b: dec-bfv (decrypt e_sm shares)"]
        C5_e_pad[ ]
        C5_e_check["Check: commit(sk_bfv) == expected"]
        C5_e_out["Output: commit(aggregated_e_sm_shares)"]
       
    end

    subgraph C7["Circuit 7: dec-share-trbfv"]
        C7_pad[ ]
        C7_check["Check: commit(s) == commit(aggregated_sk_shares)<br/>Check: commit(e) == commit(aggregated_e_sm_shares)"]
        C7_desc["Verifies d = c_0 + c_1 * s + e"]
       
    end

    subgraph C8["Circuit 8: dec-result-trbfv"]
        C8_pad[ ]
        C8_desc["Takes decryption_shares directly as input<br/>No commitment checks"]
        C8_out["Output: decrypted message"]
      
    end

    C1 -->|"commit(sk_trbfv)"| C3_sk
    input(("?"))-->|"commit(e_sm)"| C3_e
    C2 -->|"commit(sk_bfv)"| C5_sk
    C2 -->|"commit(sk_bfv)"| C5_e
    C3_sk -->|"commit(sk_share[i][j])"| C4_sk
    C3_e -->|"commit(e_sm_share[i][j])"| C4_e
    C5_sk -->|"commit(aggregated_sk_shares)"| C7
    C5_e -->|"commit(aggregated_e_sm_shares)"| C7
    C7 -->|"d (public)"| C8

    style C1_pad fill:none,stroke:none,color:transparent
    style C2_pad fill:none,stroke:none,color:transparent
    style C3_sk_pad fill:none,stroke:none,color:transparent
    style C3_e_pad fill:none,stroke:none,color:transparent
    style C4_sk_pad fill:none,stroke:none,color:transparent
    style C4_e_pad fill:none,stroke:none,color:transparent
    style C5_sk_pad fill:none,stroke:none,color:transparent
    style C5_e_pad fill:none,stroke:none,color:transparent
    style C7_pad fill:none,stroke:none,color:transparent
    style C8_pad fill:none,stroke:none,color:transparent
```

## Circuit Summary Table

| Circuit | Name | Input Commitments | Equality Checks | Output Commitments |
|---------|------|-------------------|-----------------|-------------------|
| 1 | pk-trbfv | - | - | `commit(sk_trbfv)` |
| 2 | pk-bfv | - | - | `commit(sk_bfv)` |
| 3a | sk-shares (sk) | `commit(sk_trbfv)` | `commit(sk_trbfv) == expected` | `commit(sk_share[i][j])` |
| 3b | sk-shares (e_sm) | `commit(e_sm)` | `commit(e_sm) == expected` | `commit(e_sm_share[i][j])` |
| 4a | enc-bfv (sk shares) | `commit(sk_share[i][j])` | `commit(message) == commit(sk_share[i][j])` | - |
| 4b | enc-bfv (e_sm shares) | `commit(e_sm_share[i][j])` | `commit(message) == commit(e_sm_share[i][j])` | - |
| 5a | dec-bfv (sk shares) | `commit(sk_bfv)` | `commit(sk_bfv) == expected` | `commit(aggregated_sk_shares)` |
| 5b | dec-bfv (e_sm shares) | `commit(sk_bfv)` | `commit(sk_bfv) == expected` | `commit(aggregated_e_sm_shares)` |
| 7 | dec-share-trbfv | `commit(s)`, `commit(e)` | `commit(s) == commit(aggregated_sk_shares)`<br/>`commit(e) == commit(aggregated_e_sm_shares)` | - |
| 8 | dec-result-trbfv | - | - | decrypted message |

## Simplified Linear Flow
```mermaid
flowchart LR
    C1["1: pk-trbfv"] --> C3a["3a: shares(sk)"]
    C1 --> C3b["3b: shares(e_sm)"]
    C3a --> C4a["4a: enc(sk)"]
    C3b --> C4b["4b: enc(e_sm)"]
    
    C2["2: pk-bfv"] --> C5a["5a: dec(sk)"]
    C2 --> C5b["5b: dec(e_sm)"]
    
    C5a --> C7["7: dec-share"]
    C5b --> C7
    C7 --> C8["8: dec-result"]
```

