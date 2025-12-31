# PVSS-TRBFV Circuit Architecture

## Overview

The PVSS-TRBFV protocol consists of 4 phases:
- **Phase 1**: Distributed Key Generation (DKG)
- **Phase 2**: Honest Party Aggregation
- **Phase 3**: User Encryption (Greco)
- **Phase 4**: Threshold Decryption

## Circuit Flow Diagram
```mermaid
flowchart TD
    subgraph Phase1["Phase 1: Distributed Key Generation (DKG)"]
        subgraph C1["Circuit 1: pk-trbfv (N_PARTIES×)"]
            C1_pad[ ]
            C1_desc["Verifies TRBFV public key correctness"]
            C1_out["Output: commit(sk_trbfv), commit(pk_trbfv)"]
        end

        subgraph C2_sk["Circuit 2a: sk-shares (for sk shares)"]
            C2_sk_pad[ ]
            C2_sk_check["Check: commit(sk_trbfv) == expected"]
            C2_sk_out["Output: commit(sk_share[i][j])"]
        end

        subgraph C2_e["Circuit 2b: sk-shares (for e_sm shares)"]
            C2_e_pad[ ]
            C2_e_check["Check: commit(e_sm) == expected"]
            C2_e_out["Output: commit(e_sm_share[i][j])"]
        end

        subgraph C3_sk["Circuit 3a: enc-bfv (encrypt sk shares)"]
            C3_sk_pad[ ]
            C3_sk_check["Check: commit(message) == commit(sk_share[i][j])"]
            C3_sk_desc["Verifies BFV encryption of sk shares"]
        end

        subgraph C3_e["Circuit 3b: enc-bfv (encrypt e_sm shares)"]
            C3_e_pad[ ]
            C3_e_check["Check: commit(message) == commit(e_sm_share[i][j])"]
            C3_e_desc["Verifies BFV encryption of e_sm shares"]
        end

        subgraph C4_sk["Circuit 4a: dec-bfv-commit-verify (sk shares)"]
            C4_sk_pad[ ]
            C4_sk_check["Check: commit(decrypted) == commit(sk_share)"]
            C4_sk_out["Output: commit(aggregated_sk_shares)"]
        end

        subgraph C4_e["Circuit 4b: dec-bfv-commit-verify (e_sm shares)"]
            C4_e_pad[ ]
            C4_e_check["Check: commit(decrypted) == commit(e_sm_share)"]
            C4_e_out["Output: commit(aggregated_e_sm_shares)"]
        end

        C1 -->|"commit(sk_trbfv)"| C2_sk
        C1 -->|"commit(e_sm)"| C2_e
        C2_sk -->|"commit(sk_share[i][j])"| C3_sk
        C2_e -->|"commit(e_sm_share[i][j])"| C3_e
        C2_sk -->|"commit(sk_share)"| C4_sk
        C2_e -->|"commit(e_sm_share)"| C4_e
    end
    subgraph Phase2["Phase 2: Honest Party Aggregation"]

        subgraph C5["Circuit 5: pk-aggregation-trbfv (1×)"]
            C5_pad[ ]
            C5_check["Check: commit(pk_trbfv) from honest parties"]
            C5_out["Output: pk0_agg, pk1_agg"]
        end
    end


    subgraph Phase3["Phase 3: User Encryption"]
        subgraph Greco["Greco Circuit (N_USERS×)"]
            Greco_pad[ ]
            Greco_desc["User encrypts data with pk_agg"]
            Greco_out["Output: encrypted user data"]
        end
        
        HE["Homomorphic Computation"]
    end

    subgraph Phase4["Phase 4: Threshold Decryption"]
        subgraph C6["Circuit 6: dec-share-trbfv (T+1×)"]
            C6_pad[ ]
            C6_check["Check: commit(s) == commit(aggregated_sk_shares)<br/>Check: commit(e) == commit(aggregated_e_sm_shares)"]
            C6_desc["Verifies d = c_0 + c_1 * s + e"]
            C6_out["Output: decryption_share d"]
        end

        subgraph C7["Circuit 7: dec-result-trbfv (1×)"]
            C7_pad[ ]
            C7_desc["Lagrange interpolation + decoding"]
            C7_out["Output: final decrypted message"]
        end

        C6 -->|"d (public)"| C7
    end

    %% Cross-phase connections
    C1 -->|"commit(pk_trbfv)"| C5
    Phase1 -->|"Proof verification<br/>Honest parties H"| Phase2
    C5 -->|"pk_agg"| Greco
    Greco --> HE
    HE -->|"result ciphertext"| C6
    C4_sk -->|"commit(aggregated_sk_shares)"| C6
    C4_e -->|"commit(aggregated_e_sm_shares)"| C6

    %% Invisible spacers
    style C1_pad fill:none,stroke:none,color:transparent
    style C2_sk_pad fill:none,stroke:none,color:transparent
    style C2_e_pad fill:none,stroke:none,color:transparent
    style C3_sk_pad fill:none,stroke:none,color:transparent
    style C3_e_pad fill:none,stroke:none,color:transparent
    style C4_sk_pad fill:none,stroke:none,color:transparent
    style C4_e_pad fill:none,stroke:none,color:transparent
    style C5_pad fill:none,stroke:none,color:transparent
    style Greco_pad fill:none,stroke:none,color:transparent
    style C6_pad fill:none,stroke:none,color:transparent
    style C7_pad fill:none,stroke:none,color:transparent


    %% Phase background colors
    style Phase1 fill:#e6f3ff,stroke:#4a90d9,stroke-width:2px
    style Phase2 fill:#e6ffe6,stroke:#4ad94a,stroke-width:2px
    style Phase3 fill:#f3e6ff,stroke:#9a4ad9,stroke-width:2px
    style Phase4 fill:#ffe6e6,stroke:#d94a4a,stroke-width:2px
```

## Phase Summary

### Phase 1: Distributed Key Generation (DKG)
**Participants:** N_PARTIES ciphernodes

| Step | Circuit | Description |
|------|---------|-------------|
| 1 | Circuit 1: pk-trbfv | Each party generates TRBFV keypair |
| 2 | Circuit 2a/2b: sk-shares | Secret key/smudging noise shamir secret sharing with Reed-Solomon verification |
| 3 | Circuit 3a/3b: enc-bfv | Encrypt shares to other parties |
| 4 | Circuit 4a/4b: dec-bfv-commit-verify | Verify decryption matches commitments from circuit 2 |

### Phase 2: Honest Party Aggregation
**Participants:** Aggregator (any party or external)

| Step | Circuit | Description |
|------|---------|-------------|
| 1 | - | Verify Phase 1 proofs, identify honest parties H |
| 2 | Circuit 5: pk-aggregation-trbfv | Aggregate TRBFV public keys of honest parties |

### Phase 3: User Encryption (Greco)
**Participants:** N_USERS (external users)

| Step | Circuit | Description |
|------|---------|-------------|
| 1 | Greco | Users encrypt data with aggregated public key |
| 2 | - | Homomorphic computations on encrypted data |

### Phase 4: Threshold Decryption
**Participants:** T+1 honest ciphernodes

| Step | Circuit | Description |
|------|---------|-------------|
| 1 | Circuit 6: dec-share-trbfv | Each party computes decryption share |
| 2 | Circuit 7: dec-result-trbfv | Combine shares via Lagrange interpolation |

## Circuit Summary Table

| Circuit | Name | Instances | Phase | Input Commitments | Output |
|---------|------|-----------|-------|-------------------|--------|
| 1 | pk-trbfv | N_PARTIES | 1 | - | commit(sk_trbfv), commit(pk_trbfv) |
| 2a | sk-shares (sk) | 1 | 1 | commit(sk_trbfv) | commit(sk_share[i][j]) |
| 2b | sk-shares (e_sm) | 1 | 1 | commit(e_sm) | commit(e_sm_share[i][j]) |
| 3a | enc-bfv (sk) | N_PARTIES × L | 1 | commit(sk_share[i][j]) | ciphertexts |
| 3b | enc-bfv (e_sm) | N_PARTIES × L | 1 | commit(e_sm_share[i][j]) | ciphertexts |
| 4a | dec-bfv-commit-verify (sk) | H | 1 | commit(sk_share) | commit(aggregated_sk_shares) |
| 4b | dec-bfv-commit-verify (e_sm) | H | 1 | commit(e_sm_share) | commit(aggregated_e_sm_shares) |
| 5 | pk-aggregation-trbfv | 1 | 2 | commit(pk_trbfv) | pk0_agg, pk1_agg |
| - | Greco | N_USERS | 3 | pk_agg | encrypted data |
| 6 | dec-share-trbfv | T+1 | 4 | commit(agg_sk), commit(agg_e) | decryption_share d |
| 7 | dec-result-trbfv | 1 | 4 | decryption_shares | final message |

## Commitment Flow
```
Phase 1 (DKG):
  Circuit 1 ──→ commit(sk_trbfv) ──→ Circuit 2a
           ──→ commit(e_sm) ──────→ Circuit 2b
           ──→ commit(pk_trbfv) ─────────────────────→ Circuit 5 (Phase 2)

  Circuit 2a ──→ commit(sk_share[i][j]) ──→ Circuit 3a
                                       ──→ Circuit 4a

  Circuit 2b ──→ commit(e_sm_share[i][j]) ──→ Circuit 3b
                                          ──→ Circuit 4b

  Circuit 4a ──→ commit(aggregated_sk_shares) ──────→ Circuit 6 (Phase 4)
  Circuit 4b ──→ commit(aggregated_e_sm_shares) ────→ Circuit 6 (Phase 4)

Phase 2 (Aggregation):
  Circuit 5 ──→ pk_agg ──→ Greco (Phase 3)

Phase 3 (User Encryption):
  Greco ──→ ciphertext ──→ Homomorphic Ops ──→ result_ciphertext ──→ Circuit 6 (Phase 4)

Phase 4 (Decryption):
  Circuit 6 ──→ decryption_share d ──→ Circuit 7
  Circuit 7 ──→ final_message
```

## Simplified Linear Flow
```mermaid
flowchart LR
    subgraph Phase1["Phase 1: DKG"]
        C1["1: pk-trbfv"]
        C2a["2a: shares(sk)"]
        C2b["2b: shares(e_sm)"]
        C3a["3a: enc(sk)"]
        C3b["3b: enc(e_sm)"]
        C4a["4a: dec-verify(sk)"]
        C4b["4b: dec-verify(e_sm)"]
        
        C1 --> C2a
        C1 --> C2b
        C2a --> C3a
        C2b --> C3b
        C2a --> C4a
        C2b --> C4b
    end
    
    subgraph Phase2["Phase 2: Aggregation"]
        C5["5: pk-agg"]
    end
    
    subgraph Phase3["Phase 3: Users"]
        Greco["Greco"]
        HE["HE Ops"]
        Greco --> HE
    end
    
    subgraph Phase4["Phase 4: Decryption"]
        C6["6: dec-share"]
        C7["7: dec-result"]
        C6 --> C7
    end
    
    C1 --> C5
    C5 --> Greco
    HE --> C6
    C4a --> C6
    C4b --> C6

    style Phase1 fill:#e6f3ff,stroke:#4a90d9,stroke-width:2px
    style Phase2 fill:#e6ffe6,stroke:#4ad94a,stroke-width:2px
    style Phase3 fill:#f3e6ff,stroke:#9a4ad9,stroke-width:2px
    style Phase4 fill:#ffe6e6,stroke:#d94a4a,stroke-width:2px
```

## Security Properties

1. **Threshold Security**: Need T+1 honest parties to decrypt
2. **Verifiable**: All operations proven in zero-knowledge
3. **Composition**: Commitments chain circuits together
4. **Dishonest Detection**: Phase 1 proofs identify malicious parties before Phase 2
