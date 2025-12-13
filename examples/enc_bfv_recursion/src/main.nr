// Linear Proof Recursion for enc_bfv
//
// This circuit implements linear proof aggregation for the enc_bfv circuit.
// For n_party = 4, we have 8 proofs per party = 32 total proofs.
//
// Linear aggregation strategy:
// Step 1: proof[0] + proof[1] -> recursive_proof[1]
// Step 2: recursive_proof[1] + proof[2] -> recursive_proof[2]
// ...
// Step 31: recursive_proof[30] + proof[31] -> FINAL_PROOF
//
// Total: 31 sequential aggregation steps
// This circuit verifies 2 proofs at each step - used repeatedly for linear aggregation.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_ultrahonkzk_proof};

fn main(
    // Verification key for the child proofs
    // Uses UltraHonkVerificationKey type from bb_proof_verification
    verification_key: UltraHonkVerificationKey,
    // Accumulated proof from previous step (or first proof in step 1)
    proof_accumulated: UltraHonkZKProof,
    // Next proof to add in this linear aggregation step
    proof_next: UltraHonkZKProof,
    // Public inputs for the accumulated proof
    // Note: enc_bfv has 0 public inputs, but Noir doesn't allow [Field; 0]
    // We pass [0] as a dummy value which doesn't affect verification
    // NOT marked pub - these are verified internally, not exposed as outputs
    public_inputs_accumulated: [Field; 1],
    // Public inputs for the next proof
    public_inputs_next: [Field; 1],
    // Hash of the verification key (computed by the backend)
    key_hash: Field,
) {
    // ========================================================================
    // Linear Recursion: Verify 2 Proofs
    // ========================================================================
    //
    // This circuit verifies two proofs using verify_ultrahonkzk_proof
    // from the bb_proof_verification library. This function asserts internally -
    // if verification fails, the entire circuit will fail.
    //
    // In linear aggregation, this circuit is called 31 times sequentially:
    // - Step 1: Verifies proof[0] + proof[1]
    // - Step 2: Verifies recursive_proof[1] + proof[2]
    // - Step 3: Verifies recursive_proof[2] + proof[3]
    // - ...
    // - Step 31: Verifies recursive_proof[30] + proof[31] -> FINAL_PROOF
    // ========================================================================

    // Verify the accumulated proof
    verify_ultrahonkzk_proof(verification_key, proof_accumulated, public_inputs_accumulated, key_hash);

    // Verify the next proof
    verify_ultrahonkzk_proof(verification_key, proof_next, public_inputs_next, key_hash);

    // If we reach here, both proofs are valid!
    // This circuit's proof now attests to the validity of both input proofs.
}
