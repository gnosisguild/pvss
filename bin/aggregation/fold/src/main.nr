use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::math::helpers::compute_safe;

fn main(
    verification_key: UltraHonkVerificationKey,
    wrapper_proofs: [UltraHonkProof; 2],
    commitments: pub [Field; 2],
    key_hash: Field,
) -> pub Field {
    let proof = wrapper_proofs[0];
    let public_inputs = [commitments[0]];
    verify_honk_proof_non_zk(verification_key, proof, public_inputs, key_hash);

    let proof = wrapper_proofs[1];
    let public_inputs = [commitments[1]];
    verify_honk_proof_non_zk(verification_key, proof, public_inputs, key_hash);

    // Compute commitment of the two commitments using SAFE
    let domain_separator = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]; // "PVSS_fold" in hex

    let payload = Vec::from_slice(&[commitments[0], commitments[1]]);
    let io_pattern = [0x80000002, 0x00000001];

    compute_safe(domain_separator, payload, io_pattern).get(0)
}
