use circuits::{
    crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
    math::polynomial::Polynomial,
};

fn main(
    // Circuit parameters
    qis: pub [Field; 4],
    plaintext_modulus: pub Field,
    n: pub u32,
    l: pub u32,
    threshold: pub u32,
    deltas: pub [Field; 4],
    delta_halves: pub [Field; 4],
    // Decryption shares from T+1 parties
    decryption_shares: pub [[Polynomial<4>; 4]; 11],
    // Party IDs (T+1 = 3 parties)
    party_ids: pub [Field; 11],
    // Message polynomial
    message: pub Polynomial<4>,
) {
    // Create parameters with explicit type annotations
    // N=4, T=2, L=2
    let params: Params<4, 10, 4> = Params::new(
        qis,
        plaintext_modulus,
        n,
        l,
        threshold,
        deltas,
        delta_halves,
    );

    // Create circuit instance with explicit type annotation
    // N=4, T=10, L=4, BIT_NOISE=30
    let circuit: DecryptionShareAggregation<4, 10, 4, 30> =
        DecryptionShareAggregation::new(params, decryption_shares, party_ids, message);

    // Verify the decryption share aggregation
    circuit.verify();
}
