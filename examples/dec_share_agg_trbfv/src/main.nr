use circuits::{
    crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
    math::polynomial::Polynomial,
};

fn main(
    // Circuit parameters
    qis: pub [Field; 2],
    plaintext_modulus: pub Field,
    n: pub u32,
    l: pub u32,
    threshold: pub u32,
    delta: pub Field, // Global delta
    delta_half: pub Field, // Global delta/2
    // Decryption shares
    decryption_shares: pub [[Polynomial<4>; 2]; 3],
    // Party IDs
    party_ids: pub [Field; 3],
    // Message polynomial
    message: pub Polynomial<4>,
    // Global u polynomial (CRT reconstruction)
    u_global: pub Polynomial<4>,
    // CRT quotient polynomials
    crt_quotients: pub [Polynomial<4>; 2],
) {
    let params: Params<4, 2, 2> =
        Params::new(qis, plaintext_modulus, n, l, threshold, delta, delta_half);

    let circuit: DecryptionShareAggregation<4, 2, 2, 10> = DecryptionShareAggregation::new(
        params,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    circuit.verify();
}
