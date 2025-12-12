use circuits::{
    crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<5, 2, 2>,
    expected_decryption_share_commitments: [Field; 3],
    decryption_shares: [[Polynomial<5>; 2]; 3],
    party_ids: [Field; 3],
    message: Polynomial<5>,
    u_global: Polynomial<5>,
    crt_quotients: [Polynomial<5>; 2],
) {
    let dec_share_agg: DecryptionShareAggregation<5, 2, 2, 69> = DecryptionShareAggregation::new(
        params,
        expected_decryption_share_commitments,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    dec_share_agg.verify();
}
