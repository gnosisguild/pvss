use circuits::{
    crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
    math::polynomial::Polynomial,
};

fn main(
    //N, L, T
    params: Params<5, 2, 2>,
    decryption_shares: [[Polynomial<5>; 2]; 3],
    party_ids: [Field; 3],
    message: Polynomial<5>,
    u_global: Polynomial<5>,
    crt_quotients: [Polynomial<5>; 2],
) {
    let dec_share_agg: DecryptionShareAggregation<5, 2, 2, 50> = DecryptionShareAggregation::new(
        params,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    dec_share_agg.verify();
}
