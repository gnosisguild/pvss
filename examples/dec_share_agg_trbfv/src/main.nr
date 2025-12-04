use circuits::{
    crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<1, 4, 2>,
    decryption_shares: [[Polynomial<1>; 4]; 3],
    party_ids: [Field; 3],
    message: Polynomial<1>,
    u_global: Polynomial<1>,
    crt_quotients: [Polynomial<1>; 4],
) {
    let dec_share_agg: DecryptionShareAggregation<1, 4, 2, 201> = DecryptionShareAggregation::new(
        params,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    dec_share_agg.verify();
}
