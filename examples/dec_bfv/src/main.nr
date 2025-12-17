use circuits::{
    crypto::dec_bfv::dec_bfv::{HonestCiphertextAggregationDecryption, Params},
    math::polynomial::Polynomial,
};
fn main(
    //update the params to producation params
    params: Params<512, 3, 2, 2>, // N=512, H=3, L=2, L_PRIME=2
    expected_sk_commitment: Field,
    honest_c0: [[[Polynomial<512>; 2]; 2]; 3],
    honest_c1: [[[Polynomial<512>; 2]; 2]; 3],
    s: Polynomial<512>,
    u_i: [[Polynomial<512>; 2]; 2],
    r_1: [[Polynomial<1023>; 2]; 2],
    r_2: [[Polynomial<511>; 2]; 2],
    u_global: [Polynomial<512>; 2],
    crt_quotients: [[Polynomial<512>; 2]; 2],
    message: [Polynomial<512>; 2],
) -> pub Field {
    let circuit: HonestCiphertextAggregationDecryption<512, 3, 2, 2, 51, 2, 51, 51, 51, 51> = HonestCiphertextAggregationDecryption::new(
        params,
        expected_sk_commitment,
        honest_c0,
        honest_c1,
        s,
        u_i,
        r_1,
        r_2,
        u_global,
        crt_quotients,
        message,
    );

    circuit.verify()
}
