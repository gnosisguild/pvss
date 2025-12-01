use circuits::{
    crypto::dec_bfv::dec_bfv::{HonestCiphertextAggregationDecryption, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<512, 3, 1>,
    honest_c0: [[Polynomial<512>; 1]; 3],
    honest_c1: [[Polynomial<512>; 1]; 3],
    sum_c0: [Polynomial<512>; 1],
    sum_c1: [Polynomial<512>; 1],
    s: [Polynomial<512>; 1],
    u_i: [Polynomial<512>; 1],
    r_1: [Polynomial<1023>; 1],
    r_2: [Polynomial<511>; 1],
    u_global: Polynomial<512>,
    crt_quotients: [Polynomial<512>; 1],
    message: Polynomial<512>,
) {
    // TODO: Your logic here...

    // Create Honest Ciphertext Aggregation Decryption circuit instance
    let dec_bfv: HonestCiphertextAggregationDecryption<512, 3, 1, 51, 2, 61, 11, 51, 16> = HonestCiphertextAggregationDecryption::new(
        params,
        honest_c0,
        honest_c1,
        sum_c0,
        sum_c1,
        s,
        u_i,
        r_1,
        r_2,
        u_global,
        crt_quotients,
        message,
    );

    // Verify correct decryption
    dec_bfv.verify();

    // TODO: Your logic here...
}
