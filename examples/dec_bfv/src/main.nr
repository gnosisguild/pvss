use circuits::{
    crypto::dec_bfv::dec_bfv::{HonestCiphertextAggregationDecryption, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<8192, 5, 2>,
    honest_c0: [[Polynomial<8192>; 2]; 5],
    honest_c1: [[Polynomial<8192>; 2]; 5],
    sum_c0: [Polynomial<8192>; 2],
    sum_c1: [Polynomial<8192>; 2],
    s: [Polynomial<8192>; 2],
    u_i: [Polynomial<8192>; 2],
    r_1: [Polynomial<16383>; 2],
    r_2: [Polynomial<8191>; 2],
    u_global: Polynomial<8192>,
    crt_quotients: [Polynomial<8192>; 2],
    message: Polynomial<8192>,
) {
    // TODO: Your logic here...

    // Create Honest Ciphertext Aggregation Decryption circuit instance
    let dec_bfv: HonestCiphertextAggregationDecryption<8192, 5, 2, 57, 2, 114, 15, 57, 59> = HonestCiphertextAggregationDecryption::new(
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
