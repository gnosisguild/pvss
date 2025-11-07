use circuits::{
    crypto::dec_share_trbfv::dec_share_trbfv::{DecryptionShareCorrectness, Params},
    math::polynomial::Polynomial,
};
fn main(
    params: Params<8192, 4>,
    c_0: [Polynomial<8192>; 4],
    c_1: [Polynomial<8192>; 4],
    s: [Polynomial<8192>; 4],
    e: [Polynomial<8192>; 4],
    r_1: [Polynomial<16383>; 4],
    r_2: [Polynomial<8191>; 4],
    d: [Polynomial<8192>; 4],
) {
    let dec_share: DecryptionShareCorrectness<8192, 4, 56, 56, 56, 68, 56, 56> =
        DecryptionShareCorrectness::new(params, c_0, c_1, s, e, r_1, r_2, d);

    dec_share.verify_decryption_share_correctness();
}
