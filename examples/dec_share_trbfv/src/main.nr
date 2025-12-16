use circuits::{
    crypto::dec_share_trbfv::dec_share_trbfv::{DecryptionShareCorrectness, Params},
    math::polynomial::Polynomial,
};
fn main(
    params: Params<512, 2>,
    expected_s_commitment: Field,
    expected_e_commitment: Field,
    c_0: [Polynomial<512>; 2],
    c_1: [Polynomial<512>; 2],
    s: [Polynomial<512>; 2],
    e: [Polynomial<512>; 2],
    r_1: [Polynomial<1023>; 2],
    r_2: [Polynomial<511>; 2],
    d: [Polynomial<512>; 2],
) {
    let circuit: DecryptionShareCorrectness<512, 2, 36, 36, 36, 44, 36, 36> = DecryptionShareCorrectness::new(
        params,
        expected_s_commitment,
        expected_e_commitment,
        c_0,
        c_1,
        s,
        e,
        r_1,
        r_2,
        d,
    );

    circuit.verify()
}
