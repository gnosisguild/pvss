use circuits::{crypto::enc_bfv::enc_bfv::{EncryptionBfv, Params}, math::polynomial::Polynomial};
fn main(
    params: Params<512, 2>,
    expected_message_commitment: Field,
    pk0is: [Polynomial<512>; 2],
    pk1is: [Polynomial<512>; 2],
    ct0is: [Polynomial<512>; 2],
    ct1is: [Polynomial<512>; 2],
    u: Polynomial<512>,
    e0: Polynomial<512>,
    e0is: [Polynomial<512>; 2],
    e0_quotients: [Polynomial<512>; 2],
    e1: Polynomial<512>,
    message: Polynomial<512>,
    r1is: [Polynomial<1023>; 2],
    r2is: [Polynomial<511>; 2],
    p1is: [Polynomial<1023>; 2],
    p2is: [Polynomial<511>; 2],
) -> pub bool {
    let circuit: EncryptionBfv<512, 2, 51, 51, 2, 10, 10, 7, 51, 51, 51, 51> = EncryptionBfv::new(
        params,
        expected_message_commitment,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e0is,
        e0_quotients,
        e1,
        message,
        r1is,
        r2is,
        p1is,
        p2is,
    );

    circuit.verify()
}
