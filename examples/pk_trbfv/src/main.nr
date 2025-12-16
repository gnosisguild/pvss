use circuits::{
    crypto::pk_trbfv::pk_trbfv::{BfvPublicKeyCircuit, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<512, 2>,
    a: [Polynomial<512>; 2],
    eek: Polynomial<512>,
    sk: Polynomial<512>,
    r1is: [Polynomial<1023>; 2],
    r2is: [Polynomial<511>; 2],
    pk0is: [Polynomial<512>; 2],
    pk1is: [Polynomial<512>; 2],
) -> pub Field {
    let pk_trbfv: BfvPublicKeyCircuit<512, 2, 6, 2, 14, 36> =
        BfvPublicKeyCircuit::new(params, a, eek, sk, r1is, r2is, pk0is, pk1is);

    pk_trbfv.verify_correct_public_key()
}
