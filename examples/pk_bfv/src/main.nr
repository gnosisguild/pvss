use circuits::{
    crypto::pk_trbfv::pk_trbfv::{BfvPublicKeyCircuit, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<512, 1>,
    a: [Polynomial<512>; 1],
    eek: Polynomial<512>,
    sk: Polynomial<512>,
    r1is: [Polynomial<1023>; 1],
    r2is: [Polynomial<511>; 1],
    pk0is: [Polynomial<512>; 1],
    pk1is: [Polynomial<512>; 1],
) {
    let pk_trbfv: BfvPublicKeyCircuit<512, 1, 4, 2, 12, 51> =
        BfvPublicKeyCircuit::new(params, a, eek, sk, r1is, r2is, pk0is, pk1is);
    pk_trbfv.verify_correct_public_key();
}
