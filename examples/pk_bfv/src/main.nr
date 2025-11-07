use circuits::{
    crypto::pk_trbfv::pk_trbfv::{BfvPublicKeyCircuit, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<8192, 2>,
    a: [Polynomial<8192>; 2],
    eek: Polynomial<8192>,
    sk: Polynomial<8192>,
    r1is: [Polynomial<16383>; 2],
    r2is: [Polynomial<8191>; 2],
    pk0is: [Polynomial<8192>; 2],
    pk1is: [Polynomial<8192>; 2],
) {
    let pk_trbfv: BfvPublicKeyCircuit<8192, 2, 6, 2, 18, 59> =
        BfvPublicKeyCircuit::new(params, a, eek, sk, r1is, r2is, pk0is, pk1is);
    pk_trbfv.verify_correct_public_key();
}
