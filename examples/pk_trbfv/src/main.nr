use circuits::{
    crypto::pk_trbfv::pk_trbfv::{BfvPublicKeyCircuit, Params},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<8192, 4>,
    a: [Polynomial<8192>; 4],
    eek: Polynomial<8192>,
    sk: Polynomial<8192>,
    r1is: [Polynomial<16383>; 4],
    r2is: [Polynomial<8191>; 4],
    pk0is: [Polynomial<8192>; 4],
    pk1is: [Polynomial<8192>; 4],
) {
    let pk_trbfv: BfvPublicKeyCircuit<8192, 4, 6, 2, 18, 56> =
        BfvPublicKeyCircuit::new(params, a, eek, sk, r1is, r2is, pk0is, pk1is);

    pk_trbfv.verify_correct_public_key();
}
