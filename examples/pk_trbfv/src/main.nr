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
    let circuit = BfvPublicKeyCircuit::new(params, a, eek, sk, r1is, r2is, pk0is, pk1is);
    circuit.verify_correct_bfv_public_key();
}
