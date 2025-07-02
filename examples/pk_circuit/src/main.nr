use circuits::{
    constants::{L, N},
    crypto::pk_trbfv::BfvPublicKeyCircuit,
    math::polynomial::Polynomial,
};

fn main(
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    sk: Polynomial<N>,
    eek: Polynomial<N>,
    a: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
) {
    let circuit = BfvPublicKeyCircuit::new(a, eek, sk, r1is, r2is, pk0is, pk1is);
    circuit.correct_bfv_public_key();
}
