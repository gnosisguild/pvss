fn main(
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    sk: Polynomial<N>,
    eek: Polynomial<N>,
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
) {
    let circuit = BfvPublicKeyCircuit::new(
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        sk,
        eek,
        r1is,
        r2is,
    );
    circuit.correct_encryption();
}