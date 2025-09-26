use circuits::{crypto::pk_pvw::pk_pvw::{Params, PvwPublicKeyCircuit}, math::polynomial::Matrix};

fn main(
    params: Params<8, 4>, // N=8, L=4
    a: [Matrix<2, 2, 8>; 4], // K=2, N=8, L=4
    e: Matrix<1, 2, 8>, // 1 parties, K=2, N=8
    sk: Matrix<1, 2, 8>, // 1 parties, K=2, N=8
    b: [Matrix<1, 2, 8>; 4], // 1 parties, K=2, N=8, L=4
    r1: [Matrix<1, 2, 15>; 4], // 1 parties, K=2, 2*8-1=15, 2*4-1=15, L=4
    r2: [Matrix<1, 2, 7>; 4], // 1 parties, K=2, 8-1=7, L=4
) {
    let circuit = PvwPublicKeyCircuit::new(params, a, e, sk, b, r1, r2);
    circuit.verify_correct_pvw_public_key();
}
