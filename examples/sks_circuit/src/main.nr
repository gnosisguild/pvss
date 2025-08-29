use circuits::{
    crypto::sk_shares::sk_shares::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

fn main(
    params: Params<2048, 1>,
    x_coords: [Field; 3],
    y: [[[Field; 3]; 1]; 2048],
    sk: Polynomial<2048>,
    f: Matrix<2048, 1, 3>,
    f_randomness: [[Field; 1]; 2048],
    r: [[[Field; 3]; 1]; 2048],
    d: [[Field; 1]; 2048],
) {
    let circuit = SecretKeySharesCircuit::new(params, x_coords, y, sk, f, f_randomness, r, d);
    circuit.verify_correct_trbfv_secret_sharing();
}
