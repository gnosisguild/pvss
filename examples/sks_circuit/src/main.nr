use circuits::{
    crypto::sk_shares::sk_shares::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

fn main(
    params: Params<128, 1>,
    x_coords: [Field; 3],
    y: [[[Field; 3]; 1]; 128],
    sk: Polynomial<128>,
    f: Matrix<128, 1, 2>,
    f_randomness: [[Field; 1]; 128],
    r: [[[Field; 3]; 1]; 128],
    d: [[Field; 1]; 128],
) {
    let circuit = SecretKeySharesCircuit::new(params, x_coords, y, sk, f, f_randomness, r, d);
    circuit.verify_correct_trbfv_secret_sharing();
}
