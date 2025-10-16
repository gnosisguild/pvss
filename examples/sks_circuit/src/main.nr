use circuits::{
    crypto::sk_shares::sk_share_mod::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

fn main(
    params: Params<8192, 4>,
    x_coords: [Field; 100],
    y: [[[Field; 100]; 4]; 8192],
    sk: Polynomial<8192>,
    f: Matrix<8192, 4, 50>,
    f_randomness: [[Field; 4]; 8192],
) {
    let circuit = SecretKeySharesCircuit::new(params, x_coords, y, sk, f, f_randomness);
    circuit.verify_correct_trbfv_secret_sharing();
}
