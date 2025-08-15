use circuits::{
    crypto::sk_shares::{constants::{L, N, N_PARTIES, T}, sk_shares::SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

fn main(
    sk: Polynomial<N>,
    f: Matrix<N + 1, L, T>,
    y: [[[Field; N_PARTIES]; L]; N + 1],
    r: [[[Field; N_PARTIES]; L]; N + 1],
    d: [[Field; L]; N + 1],
    x_coords: [Field; N_PARTIES],
) {
    let circuit = SecretKeySharesCircuit::new(sk, f, y, r, d, x_coords);
    circuit.correct_sss();
}
