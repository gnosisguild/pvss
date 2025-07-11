use crate::math::polynomial::Polynomial;
use super::constants::{L, N, N_PARTIES, QIS, T};

// Matrix is a type representing a 2D array of polynomials, parameterized by the number of rows, columns, and polynomial degree.
type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];
//we have to convert mod q_i to mod P.
pub struct SecretKeySharesCircuit {
    //trBFV secret key for one party
    //sk=a_0 + a_1 * x + ... + a_N * x^N
    sk: Polynomial<N>,
    //Polynmouial `f_i` of degree `t-1` correspond to the shamir secret share of coefficient `a_i` in the `sk`
    f: Matrix<N + 1, L, T>,
    //y^i0, ..., y^i_N_PARTIES are shamir secret shares for one coefficient `a_i` of sk which are on polynomial `f_i`
    //y=[[moduli_1], [moduli_2], [moduli_3]]
    y: [[[Field; N_PARTIES]; L]; N + 1],
    r: [[[Field; N_PARTIES]; L]; N + 1], //r_k_j = (y_k_j - f_j(x_k))/ q_j
    d: [[Field; L]; N + 1], // d_i_j = (a_i - f_i_j(0)) / q_j
    x_coords: [Field; N_PARTIES],
}
//y_k_j= f_j(x_k) mod q_j
//y_k_j= f_j(x_k) + r_k_j * q_j   mod P

impl SecretKeySharesCircuit {
    /// Creates a new instance of `SecretKeySharesCircuit`.
    pub fn new(
        sk: Polynomial<N>,
        f: Matrix<N + 1, L, T>,
        y: [[[Field; N_PARTIES]; L]; N + 1],
        r: [[[Field; N_PARTIES]; L]; N + 1],
        d: [[Field; L]; N + 1],
        x_coords: [Field; N_PARTIES],
    ) -> Self {
        SecretKeySharesCircuit { sk, f, y, r, d, x_coords }
    }
    pub fn correct_sss(self) {
        for i in 0..N + 1 {
            let a_i = self.sk.coefficients[i];

            // Loop over each modulus q_j
            for j in 0..L {
                let q_j = QIS[j];
                let f_i_j = self.f[i][j]; // Polynomial for coefficient i, modulus j
                //Range check on each f_i_j polynomial
                f_i_j.range_check_1bound(q_j as u64);

                // Loop over each party's share
                for k_party in 0..N_PARTIES {
                    let x_k = self.x_coords[k_party];
                    let y_i_j_k = self.y[i][j][k_party];
                    let r_i_j_k = self.r[i][j][k_party];
                    //range check on y_i_j_k and r_i_j_k

                    // Check: f_i_j(x_k) = y_i_j_k + r_i_j_k * q_j
                    let computed_y = f_i_j.eval(x_k);
                    assert_eq(computed_y, y_i_j_k + r_i_j_k * q_j);
                }
                let d_i_j = self.d[i][j];
                // Verify a_i = f_i_j(0) mod q_j (secret-key consistency)
                //f_i_j(0) = a_i + d_i_j * q_j  mod P
                assert_eq(f_i_j.eval(0), a_i + d_i_j * q_j);
            }
        }
    }
}
