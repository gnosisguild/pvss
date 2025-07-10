use crate::math::polynomial::Polynomial;
use super::constants::{L, N, N_PARTIES};

// Matrix is a type representing a 2D array of polynomials, parameterized by the number of rows, columns, and polynomial degree.
type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];
//we have to convert mod q_i to mod P.
pub struct SecretKeySharesCircuit {
    //trBFV secret key for one party
    //sk=a_0 + a_1 * x + ... + a_N * x^N
    sk: Polynomial<N>,
    //Polynmouial `f_i` of degree `t+1` correspond to the shamir secret share of coefficient `a_i` in the `sk`
    f: Matrix<N + 1, L, t - 1>,
    //y^i0, ..., y^i_N_PARTIES are shamir secret shares for one coefficient `a_i` of sk which are on polynomial `f_i`
    //y=[[moduli_1], [moduli_2], [moduli_3]]
    y: [[[Field; N_PARTIES]; L]; N + 1],
    k: [[[Field; N_PARTIES]; L]; N + 1],
    x_coords: [Field; N_PARTIES],
}
//y_i = f(x_i) mod q_i
//y_i = f(x_i) + k_jq_j mod P

impl SecretKeySharesCircuit {
    pub fn new(
        sk: Polynomial<N>,
        f: Matrix<N + 1, L, t - 1>,
        y: [[[Field; N_PARTIES]; L]; N + 1],
        k: [[[Field; N_PARTIES]; L]; N + 1],
        x_coords: [Field; N_PARTIES],
    ) -> Self {
        SecretKeySharesCircuit { sk, f, y, k, x_coords }
    }

    pub fn correct_sss(self) {
        for i in 0..N + 1 {
            let a_i = self.sk[i];

            // Loop over each modulus q_j
            for j in 0..L {
                let q_j = q[j];
                let f_i_j = self.f[i][j]; // Polynomial for coefficient i, modulus j

                // Loop over each party's share
                for k_party in 0..N_PARTIES {
                    let x_k = self.x_coords[k_party];
                    let y_i_j_k = self.y[i][j][k_party];
                    let k_i_j_k = self.k[i][j][k_party];

                    // Check: f_i_j(x_k) = y_i_j_k + k_i_j_k * q_j
                    let computed_y = f_i_j.eval(x_k);
                    assert_eq(computed_y, y_i_j_k + k_i_j_k * q_j);
                }

                // Verify a_i = f_i_j(0) mod q_j (secret-key consistency)
                assert_eq(f_i_j.eval(0), a_i + k_zero[i][j] * q_j);
            }
        }
    }
}
