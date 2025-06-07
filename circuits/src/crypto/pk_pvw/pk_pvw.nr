use crate::crypto::pk_pvw::constants::{
    E_BOUND, K, L, N, N_PARTIES, QIS, R1_LOW_BOUNDS, R1_UP_BOUNDS, R2_BOUNDS, SK_BOUND,
};
use crate::math::polynomial::Polynomial;
use poseidon::poseidon2::Poseidon2;

// Matrix is a type representing a 2D array of polynomials, parameterized by the number of rows, columns, and polynomial degree.
type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

//the formulas are in the RNS mode
pub struct PvwPublicKeyCircuit {
    a: [Matrix<K, K, N>; L],
    //For each party `i`, each `e_i` is a vector of size `K` of the polynomials.
    e: Matrix<N_PARTIES, K, N>,
    sk: Matrix<N_PARTIES, K, N>,
    b: [Matrix<N_PARTIES, K, N>; L],
    r1: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
    r2: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
}

impl PvwPublicKeyCircuit {
    pub fn new(
        a: [Matrix<K, K, N>; L],
        e: Matrix<N_PARTIES, K, N>,
        sk: Matrix<N_PARTIES, K, N>,
        b: [Matrix<N_PARTIES, K, N>; L],
        r1: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
        r2: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
    ) -> Self {
        PvwPublicKeyCircuit { a, e, sk, b, r1, r2 }
    }

    fn correct_pvw_public_key(self) {
        //Range checks
        for i in 0..N_PARTIES {
            for j in 0..K {
                self.e[i][j].range_check_1bound(E_BOUND);
                self.sk[i][j].range_check_1bound(SK_BOUND);
            }
        }

        for i in 0..L {
            for j in 0..N_PARTIES {
                for k in 0..K {
                    self.r1[i][j][k].range_check_2bounds(R1_UP_BOUNDS[j], R1_LOW_BOUNDS[j]);
                    self.r2[i][j][k].range_check_1bound(R2_BOUNDS[j]);
                }
            }
        }

        // @todo: generate the input using the safe API
        let input = [1, 2, 3];
        let size = 3;
        let gamma = Poseidon2::hash(input, size);

        // Evaluate a at gamma (3D array)
        let a_at_gamma =
            self.a.map(|matrix| matrix.map(|row| row.map(|poly| poly.eval(gamma))));

        let e_at_gamma = self.e.map(|row| row.map(|poly| poly.eval(gamma)));

        let sk_at_gamma = self.sk.map(|row| row.map(|poly| poly.eval(gamma)));

        let b_at_gamma =
            self.b.map(|matrix| matrix.map(|row| row.map(|poly| poly.eval(gamma))));

        let r1_at_gamma =
            self.r1.map(|matrix| matrix.map(|row| row.map(|poly| poly.eval(gamma))));

        let r2_at_gamma =
            self.r2.map(|matrix| matrix.map(|row| row.map(|poly| poly.eval(gamma))));

        // cyclo poly is equal to x^N + 1
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Check the correctness of the public key
        //b_{l,i} = -a_l * s_i + e_i + r2_{l,i}*(X^N+1) + r1_{l,i}*q_l

        // For each modulus q_l (L total)
        for l in 0..L {
            // For each party (N_PARTIES total)
            for i in 0..N_PARTIES {
                // 1. Compute matrix-vector product: a_l * s_i (result is K elements)
                // Temporary array for (a_l * s_i)
                let mut a_times_s = [0; K];
                // Matrix-vector multiply
                for row in 0..K {
                    for col in 0..K {
                        a_times_s[row] += a_at_gamma[l][row][col] * sk_at_gamma[i][col];
                    }
                }

                // 2. Verify each of the K components
                for k in 0..K {
                    // Compute the right-hand side of the equation
                    let rhs = -a_times_s[k] // - (a_l * s_i)[k]
                        + e_at_gamma[i][k] // + e_i[k]
                        + r2_at_gamma[l][i][k] * cyclo_at_gamma // + r2_{l,i}[k] * (X^N + 1)
                        + r1_at_gamma[l][i][k] * QIS[l]; // + r1_{l,i}[k] * q_l

                    // Check equality with b_{l,i}[k]
                    assert_eq(b_at_gamma[l][i][k], rhs);
                }
            }
        }
    }
}
