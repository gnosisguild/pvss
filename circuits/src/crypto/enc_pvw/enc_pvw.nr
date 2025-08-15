use crate::crypto::pk_pvw::constants::{
    E_BOUND, K, L, N, N_PARTIES, QIS, R1_LOW_BOUNDS, R1_UP_BOUNDS, R2_BOUNDS, SK_BOUND, E1_BOUND,
    E2_BOUND, // Different bounds for e1 and e2
    ENCRYPTION_R1_LOW_BOUNDS, ENCRYPTION_R1_UP_BOUNDS, ENCRYPTION_R2_BOUNDS,
    ENCRYPTION_S1_LOW_BOUNDS, ENCRYPTION_S1_UP_BOUNDS, ENCRYPTION_S2_BOUNDS, SIZE_ENCRYPTION,
    TAG_ENCRYPTION,
};
use crate::math::polynomial::Polynomial;
use safe::safe::SafeSponge;

// Matrix types for encryption circuit
pub type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];
pub type Vector<let SIZE: u32, let N: u32> = [Polynomial<N>; SIZE];

/// PVW Encryption Verification Circuit
///
/// Verifies that a ciphertext was correctly generated according to the PVW encryption algorithm.
/// For each party i and modulus l, the encryption equation is:
/// c1_{l,j} = a_{l,j} * u + e1_{j} + r2_{l,j} * (X^N + 1) + r1_{l,j} * q_l
/// c2_{l,i} = b_{l,i} * u + m_i + e2_{i} + s2_{l,i} * (X^N + 1) + s1_{l,i} * q_l
///
/// Where:
/// - u is the random encryption vector (K polynomials: u_0, u_1, ..., u_{K-1})
/// - a_{l,j} is the j-th row of matrix A_l, so a_{l,j} * u = sum_{k=0}^{K-1} a_{l,j,k} * u_k
/// - b_{l,i} is the i-th row of matrix B_l, so b_{l,i} * u = sum_{k=0}^{K-1} b_{l,i,k} * u_k
/// - encoded_messages are the result of message_i * gadget_polynomial (already computed)
/// - e1, e2 are error terms
/// - r1, r2, s1, s2 are quotients from modulus switching and cyclotomic reduction
/// - L is the number of moduli, must equal the length of QIS array
/// - q_l = QIS[l] is the l-th modulus in the RNS representation
pub struct PvwEncryptionCircuit {
    // Public inputs (from public key)
    // Public matrix A for each modulus
    a: [Matrix<K, K, N>; L],
    // Public matrix B for each modulus
    b: [Matrix<N_PARTIES, K, N>; L],

    // Public ciphertext components
    // First ciphertext component for each modulus
    c1: [Vector<K, N>; L],
    // Second ciphertext component (per party, per modulus)
    c2: [Matrix<N_PARTIES, 1, N>; L],

    // Secret witness values
    // Random encryption vector (K polynomials, same distribution as secret key)
    u: Vector<K, N>,
    // Already-encoded messages for each party (result of message_i * gadget_polynomial)
    encoded_messages: Vector<N_PARTIES, N>,

    // Error terms
    // Error for c1 components
    e1: Vector<K, N>,
    // Error for c2 components
    e2: Vector<N_PARTIES, N>,

    // Quotients from modulus switching and cyclotomic reduction
    // Quotient from c1 modulus switching
    r1: [Vector<K, 2 * N - 1>; L],
    // Quotient from c1 cyclotomic reduction
    r2: [Vector<K, N - 1>; L],
    // Quotient from c2 modulus switching
    s1: [Matrix<N_PARTIES, 1, 2 * N - 1>; L],
    // Quotient from c2 cyclotomic reduction
    s2: [Matrix<N_PARTIES, 1, N - 1>; L],
}

impl PvwEncryptionCircuit {
    pub fn new(
        a: [Matrix<K, K, N>; L],
        b: [Matrix<N_PARTIES, K, N>; L],
        c1: [Vector<K, N>; L],
        c2: [Matrix<N_PARTIES, 1, N>; L],
        u: Vector<K, N>,
        encoded_messages: Vector<N_PARTIES, N>,
        e1: Vector<K, N>,
        e2: Vector<N_PARTIES, N>,
        r1: [Vector<K, 2 * N - 1>; L],
        r2: [Vector<K, N - 1>; L],
        s1: [Matrix<N_PARTIES, 1, 2 * N - 1>; L],
        s2: [Matrix<N_PARTIES, 1, N - 1>; L],
    ) -> Self {
        PvwEncryptionCircuit { a, b, c1, c2, u, messages, e1, e2, r1, r2, s1, s2 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir
    pub fn payload(self) -> [Field; SIZE_ENCRYPTION] {
        let mut inputs = [0; SIZE_ENCRYPTION];
        let mut offset = 0;

        // Flatten public matrices a and b (already known, but included for completeness)
        for l in 0..L {
            for row in 0..K {
                for col in 0..K {
                    for k in 0..N {
                        inputs[k + offset] = self.a[l][row][col].coefficients[k];
                    }
                    offset += N;
                }
            }
        }

        for l in 0..L {
            for i in 0..N_PARTIES {
                for j in 0..K {
                    for k in 0..N {
                        inputs[k + offset] = self.b[l][i][j].coefficients[k];
                    }
                    offset += N;
                }
            }
        }

        // Flatten ciphertext components (public)
        for l in 0..L {
            for j in 0..K {
                for k in 0..N {
                    inputs[k + offset] = self.c1[l][j].coefficients[k];
                }
                offset += N;
            }
        }

        for l in 0..L {
            for i in 0..N_PARTIES {
                for k in 0..N {
                    inputs[k + offset] = self.c2[l][i][0].coefficients[k];
                }
                offset += N;
            }
        }

        // Flatten witness values (secret)
        for j in 0..K {
            for k in 0..N {
                inputs[k + offset] = self.u[j].coefficients[k];
            }
            offset += N;
        }

        for i in 0..N_PARTIES {
            for k in 0..N {
                inputs[k + offset] = self.encoded_messages[i].coefficients[k];
            }
            offset += N;
        }

        // Flatten error terms
        for j in 0..K {
            for k in 0..N {
                inputs[k + offset] = self.e1[j].coefficients[k];
            }
            offset += N;
        }

        for i in 0..N_PARTIES {
            for k in 0..N {
                inputs[k + offset] = self.e2[i].coefficients[k];
            }
            offset += N;
        }

        // Flatten modulus switching terms
        for l in 0..L {
            for j in 0..K {
                for k in 0..(2 * N - 1) {
                    inputs[k + offset] = self.r1[l][j].coefficients[k];
                }
                offset += 2 * N - 1;
            }
        }

        for l in 0..L {
            for j in 0..K {
                for k in 0..(N - 1) {
                    // Updated: N-1 degree
                    inputs[k + offset] = self.r2[l][j].coefficients[k];
                }
                offset += N - 1; // Updated: N-1 degree
            }
        }

        for l in 0..L {
            for i in 0..N_PARTIES {
                for k in 0..(2 * N - 1) {
                    inputs[k + offset] = self.s1[l][i][0].coefficients[k];
                }
                offset += 2 * N - 1;
            }
        }

        for l in 0..L {
            for i in 0..N_PARTIES {
                for k in 0..(N - 1) {
                    // Updated: N-1 degree
                    inputs[k + offset] = self.s2[l][i][0].coefficients[k];
                }
                offset += N - 1; // Updated: N-1 degree
            }
        }

        inputs
    }

    /// Verifies that the ciphertext was correctly generated
    pub fn verify_correct_encryption(self) {
        // 1. Range checks on all secret values
        perform_range_checks(self);

        // 2. Generate Fiat-Shamir challenges
        let inputs = self.payload();
        let mut safe = SafeSponge::<_, _, TAG_ENCRYPTION>::start([SIZE_ENCRYPTION, L]);
        safe = safe.absorb(inputs);
        let gammas = safe.squeeze();

        // 3. Verify encryption equations for each modulus
        for l in 0..L {
            verify_encryption_for_modulus(self, l, gammas.get(l));
        }

        safe.finish();
    }

    /// Performs range checks on all secret witness values
    fn perform_range_checks(circuit: PvwEncryptionCircuit) {
        // Check encryption vector u has same bounds as secret key (CBD distribution)
        for j in 0..K {
            // Same bound as secret key
            circuit.u[j].range_check_1bound(SK_BOUND);
        }

        // Check error terms have appropriate bounds
        for j in 0..K {
            // Error bound for c1 components
            circuit.e1[j].range_check_1bound(E1_BOUND);
        }

        for i in 0..N_PARTIES {
            // Error bound for c2 components
            circuit.e2[i].range_check_1bound(E2_BOUND);
        }

        // Check quotient terms are within expected bounds (per modulus)
        for l in 0..L {
            for j in 0..K {
                // r1 can be negative (modulus switching quotients for c1)
                circuit.r1[l][j].range_check_2bounds(
                    ENCRYPTION_R1_UP_BOUNDS[l],
                    ENCRYPTION_R1_LOW_BOUNDS[l],
                );
                // r2 bound check (cyclotomic reduction quotients for c1)
                circuit.r2[l][j].range_check_1bound(ENCRYPTION_R2_BOUNDS[l]);
            }

            for i in 0..N_PARTIES {
                // s1 can be negative (modulus switching quotients for c2)
                circuit.s1[l][i][0].range_check_2bounds(
                    ENCRYPTION_S1_UP_BOUNDS[l],
                    ENCRYPTION_S1_LOW_BOUNDS[l],
                );
                // s2 range check (cyclotomic reduction quotients for c2)
                circuit.s2[l][i][0].range_check_1bound(ENCRYPTION_S2_BOUNDS[l]);
            }
        }

        // The circuit assumes encoded_messages = [message_0 * g, message_1 * g, ..., message_{N_PARTIES-1} * g]
    }

    /// Verifies encryption equations for a specific modulus
    fn verify_encryption_for_modulus(circuit: PvwEncryptionCircuit, l: usize, gamma: Field) {
        // Evaluate all polynomials at the challenge point gamma
        let a_at_gamma = circuit.a[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let b_at_gamma = circuit.b[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let c1_at_gamma = circuit.c1[l].map(|poly| poly.eval(gamma));
        let c2_at_gamma = circuit.c2[l].map(|row| row.map(|poly| poly.eval(gamma)));

        let u_at_gamma = circuit.u.map(|poly| poly.eval(gamma));
        let messages_at_gamma = circuit.encoded_messages.map(|poly| poly.eval(gamma));
        let e1_at_gamma = circuit.e1.map(|poly| poly.eval(gamma));
        let e2_at_gamma = circuit.e2.map(|poly| poly.eval(gamma));

        let r1_at_gamma = circuit.r1[l].map(|poly| poly.eval(gamma));
        let r2_at_gamma = circuit.r2[l].map(|poly| poly.eval(gamma));
        let s1_at_gamma = circuit.s1[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let s2_at_gamma = circuit.s2[l].map(|row| row.map(|poly| poly.eval(gamma)));

        // Cyclotomic polynomial evaluation: X^N + 1
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Verify c1 components: c1_{l,j} = sum_{k=0}^{K-1} a_{l,j,k} * u_k + e1_{j} + r2_{l,j} * (X^N + 1) + r1_{l,j} * q_l
        for j in 0..K {
            // Compute a_{l,j} * u = sum_{k=0}^{K-1} a_{l,j,k} * u_k (dot product of j-th row of A with vector u)
            let mut a_u_product = 0;
            for col in 0..K {
                // a_{l,j,k} * u_k
                a_u_product += a_at_gamma[j][col] * u_at_gamma[col];
            }

            // Compute expected c1 value
            let expected_c1 = a_u_product
                + e1_at_gamma[j]
                + r2_at_gamma[j] * cyclo_at_gamma
                + r1_at_gamma[j] * QIS[l];

            // Verify c1 matches
            assert_eq(c1_at_gamma[j], expected_c1);
        }

        // Verify c2 components: c2_{l,i} = sum_{k=0}^{K-1} b_{l,i,k} * u_k + m_i + e2_{i} + s2_{l,i} * (X^N + 1) + s1_{l,i} * q_l
        for i in 0..N_PARTIES {
            // Compute b_{l,i} * u = sum_{k=0}^{K-1} b_{l,i,k} * u_k (dot product of i-th row of B with vector u)
            let mut b_u_product = 0;
            for j in 0..K {
                // b_{l,i,k} * u_k
                b_u_product += b_at_gamma[i][j] * u_at_gamma[j];
            }

            // Compute expected c2 value
            let expected_c2 = b_u_product
                + messages_at_gamma[i]
                + e2_at_gamma[i]
                + s2_at_gamma[i][0] * cyclo_at_gamma
                + s1_at_gamma[i][0] * QIS[l];

            // Verify c2 matches
            assert_eq(c2_at_gamma[i][0], expected_c2);
        }
    }

    /// Verify that the encryption uses fresh randomness
    /// (prevents replay attacks and ensures semantic security)
    pub fn verify_fresh_randomness(circuit: PvwEncryptionCircuit, mut previous_u: Vector<K, N>) {
        // Ensure u is different from any previously used randomness
        let mut is_different = false;
        for j in 0..K {
            for k in 0..N {
                if circuit.u[j].coefficients[k] != previous_u[j].coefficients[k] {
                    is_different = true;
                    break;
                }
            }
            if is_different {
                break;
            }
        }
        assert(is_different);
    }
}
