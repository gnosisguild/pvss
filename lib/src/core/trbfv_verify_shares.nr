use crate::math::helpers::{compute_safe, flatten};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for TRBFV secret share verification circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for secret key polynomial coefficients (trinary: -1, 0, 1)
    pub sk_bound: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], sk_bound: Field) -> Self {
        Configs { qis, sk_bound }
    }
}

/// TRBFV Secret Share Verification Circuit.
///
/// Verifies:
/// 1. sk commitment: verify sk hashes to expected_sk_commitment
/// 2. sk consistency: y[i][j][0] == sk[i] for all i, j
/// 3. Range check: sk coefficients are trinary (-1, 0, 1)
/// 4. Range check: shares are in [0, q_j)
/// 5. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
pub struct VerifyShares<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_SHARE: u32> {
    configs: Configs<L>,
    /// Expected commitment to sk (from BFV public key circuit)
    expected_sk_commitment: Field,
    /// Secret key polynomial (trinary coefficients)
    sk: Polynomial<N>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk[i] = f(0), y[i][j][k] = f(k) for k = 1..N_PARTIES
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) * (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_SHARE: u32> VerifyShares<N, L, N_PARTIES, T, BIT_SK, BIT_SHARE> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        sk: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        VerifyShares { configs, expected_sk_commitment, sk, y, h }
    }

    /// Main verification function
    pub fn verify(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify sk commitment matches expected
        self.verify_sk_commitment();

        // Step 2: Verify sk consistency
        self.verify_sk_consistency();

        // Step 3: Range checks
        self.check_range_bounds();

        // Step 4: Verify parity check
        self.verify_parity_check();

        // Step 5: Commit to shares for each party and modulus
        self.commit_to_party_shares()
    }

    /// Computes commitment to sk (must match BFV circuit's commit_to_sk)
    fn compute_sk_commitment(sk: Polynomial<N>) -> Field {
        let sk_payload = flatten::<_, _, BIT_SK>(Vec::new(), [sk]);

        // Domain separator - "PVSS_sk_comm" (must match BFV circuit)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = sk_payload.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, sk_payload, io_pattern).get(0)
    }

    /// Verifies that sk hashes to expected_sk_commitment
    fn verify_sk_commitment(self) {
        let computed_commitment = Self::compute_sk_commitment(self.sk);
        assert(computed_commitment == self.expected_sk_commitment, "SK commitment mismatch");
    }

    /// Verifies secret key consistency: `y[i][j][0] == sk[i]` for all i, j.
    ///
    /// This function ensures that for each coefficient i and CRT basis j, the share
    /// at party ID 0 equals the corresponding secret key coefficient. This is a
    /// fundamental property of Shamir secret sharing where the secret is the
    /// evaluation of the sharing polynomial at point 0.
    ///
    /// # Panics
    /// The circuit will fail if secret key consistency doesn't hold for any
    /// coefficient or CRT basis.
    fn verify_sk_consistency(self) {
        for coeff_idx in 0..N {
            let sk_coeff = self.sk.coefficients[coeff_idx];

            for mod_idx in 0..L {
                assert(self.y[coeff_idx][mod_idx][0] == sk_coeff);
            }
        }
    }

    /// Performs range checks on secret key and share values.
    ///
    /// This function constrains all values to be within their expected bounds:
    /// - Secret key coefficients must be trinary (-1, 0, 1) as required by BFV
    /// - Share values for parties k >= 1 must be in [0, q_j) for each CRT modulus q_j
    ///
    /// These bounds are critical for security and correctness of the threshold BFV scheme.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any value is outside
    /// its expected bounds.
    fn check_range_bounds(self) {
        // sk coefficients should be in {-1, 0, 1}
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        // Shares y[i][j][k] for k >= 1 should be in [0, q_j)
        for mod_idx in 0..L {
            let q_j = self.configs.qis[mod_idx];

            for coeff_idx in 0..N {
                for party_idx in 1..(N_PARTIES + 1) {
                    // Use range_check_standard from Polynomial by creating a single-coefficient polynomial
                    Polynomial::new([self.y[coeff_idx][mod_idx][party_idx]])
                        .range_check_standard::<BIT_SHARE>(q_j);
                }
            }
        }
    }

    /// Verifies Reed-Solomon parity check: `H[j] * y[i][j]^T == 0 mod q_j` for all i, j.
    ///
    /// This function verifies that for each coefficient i and CRT basis j, the share
    /// vector `y[i][j]` forms a valid Reed-Solomon codeword by satisfying the parity
    /// check equation with the parity check matrix `H[j]`.
    ///
    /// The parity check matrix H[j] has dimensions `(N_PARTIES - T) * (N_PARTIES + 1)`,
    /// and the share vector `y[i][j]` has length `N_PARTIES + 1`. The parity check
    /// ensures that any T+1 shares can correctly reconstruct the secret key via
    /// Lagrange interpolation.
    ///
    /// # Panics
    /// The circuit will fail if the parity check doesn't hold for any coefficient,
    /// CRT basis, or parity check row.
    fn verify_parity_check(self) {
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = self.configs.qis[mod_idx];

                // For each row of H, compute dot product with y and verify == 0
                for row in 0..(N_PARTIES - T) {
                    let mut sum: Field = 0;

                    for col in 0..(N_PARTIES + 1) {
                        sum = sum + self.h[mod_idx][row][col] * self.y[coeff_idx][mod_idx][col];
                    }

                    // Reduce mod q_j and verify == 0
                    let m = ModU128::new(q_j);
                    let result = m.reduce_mod(sum);
                    assert(result == 0, "Parity check failed");
                }
            }
        }
    }

    /// Flattens shares for a specific party and modulus into Vec<Field>
    /// Returns N field elements: y[0][mod_idx][party_idx+1], ..., y[N-1][mod_idx][party_idx+1]
    fn party_modulus_payload(self, party_idx: u32, mod_idx: u32) -> Vec<Field> {
        let mut inputs = Vec::new();

        for coeff_idx in 0..N {
            inputs.push(self.y[coeff_idx][mod_idx][party_idx + 1]);
        }

        inputs
    }

    /// Commits to shares
    fn commit_to_single_party_modulus(self, party_idx: u32, mod_idx: u32) -> Field {
        let inputs = self.party_modulus_payload(party_idx, mod_idx);
        // Domain separator - "PVSS_sh_pm" (shares party-modulus)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Include party_idx and mod_idx in the hash
        let mut inputs_with_indices = inputs;
        inputs_with_indices.push(party_idx as Field);
        inputs_with_indices.push(mod_idx as Field);
        let input_size = inputs_with_indices.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, inputs_with_indices, io_pattern).get(0)
    }

    /// Commits to shares for each party and modulus
    /// Returns [[Field; L]; N_PARTIES] where commitments[party_idx][mod_idx]
    fn commit_to_party_shares(self) -> [[Field; L]; N_PARTIES] {
        let mut commitments: [[Field; L]; N_PARTIES] = [[0; L]; N_PARTIES];

        for party_idx in 0..N_PARTIES {
            for mod_idx in 0..L {
                commitments[party_idx][mod_idx] =
                    self.commit_to_single_party_modulus(party_idx, mod_idx);
            }
        }

        commitments
    }
}
