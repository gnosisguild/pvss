use crate::core::commitments::{
    compute_secret_commitment, compute_shares_party_modulus_commitment,
    prepare_secret_commitment_payload, prepare_shares_party_modulus_commitment_payload,
};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for TRBFV secret share verification circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// TRBFV Secret Share Verification Circuit (Circuit 2).
///
/// Verifies:
/// 1. secret commitment: verify secret hashes to expected_secret_commitment
/// 2. secret consistency: y[i][j][0] == secret[i] for all i, j
/// 3. Range check: shares are in [0, q_j)
/// 4. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
pub struct VerifyShares<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> {
    configs: Configs<L>,
    /// Expected commitment to secret (from C1)
    /// This can be either commit(e_sm) or commit(sk_trbfv).
    expected_secret_commitment: Field,
    /// Secret polynomial (trinary coefficients)
    /// This can be either e_sm or sk_trbfv.
    secret: Polynomial<N>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk[i] = f(0), y[i][j][k] = f(k) for k = 1..N_PARTIES
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) * (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SECRET: u32, let BIT_SHARE: u32> VerifyShares<N, L, N_PARTIES, T, BIT_SECRET, BIT_SHARE> {
    pub fn new(
        configs: Configs<L>,
        expected_secret_commitment: Field,
        secret: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        VerifyShares { configs, expected_secret_commitment, secret, y, h }
    }

    /// Main verification function
    pub fn verify(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify secret commitment matches expected
        self.verify_secret_commitment();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Range checks
        self.check_range_bounds();

        // Step 4: Verify parity check
        self.verify_parity_check();

        // Step 5: Commit to shares for each party and modulus
        self.commit_to_party_shares()
    }

    /// Verifies that secret hashes to expected_secret_commitment
    fn verify_secret_commitment(self) {
        let payload = prepare_secret_commitment_payload::<N, L, BIT_SECRET>(self.secret);
        let computed_commitment = compute_secret_commitment(payload);
        assert(computed_commitment == self.expected_secret_commitment, "SK commitment mismatch");
    }

    /// Verifies secret consistency: `y[i][j][0] == secret[i]` for all i, j.
    ///
    /// This function ensures that for each coefficient i and CRT basis j, the share
    /// at party ID 0 equals the corresponding secret coefficient. This is a
    /// fundamental property of Shamir secret sharing where the secret is the
    /// evaluation of the sharing polynomial at point 0.
    ///
    /// # Panics
    /// The circuit will fail if secret consistency doesn't hold for any
    /// coefficient or CRT basis.
    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            let secret_coeff = self.secret.coefficients[coeff_idx];

            for mod_idx in 0..L {
                assert(self.y[coeff_idx][mod_idx][0] == secret_coeff);
            }
        }
    }

    /// Performs range checks on secret key and share values.
    ///
    /// This function constrains all values to be within their expected bounds:
    /// - Share values for parties k >= 1 must be in [0, q_j) for each CRT modulus q_j
    ///
    /// These bounds are critical for security and correctness of the threshold BFV scheme.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any value is outside
    /// its expected bounds.
    fn check_range_bounds(self) {
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

    /// Commits to shares for each party and modulus
    /// Returns [[Field; L]; N_PARTIES] where commitments[party_idx][mod_idx]
    fn commit_to_party_shares(self) -> [[Field; L]; N_PARTIES] {
        let mut commitments: [[Field; L]; N_PARTIES] = [[0; L]; N_PARTIES];

        for party_idx in 0..N_PARTIES {
            for mod_idx in 0..L {
                let payload = prepare_shares_party_modulus_commitment_payload::<N, L, N_PARTIES>(
                    self.y,
                    party_idx,
                    mod_idx,
                );

                commitments[party_idx][mod_idx] = compute_shares_party_modulus_commitment(payload);
            }
        }

        commitments
    }
}
