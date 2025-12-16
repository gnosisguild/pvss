use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for the TRBFV secret share verification circuit.
///
/// This struct contains all the mathematical constants and bounds needed to verify
/// correct Shamir secret sharing of the TRBFV secret key.
///
/// # Generic Parameters
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for secret key polynomial coefficients (trinary: -1, 0, 1)
    pub sk_bound: Field,
}

impl<let L: u32> Configs<L> {
    /// Creates a new `Configs` instance with the specified cryptographic parameters.
    ///
    /// # Arguments
    /// All parameters correspond to the fields of the `Configs` struct. See the struct
    /// documentation for details on each parameter.
    ///
    /// # Returns
    /// A new `Configs` instance ready for use with the `VerifyShares` circuit.
    pub fn new(qis: [Field; L], sk_bound: Field) -> Self {
        Configs { qis, sk_bound }
    }
}

/// TRBFV Secret Share Verification Circuit.
///
/// This circuit implements a zero-knowledge proof for the correct Shamir secret sharing
/// of the TRBFV secret key. It verifies that secret key shares are correctly generated
/// and satisfy the Reed-Solomon parity check constraints.
///
/// The circuit verifies:
/// 1. **Secret Key Consistency**: For each coefficient i and CRT basis j,
///    `y[i][j][0] == sk[i]`, ensuring shares at party ID 0 equal the secret key
/// 2. **Range Checks**: Secret key coefficients are trinary (-1, 0, 1) and shares
///    are in the valid range [0, q_j) for each CRT modulus
/// 3. **Parity Check**: For each coefficient i and CRT basis j, the Reed-Solomon
///    parity check matrix H[j] satisfies `H[j] * y[i][j]^T == 0 mod q_j`
///
/// The parity check ensures that shares form a valid Reed-Solomon codeword, which
/// guarantees that any T+1 shares can correctly reconstruct the secret key.
///
/// # Generic Parameters
/// * `N` - Number of TRBFV secret key coefficients (ring dimension)
/// * `L` - Number of CRT moduli
/// * `N_PARTIES` - Number of parties (shares per coefficient)
/// * `T` - Threshold (degree of sharing polynomial, need T+1 shares to reconstruct)
/// * `BIT_SK` - Bit-width bound per coefficient for secret key polynomial
/// * `BIT_SHARE` - Bit-width bound per coefficient for share values
pub struct VerifyShares<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_SHARE: u32> {
    configs: Configs<L>,
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
    /// Creates a new `VerifyShares` circuit instance.
    ///
    /// This constructor initializes all the polynomials and parameters needed for
    /// the zero-knowledge proof of correct secret key sharing.
    ///
    /// # Arguments
    /// * `configs` - Cryptographic parameters including moduli and bounds
    /// * `sk` - Secret key polynomial with trinary coefficients (secret witness)
    /// * `y` - Share values: `y[coeff_idx][mod_idx][party_idx]` where
    ///         `y[i][j][0] = sk[i]` and `y[i][j][k]` for k >= 1 are shares for party k
    /// * `h` - Parity check matrices: `H[mod_idx][row][col]` of size
    ///         `(N_PARTIES - T) * (N_PARTIES + 1)` for each CRT basis
    ///
    /// # Returns
    /// A new `VerifyShares` instance ready for constraint checking via the `verify()` method
    pub fn new(
        configs: Configs<L>,
        sk: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        VerifyShares { configs, sk, y, h }
    }

    /// Main verification function that performs all circuit checks.
    ///
    /// This function implements the complete zero-knowledge proof by verifying:
    /// 1. Secret key consistency across all CRT bases
    /// 2. Range bounds on secret key and share values
    /// 3. Reed-Solomon parity check constraints for all coefficients and CRT bases
    ///
    /// After successful verification, returns a commitment to the shares (excluding
    /// the secret key values) that can be used for public verification.
    ///
    /// # Returns
    /// A commitment hash to all share values (excluding secret key values), computed
    /// using the SAFE sponge API. This commitment can be used to verify that shares
    /// were correctly generated without revealing the secret key.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any verification step fails.
    /// The circuit fails if:
    /// - Secret key consistency doesn't hold for any coefficient or CRT basis
    /// - Any value is outside its expected bounds
    /// - Parity check doesn't hold for any coefficient or CRT basis
    pub fn verify(self) -> Field {
        // Step 1: Verify sk consistency
        self.verify_sk_consistency();

        // Step 2: Range checks
        self.check_range_bounds();

        // Step 3: Verify parity check
        self.verify_parity_check();

        // Step 4: Commit to shares (excluding sk values)
        Self::commit_to_shares(self.y)
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
                assert_eq(self.y[coeff_idx][mod_idx][0], sk_coeff);
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

    /// Flattens shares (excluding secret key values) into a single array.
    ///
    /// This function serializes all share values into a 1D array, excluding the
    /// secret key values at index 0. The flattened data is used to generate a
    /// commitment to the shares without revealing the secret key.
    ///
    /// # Arguments
    /// * `y` - Share values array: `y[coeff_idx][mod_idx][party_idx]`
    ///
    /// # Returns
    /// A vector containing all share values (excluding secret key values) in flattened form
    fn payload(y: [[[Field; N_PARTIES + 1]; L]; N]) -> Vec<Field> {
        let mut inputs = Vec::new();

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                // Only include shares, not sk (skip index 0)
                for party_idx in 1..(N_PARTIES + 1) {
                    inputs.push(y[coeff_idx][mod_idx][party_idx]);
                }
            }
        }

        inputs
    }

    /// Commits to shares using the SAFE cryptographic sponge.
    ///
    /// This function generates a cryptographic commitment to all share values
    /// (excluding secret key values) using the SAFE sponge API. The commitment
    /// can be used for public verification that shares were correctly generated
    /// without revealing the secret key.
    ///
    /// # Arguments
    /// * `y` - Share values array: `y[coeff_idx][mod_idx][party_idx]`
    ///
    /// # Returns
    /// A single field element representing the commitment hash to all shares
    fn commit_to_shares(y: [[[Field; N_PARTIES + 1]; L]; N]) -> Field {
        let inputs = Self::payload(y);

        // Domain separator - "PVSS_verify"
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let commitment = sponge.squeeze();
        sponge.finish();

        commitment.get(0)
    }
}
