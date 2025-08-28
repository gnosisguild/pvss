use crate::crypto::sk_shares::constants::{
    D_LOWER_BOUND, D_UPPER_BOUND, L, N, N_PARTIES, QIS, R_LOWER_BOUND, R_UPPER_BOUND,
    RANDOMNESS_BOUND, SK_BOUND, T, TAG, TRANSCRIPT_SIZE,
};
use crate::math::polynomial::Polynomial;
use safe::safe::SafeSponge;

/// Matrix and Vector types for polynomial arrays (using your existing definitions)
pub type Matrix<let ROWS: u32, let COLS: u32, let POLY_SIZE: u32> = [[Polynomial<POLY_SIZE>; COLS]; ROWS];
pub type Vector<let SIZE: u32, let POLY_SIZE: u32> = [Polynomial<POLY_SIZE>; SIZE];

/// PVSS Circuit for TRBFV Secret Key Shamir Secret Shares
///
/// This circuit verifies the correct generation of Shamir secret shares for TRBFV secret keys
/// within a Publicly Verifiable Secret Sharing (PVSS) protocol. The circuit ensures that:
///
/// 1. Each coefficient a_i of the TRBFV secret key polynomial is properly shared using Shamir secret sharing
/// 2. The sharing polynomials f_{i,j} have degree T and are committed to prevent manipulation
/// 3. The generated shares y_{i,j,k} = f_{i,j}(x_k) are correctly computed for each party k
/// 4. Secret consistency: f_{i,j}(0) = a_i (mod q_j) for all coefficients and moduli
///
/// TRBFV Context:
/// - The secret key sk is a polynomial of degree N-1 used in TRBFV encryption/decryption
/// - Each coefficient a_i is shared independently across all RNS moduli q_j
/// - The resulting shares will be encrypted using PVW and broadcast for distributed key generation
///
/// PVSS Protocol Flow:
/// 1. Each party generates their TRBFV secret key polynomial sk
/// 2. This circuit proves correct Shamir sharing of sk coefficients
/// 3. Shares are PVW encrypted and broadcast to all parties
/// 4. Parties can verify shares without learning the secret key
/// 5. Threshold reconstruction allows collaborative decryption operations
///
/// Security Model:
/// - Polynomials f_{i,j} are private witnesses (never revealed)
/// - Shares y_{i,j,k} are private but will be PVW encrypted for broadcast
/// - Only polynomial commitments are public
/// - Fiat-Shamir challenges prevent selective disclosure
pub struct SecretKeySharesCircuit {
    // === Public Inputs ===

    /// Evaluation points for each party (public party IDs: 1, 2, 3, ..., N_PARTIES)
    /// These are the x-coordinates used for evaluating Shamir sharing polynomials
    x_coords: [Field; N_PARTIES],

    // === Private Witnesses ===

    /// TRBFV secret key Shamir shares: y[i][j][k] = f[i][j](x_k)
    /// Structure: shares[coefficient_index][modulus_index][party_index]
    /// These represent shares of TRBFV secret key coefficient a_i under modulus q_j for party k
    /// Since TRBFV secret key has N coefficients, we have N sets of shares
    /// Will be PVW encrypted before broadcast in the PVSS protocol
    y: [[[Field; N_PARTIES]; L]; N],

    /// TRBFV secret key polynomial: sk = a_0 + a_1*x + ... + a_{N-1}*x^{N-1}
    /// This is the polynomial used for TRBFV encryption/decryption operations
    /// Each coefficient a_i will be shared using independent Shamir secret sharing
    sk: Polynomial<N>,

    /// Matrix of Shamir secret sharing polynomials f[i][j] of degree T
    /// f[i][j] is the polynomial used for sharing TRBFV coefficient a_i under modulus q_j
    /// Constraint: f[i][j](0) = a_i (mod q_j)
    /// Since TRBFV secret key has N coefficients (a_0, ..., a_{N-1}), we have N polynomials
    /// Polynomial<T+1> has T+1 coefficients and degree T
    /// Requires T+1 parties to reconstruct the secret
    f: Matrix<N, L, T + 1>,
    /// Randomness used in polynomial commitments for hiding
    f_randomness: [[Field; L]; N],

    // === Auxiliary Witnesses ===

    /// Quotient values for share consistency: r[i][j][k] = (y[i][j][k] - f[i][j](x_k)) / q_j
    /// Used to prove y[i][j][k] = f[i][j](x_k) (mod q_j) in the larger field
    r: [[[Field; N_PARTIES]; L]; N],

    /// Quotient values for secret consistency: d[i][j] = (a_i - f[i][j](0)) / q_j
    /// Used to prove f[i][j](0) = a_i (mod q_j) in the larger field
    d: [[Field; L]; N],
}

impl SecretKeySharesCircuit {
    /// Creates a new instance of the TRBFV secret key sharing circuit for PVSS
    pub fn new(
        x_coords: [Field; N_PARTIES],
        y: [[[Field; N_PARTIES]; L]; N],
        sk: Polynomial<N>,
        f: Matrix<N, L, T + 1>,
        f_randomness: [[Field; L]; N],
        r: [[[Field; N_PARTIES]; L]; N],
        d: [[Field; L]; N],
    ) -> Self {
        SecretKeySharesCircuit { x_coords, y, sk, f, f_randomness, r, d }
    }

    /// Main circuit verification function for TRBFV secret key sharing in PVSS
    /// Computes polynomial commitments internally and uses them to generate challenge
    pub fn verify_correct_trbfv_secret_sharing(self) {
        // 1. Verify evaluation points are valid (basic sanity checks)
        self.verify_evaluation_points_validity();

        // 2. Perform range checks on all private values
        self.perform_range_checks();

        // 3. Generate Fiat-Shamir challenge from public inputs + polynomial commitments
        let gamma = self.generate_challenge();

        // 4. Verify TRBFV secret key sharing equations using the challenge
        self.verify_trbfv_sharing_equations(gamma);
    }

    /// Verifies evaluation points are valid for Shamir sharing
    /// Since x_coords are public party IDs, we just verify they follow the expected pattern
    fn verify_evaluation_points_validity(self) {
        // Verify that evaluation points are consecutive integers starting from 1
        // This is the standard pattern for party IDs in PVSS: 1, 2, 3, ..., N_PARTIES
        for party_idx in 0..N_PARTIES {
            let expected_id = (party_idx + 1) as Field;
            assert_eq(self.x_coords[party_idx], expected_id);
        }

        // All points are automatically distinct and non-zero since they're 1, 2, 3, ...
    }

    /// Verifies the TRBFV secret key sharing equations using Fiat-Shamir challenge
    /// All verification is done in zero-knowledge using the challenge point
    fn verify_trbfv_sharing_equations(self, gamma: Field) {
        for coefficient_idx in 0..N {
            let trbfv_secret_coeff = self.sk.coefficients[coefficient_idx];

            for modulus_idx in 0..L {
                let current_modulus = QIS[modulus_idx];
                let sharing_poly = self.f[coefficient_idx][modulus_idx];

                // Verify share consistency using polynomial evaluation at challenge
                self.verify_shares_at_challenge(
                    coefficient_idx,
                    modulus_idx,
                    sharing_poly,
                    current_modulus,
                    gamma,
                );

                // Verify TRBFV secret consistency: f[i][j](0) = a_i (mod q_j)
                let consistency_quotient = self.d[coefficient_idx][modulus_idx];
                let poly_at_zero = sharing_poly.eval(0);
                let reconstructed_coeff =
                    trbfv_secret_coeff + consistency_quotient * current_modulus;

                assert_eq(poly_at_zero, reconstructed_coeff);
            }
        }
    }

    /// Verifies share consistency using random linear combination with challenge
    /// Uses powers of challenge as random coefficients instead of Lagrange interpolation
    fn verify_shares_at_challenge(
        self,
        coefficient_idx: u32,
        modulus_idx: u32,
        sharing_poly: Polynomial<T + 1>,
        current_modulus: Field,
        gamma: Field,
    ) {
        // Use random linear combination instead of Lagrange interpolation
        let mut lhs = 0; // Left side: polynomial evaluations
        let mut rhs = 0; // Right side: reconstructed from shares

        for party_idx in 0..N_PARTIES {
            let x_k = self.x_coords[party_idx];
            let y_k = self.y[coefficient_idx][modulus_idx][party_idx];
            let r_k = self.r[coefficient_idx][modulus_idx][party_idx];

            // Use powers of challenge as random coefficients
            let challenge_power = gamma.pow_32(party_idx as Field);

            // Add contributions to the linear combination
            lhs += challenge_power * sharing_poly.eval(x_k);
            rhs += challenge_power * (y_k + r_k * current_modulus);
        }

        // Verify: random linear combination of f[i][j](x_k) equals random linear combination of shares
        assert_eq(lhs, rhs);
    }

    // === Helper Functions ===

    /// Generates Fiat-Shamir challenge from public inputs and polynomial commitments
    /// Commits to polynomials first, then includes commitments in transcript
    fn generate_challenge(self) -> Field {
        // Use pre-defined constant for transcript size
        // TRANSCRIPT_SIZE = N_PARTIES + N * L (defined in constants)
        let mut transcript = [0; TRANSCRIPT_SIZE];
        let mut offset = 0;

        // Add public evaluation points to transcript
        for i in 0..N_PARTIES {
            transcript[offset] = self.x_coords[i];
            offset += 1;
        }

        // Add polynomial commitments to transcript (not the polynomials themselves!)
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let polynomial = self.f[coefficient_idx][modulus_idx];
                let randomness = self.f_randomness[coefficient_idx][modulus_idx];

                // Compute commitment and add to transcript
                let commitment = Self::compute_polynomial_commitment(polynomial, randomness);
                transcript[offset] = commitment;
                offset += 1;
            }
        }

        // Generate challenge using SafeSponge
        let mut safe = SafeSponge::<_, _, TAG>::start([TRANSCRIPT_SIZE, 1]);
        safe = safe.absorb(transcript);
        let challenges = safe.squeeze();
        safe.finish();

        challenges.get(0)
    }

    /// Computes polynomial commitment using SafeSponge hash-based commitment
    /// Provides computational binding and hiding using the same primitive as the protocol
    fn compute_polynomial_commitment(polynomial: Polynomial<T + 1>, randomness: Field) -> Field {
        // Hash-based commitment: SafeSponge(polynomial_coefficients || randomness)
        // This provides computational binding and hiding properties

        let mut commitment_input = [0; T + 2]; // (T+1) coefficients + 1 randomness

        // Add polynomial coefficients (Polynomial<T+1> has T+1 coefficients: a_0, a_1, ..., a_T)
        for deg in 0..(T + 1) {
            commitment_input[deg] = polynomial.coefficients[deg];
        }

        // Add randomness for hiding property
        commitment_input[T + 1] = randomness;

        // Use SafeSponge to compute commitment hash
        let mut safe = SafeSponge::<_, _, TAG>::start([T + 2, 1]);
        safe = safe.absorb(commitment_input);
        let commitment_hash = safe.squeeze();
        safe.finish();

        commitment_hash.get(0)
    }

    /// Performs range checks on all private witness values
    fn perform_range_checks(self) {
        // Check secret key coefficients
        self.sk.range_check_1bound(SK_BOUND);

        // Check sharing polynomial coefficients
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let current_modulus = QIS[modulus_idx];
                self.f[coefficient_idx][modulus_idx].range_check_1bound(current_modulus as u64);
            }
        }

        // Check shares are within field bounds
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                for party_idx in 0..N_PARTIES {
                    // Shares should be reduced modulo q_j
                    let share = self.y[coefficient_idx][modulus_idx][party_idx];
                    let modulus = QIS[modulus_idx] as Field;
                    let shifted_share = share + modulus;
                    shifted_share.assert_max_bit_size::<66>();
                    (2 * modulus - shifted_share).assert_max_bit_size::<66>();

                    // Range check on share consistency quotients r[i][j][k]
                    let r_val = self.r[coefficient_idx][modulus_idx][party_idx];
                    let r_shift = (-1 * R_LOWER_BOUND) as u64 as Field;
                    let r_comp_value = r_shift + R_UPPER_BOUND as Field;
                    let r_shifted = r_val + r_shift;
                    r_shifted.assert_max_bit_size::<66>();
                    (r_comp_value - r_shifted).assert_max_bit_size::<66>();
                }
            }
        }

        // Check secret consistency quotients d[i][j]
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let d_val = self.d[coefficient_idx][modulus_idx];
                let d_shift = (-1 * D_LOWER_BOUND) as u64 as Field;
                let d_comp_value = d_shift + D_UPPER_BOUND as Field;
                let d_shifted = d_val + d_shift;
                d_shifted.assert_max_bit_size::<66>();
                (d_comp_value - d_shifted).assert_max_bit_size::<66>();
            }
        }

        // Check commitment randomness is within bounds
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let randomness = self.f_randomness[coefficient_idx][modulus_idx];
                let rand_shifted = randomness + RANDOMNESS_BOUND as Field;
                rand_shifted.assert_max_bit_size::<66>();
                (2 * RANDOMNESS_BOUND as Field - rand_shifted).assert_max_bit_size::<66>();
            }
        }
    }
}
