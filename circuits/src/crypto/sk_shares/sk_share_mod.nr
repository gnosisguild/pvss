use crate::math::polynomial::{Matrix, Polynomial};
use safe::safe::SafeSponge;

/// Cryptographic parameters for SK shares circuit.
/// Contains the core mathematical constants used in the SK sharing scheme.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    /// Creates new cryptographic parameters
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking in SK shares circuit.
/// Contains all the bounds used to validate polynomial coefficients.
pub struct BoundParams {
    /// Bound for secret key polynomials (sk)
    pub sk_bound: u64,
    /// Bound for randomness values
    pub randomness_bound: u64,
}

impl BoundParams {
    /// Creates new bound parameters
    pub fn new(sk_bound: u64, randomness_bound: u64) -> Self {
        BoundParams { sk_bound, randomness_bound }
    }
}

/// Circuit-specific parameters for SK shares circuit.
/// Contains dimensions and other circuit-specific constants.
pub struct CircuitParams {
    /// The degree of polynomials (ring dimension)
    pub n: u32,
    /// Number of parties
    pub n_parties: u32,
    /// Threshold for Shamir's secret sharing
    pub t: u32,
}

impl CircuitParams {
    /// Creates new circuit parameters
    pub fn new(n: u32, n_parties: u32, t: u32) -> Self {
        CircuitParams { n, n_parties, t }
    }
}

/// Complete parameters for SK shares circuit.
/// Combines cryptographic parameters, bounds, and circuit-specific parameters.
pub struct Params<let N: u32, let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams,
    /// Circuit-specific parameters
    pub circuit: CircuitParams,
}

impl<let N: u32, let L: u32> Params<N, L> {
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        sk_bound: u64,
        randomness_bound: u64,
        n: u32,
        n_parties: u32,
        t: u32,
    ) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(sk_bound, randomness_bound);
        let circuit = CircuitParams::new(n, n_parties, t);

        Params { crypto, bounds, circuit }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    /// Convenience method to access bound parameters
    pub fn bound_params(self) -> BoundParams {
        self.bounds
    }

    /// Convenience method to access circuit parameters
    pub fn circuit_params(self) -> CircuitParams {
        self.circuit
    }
}

/// PVSS Circuit for TRBFV Secret Key Shamir Secret Shares
///
/// This circuit verifies the correct generation of Shamir secret shares for TRBFV secret keys
/// within a Publicly Verifiable Secret Sharing (PVSS) protocol. The circuit ensures that:
///
/// 1. Each coefficient a_i of the TRBFV secret key polynomial is properly shared using Shamir secret sharing
/// 2. The sharing polynomials f_{i,j} have degree T and are committed to prevent manipulation
/// 3. The generated shares y_{i,j,k} = f_{i,j}(x_k) mod q_j are correctly computed for each party k
/// 4. Secret consistency: f_{i,j}(0) = a_i for all coefficients and moduli
///
/// All polynomial evaluations use modular arithmetic (eval_mod) to handle intermediate overflow.
/// Input values (shares, polynomial coefficients) are already reduced modulo q_j.
///
/// TRBFV Context:
/// - The secret key sk is a polynomial of degree N-1 with small coefficients (< 20)
/// - Each coefficient a_i is shared independently across all RNS moduli q_j
/// - The resulting shares will be encrypted using PVW and broadcast for distributed key generation
///
/// PVSS Protocol Flow:
/// 1. Each party generates their TRBFV secret key polynomial sk with small coefficients
/// 2. This circuit proves correct Shamir sharing of sk coefficients modulo each q_j
/// 3. Shares are BFV encrypted and broadcast to all parties
/// 4. Parties can verify shares without learning the secret key
/// 5. Threshold reconstruction allows collaborative decryption operations
///
/// Security Model:
/// - Polynomials f_{i,j} are private witnesses (never revealed)
/// - Shares y_{i,j,k} are private but will be BFV encrypted for broadcast
/// - Only polynomial commitments are public
/// - Fiat-Shamir challenges prevent selective disclosure
pub struct SecretKeySharesCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    params: Params<N, L>,

    // === Public Inputs ===

    /// Evaluation points for each party (public party IDs: 1, 2, 3, ..., N_PARTIES)
    /// These are the x-coordinates used for evaluating Shamir sharing polynomials
    x_coords: [Field; N_PARTIES],

    // === Private Witnesses ===

    /// TRBFV secret key Shamir shares: y[i][j][k] = f[i][j](x_k) mod q_j
    /// Structure: shares[coefficient_index][modulus_index][party_index]
    /// All values are already reduced modulo q_j (in range [0, q_j))
    y: [[[Field; N_PARTIES]; L]; N],

    /// TRBFV secret key polynomial: sk = a_0 + a_1*x + ... + a_{N-1}*x^{N-1}
    /// Coefficients are small values (typically < 20)
    /// Each coefficient a_i will be shared using independent Shamir secret sharing
    sk: Polynomial<N>,

    /// Matrix of Shamir secret sharing polynomials f[i][j] of degree T
    /// f[i][j] is the polynomial used for sharing TRBFV coefficient a_i under modulus q_j
    /// All coefficients are already reduced modulo q_j (in range [0, q_j))
    /// Constraint: f[i][j](0) = a_i (constant term = a_i)
    /// Polynomial<T+1> has T+1 coefficients: [a_T, a_{T-1}, ..., a_1, a_0] (highest degree first)
    f: Matrix<N, L, T + 1>,

    /// Randomness used in polynomial commitments for hiding
    f_randomness: [[Field; L]; N],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32> SecretKeySharesCircuit<N, L, N_PARTIES, T> {
    /// Creates a new instance of the TRBFV secret key sharing circuit for PVSS
    pub fn new(
        params: Params<N, L>,
        x_coords: [Field; N_PARTIES],
        y: [[[Field; N_PARTIES]; L]; N],
        sk: Polynomial<N>,
        f: Matrix<N, L, T + 1>,
        f_randomness: [[Field; L]; N],
    ) -> Self {
        SecretKeySharesCircuit { params, x_coords, y, sk, f, f_randomness }
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
    /// Since x_coords are public party IDs, we verify they follow the expected pattern
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
        let crypto_params = self.params.crypto_params();

        for coefficient_idx in 0..N {
            let trbfv_secret_coeff = self.sk.coefficients[coefficient_idx];

            for modulus_idx in 0..L {
                let current_modulus = crypto_params.qis[modulus_idx];
                let sharing_poly = self.f[coefficient_idx][modulus_idx];

                // Verify share consistency using polynomial evaluation at challenge
                self.verify_shares_at_challenge(
                    coefficient_idx,
                    modulus_idx,
                    sharing_poly,
                    current_modulus,
                    gamma,
                );

                // Verify TRBFV secret consistency: f[i][j](0) = a_i
                // The constant term (coefficient of x^0) is at index T
                // Since polynomial is [a_T, a_{T-1}, ..., a_1, a_0], constant is at position T
                let constant_term = sharing_poly.coefficients[T];
                assert_eq(constant_term, trbfv_secret_coeff);
            }
        }
    }

    /// Verifies share consistency using random linear combination with challenge
    /// Uses powers of challenge as random coefficients instead of Lagrange interpolation
    /// All polynomial evaluations use eval_mod to handle intermediate overflow
    fn verify_shares_at_challenge(
        self,
        coefficient_idx: u32,
        modulus_idx: u32,
        sharing_poly: Polynomial<T + 1>,
        current_modulus: Field,
        gamma: Field,
    ) {
        // Use random linear combination to batch-verify all shares
        let mut lhs = 0; // Left side: sum of polynomial evaluations (mod q_j)
        let mut rhs = 0; // Right side: sum of shares

        for party_idx in 0..N_PARTIES {
            let x_k = self.x_coords[party_idx];
            let y_k = self.y[coefficient_idx][modulus_idx][party_idx];

            // Use powers of challenge as random coefficients
            let challenge_power = gamma.pow_32(party_idx as Field);

            // Evaluate polynomial at x_k using modular arithmetic
            // This handles intermediate overflow during Horner's method
            let poly_eval = sharing_poly.eval_mod(x_k, current_modulus);

            // Both poly_eval and y_k are in [0, q_j), so arithmetic stays in Noir field
            lhs = lhs + challenge_power * poly_eval;
            rhs = rhs + challenge_power * y_k;
        }

        // Direct comparison in Noir field (no final reduction needed)
        // Since both sides are sums of values in [0, q_j), they're equal in Noir field
        // if and only if they're equal modulo q_j
        assert_eq(lhs, rhs);
    }

    // === Helper Functions ===

    /// Generates Fiat-Shamir challenge from transcript
    /// Transcript includes: evaluation points + polynomial commitments + shares
    fn generate_challenge(self) -> Field {
        // Array size: x_coords + polynomial commitments + y values
        let mut transcript = [0; N_PARTIES + N * L + N * L * N_PARTIES];
        let mut offset = 0;

        // Add public evaluation points to transcript
        for i in 0..N_PARTIES {
            transcript[offset] = self.x_coords[i];
            offset += 1;
        }

        // Add polynomial commitments to transcript
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

        // Add all y values to transcript
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                for party_idx in 0..N_PARTIES {
                    transcript[offset] = self.y[coefficient_idx][modulus_idx][party_idx];
                    offset += 1;
                }
            }
        }

        // Generate challenge using SafeSponge
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let io_pattern = [0x80000000 | N_PARTIES + N * L + N * L * N_PARTIES, 0x00000000 | 1];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(transcript);
        let challenges = sponge.squeeze();
        sponge.finish();

        challenges.get(0)
    }

    /// Computes polynomial commitment using SafeSponge hash-based commitment
    /// Provides computational binding and hiding using the same primitive as the protocol
    fn compute_polynomial_commitment(polynomial: Polynomial<T + 1>, randomness: Field) -> Field {
        // Hash-based commitment: SafeSponge(polynomial_coefficients || randomness)
        // This provides computational binding and hiding properties

        let mut commitment_input = [0; T + 2]; // (T+1) coefficients + 1 randomness

        // Add polynomial coefficients (Polynomial<T+1> has T+1 coefficients: a_T, a_{T-1}, ..., a_0)
        for deg in 0..(T + 1) {
            commitment_input[deg] = polynomial.coefficients[deg];
        }

        // Add randomness for hiding property
        commitment_input[T + 1] = randomness;

        // Use SafeSponge to compute commitment hash
        // Domain separator for PVSS_sk_shares circuit - "PVSS_sk_shares" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(TRANSCRIPT_SIZE), SQUEEZE(1)
        let input_size = T + 2;
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (1)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(commitment_input);
        let commitment_hash = sponge.squeeze();
        sponge.finish();

        commitment_hash.get(0)
    }

    /// Performs range checks on all private witness values
    /// Ensures all values are within their expected bounds
    fn perform_range_checks(self) {
        let bound_params = self.params.bound_params();
        let crypto_params = self.params.crypto_params();

        // Check secret key coefficients are small (typically < 20)
        self.sk.range_check_1bound(bound_params.sk_bound);

        // Check sharing polynomial coefficients are in [0, q_j)
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let current_modulus = crypto_params.qis[modulus_idx];
                let poly = self.f[coefficient_idx][modulus_idx];

                // All coefficients should be in [0, q_j)
                for coeff_deg in 0..(T + 1) {
                    let coeff = poly.coefficients[coeff_deg];
                    assert(coeff as u64 < current_modulus as u64);
                }
            }
        }

        // Check shares are in [0, q_j)
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let modulus = crypto_params.qis[modulus_idx];
                for party_idx in 0..N_PARTIES {
                    let share = self.y[coefficient_idx][modulus_idx][party_idx];
                    assert(share as u64 < modulus as u64);
                }
            }
        }

        // Check commitment randomness is within bounds
        for coefficient_idx in 0..N {
            for modulus_idx in 0..L {
                let randomness = self.f_randomness[coefficient_idx][modulus_idx];
                let rand_shifted = randomness + bound_params.randomness_bound as Field;
                rand_shifted.assert_max_bit_size::<66>();
                (2 * bound_params.randomness_bound as Field - rand_shifted)
                    .assert_max_bit_size::<66>();
            }
        }
    }
}
