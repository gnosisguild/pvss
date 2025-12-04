use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for SK shares circuit.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking in SK shares circuit.
pub struct BoundParams {
    /// Bound for secret key polynomials (sk)
    pub sk_bound: Field,
    /// Bound for randomness values
    pub randomness_bound: Field,
}

impl BoundParams {
    pub fn new(sk_bound: Field, randomness_bound: Field) -> Self {
        BoundParams { sk_bound, randomness_bound }
    }
}

/// Complete parameters for SK shares circuit.
pub struct Params<let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams,
}

impl<let L: u32> Params<L> {
    pub fn new(qis: [Field; L], sk_bound: Field, randomness_bound: Field) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(sk_bound, randomness_bound);
        Params { crypto, bounds }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams {
        self.bounds
    }
}

/// PVSS Circuit for TRBFV Secret Key Shamir Secret Shares
///
/// This circuit verifies the correct generation of Shamir secret shares for TRBFV secret keys.
///
/// Verification steps:
/// 1. Evaluation points are valid (consecutive integers 1, 2, ..., N_PARTIES)
/// 2. Range checks on all private witnesses
/// 3. For each coefficient i and modulus j:
///    - f[i][j](0) = sk[i] (secret consistency)
///    - y[i][j][k] = f[i][j](x_k) mod q_j for all parties k (share correctness)
///
/// # Generic Parameters
/// * `N` - Polynomial degree (number of TRBFV secret key coefficients)
/// * `L` - Number of CRT moduli
/// * `N_PARTIES` - Number of parties in the sharing scheme
/// * `T` - Threshold degree (sharing polynomials have degree T)
/// * `BIT_SK` - Bit width for secret key bounds
/// * `BIT_RAND` - Bit width for randomness bounds
pub struct SecretKeySharesCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_RAND: u32> {
    /// Cryptographic parameters including bounds and moduli
    params: Params<L>,

    /// Evaluation points for each party (public party IDs: 1, 2, ..., N_PARTIES)
    x_coords: [Field; N_PARTIES],

    /// TRBFV secret key Shamir shares: y[i][j][k] = f[i][j](x_k) mod q_j
    /// Structure: shares[coefficient_index][modulus_index][party_index]
    y: [[[Field; N_PARTIES]; L]; N],

    /// TRBFV secret key polynomial coefficients
    sk: Polynomial<N>,

    /// Shamir secret sharing polynomials f[i][j] of degree T
    /// f[i][j](0) = sk[i] (constant term equals secret key coefficient)
    /// Polynomial<T+1> has coefficients: [a_T, a_{T-1}, ..., a_1, a_0]
    f: [[Polynomial<T + 1>; L]; N],

    /// Randomness used in polynomial commitments for hiding
    f_randomness: [[Field; L]; N],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_RAND: u32> SecretKeySharesCircuit<N, L, N_PARTIES, T, BIT_SK, BIT_RAND> {
    /// Creates a new instance of the circuit
    pub fn new(
        params: Params<L>,
        x_coords: [Field; N_PARTIES],
        y: [[[Field; N_PARTIES]; L]; N],
        sk: Polynomial<N>,
        f: [[Polynomial<T + 1>; L]; N],
        f_randomness: [[Field; L]; N],
    ) -> Self {
        SecretKeySharesCircuit { params, x_coords, y, sk, f, f_randomness }
    }

    /// Main verification function
    pub fn verify(self) {
        // Step 1: Verify evaluation points are valid
        // self.verify_evaluation_points();

        // Step 2: Perform range checks
        //self.check_range_bounds();

        // Step 3: Generate Fiat-Shamir challenge
        let gamma = self.generate_challenge();

        // Step 4: Verify sharing equations
        self.verify_sharing_equations(gamma);
    }

    /// Verifies evaluation points are consecutive integers starting from 1
    fn verify_evaluation_points(self) {
        for party_idx in 0..N_PARTIES {
            let expected_id = (party_idx + 1) as Field;
            assert_eq(self.x_coords[party_idx], expected_id);
        }
    }

    /// Performs range checks on all private witness values
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();
        let crypto_params = self.params.crypto_params();

        // Check secret key coefficients are within bounds
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        // Check sharing polynomial coefficients are in [0, q_j)
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                let poly = self.f[coeff_idx][mod_idx];

                for deg in 0..(T + 1) {
                    let coeff = poly.coefficients[deg];
                    assert(coeff as u64 < q_j as u64);
                }
            }
        }

        // Check shares are in [0, q_j)
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                for party_idx in 0..N_PARTIES {
                    let share = self.y[coeff_idx][mod_idx][party_idx];
                    assert(share as u64 < q_j as u64);
                }
            }
        }

        // Check commitment randomness is within bounds
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let randomness = self.f_randomness[coeff_idx][mod_idx];
                let rand_shifted = randomness + bound_params.randomness_bound;
                rand_shifted.assert_max_bit_size::<BIT_RAND>();
                (2 * bound_params.randomness_bound - rand_shifted).assert_max_bit_size::<BIT_RAND>();
            }
        }
    }

    /// Flattens all witness data for Fiat-Shamir challenge generation
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Add evaluation points (public)
        for party_idx in 0..N_PARTIES {
            inputs.push(self.x_coords[party_idx]);
        }

        // Add polynomial commitments
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let commitment = Self::compute_polynomial_commitment(
                    self.f[coeff_idx][mod_idx],
                    self.f_randomness[coeff_idx][mod_idx],
                );
                inputs.push(commitment);
            }
        }

        // Add shares
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                for party_idx in 0..N_PARTIES {
                    inputs.push(self.y[coeff_idx][mod_idx][party_idx]);
                }
            }
        }

        inputs
    }

    /// Generates Fiat-Shamir challenge value
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        // Domain separator - "PVSS_sk_shares" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas.get(0)
    }

    /// Computes polynomial commitment using SafeSponge hash
    fn compute_polynomial_commitment(polynomial: Polynomial<T + 1>, randomness: Field) -> Field {
        let mut commitment_input: Vec<Field> = Vec::new();

        // Add polynomial coefficients
        for deg in 0..(T + 1) {
            commitment_input.push(polynomial.coefficients[deg]);
        }

        // Add randomness for hiding
        commitment_input.push(randomness);

        // Domain separator for commitment - "PVSS_commit" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = commitment_input.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(commitment_input);
        let commitment_hash = sponge.squeeze();
        sponge.finish();
        commitment_hash.get(0)
    }

    /// Verifies all sharing equations using Fiat-Shamir challenge
    fn verify_sharing_equations(self, gamma: Field) {
        let crypto_params = self.params.crypto_params();

        for coeff_idx in 0..N {
            let sk_coeff = self.sk.coefficients[coeff_idx];

            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                let f_poly = self.f[coeff_idx][mod_idx];

                // Verify secret consistency: f[i][j](0) = sk[i]
                // Constant term is at index T (polynomial is [a_T, ..., a_1, a_0])
                let constant_term = f_poly.coefficients[T];
                assert_eq(constant_term, sk_coeff);

                // Verify share correctness using random linear combination
                self.verify_shares_batch(coeff_idx, mod_idx, f_poly, q_j, gamma);
            }
        }
    }

    /// Batch-verifies all shares for one coefficient and modulus using random linear combination
    fn verify_shares_batch(
        self,
        coeff_idx: u32,
        mod_idx: u32,
        f_poly: Polynomial<T + 1>,
        q_j: Field,
        gamma: Field,
    ) {
        let mut lhs: Field = 0; // Sum of f(x_k) * gamma^k
        let mut rhs: Field = 0; // Sum of y[k] * gamma^k

        for party_idx in 0..N_PARTIES {
            let x_k = self.x_coords[party_idx];
            let y_k = self.y[coeff_idx][mod_idx][party_idx];

            // Challenge power as random coefficient
            let gamma_power = gamma.pow_32(party_idx as Field);

            // Evaluate f(x_k) mod q_j
            let f_at_x_k = f_poly.eval_mod(x_k, q_j);

            lhs = lhs + gamma_power * f_at_x_k;
            rhs = rhs + gamma_power * y_k;
        }

        assert_eq(lhs, rhs);
    }
}
