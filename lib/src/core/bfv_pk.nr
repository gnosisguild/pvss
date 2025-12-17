use crate::math::helpers::{compute_safe, flatten};
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for the BFV public key generation circuit.
///
/// This struct contains all the mathematical constants and bounds needed to verify
/// correct BFV public key generation. The circuit works for both standard BFV and
/// threshold BFV (trBFV) schemes.
///
/// # Generic Parameters
/// * `N` - The degree of polynomials (ring dimension, typically 8192)
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for error polynomial (eek) coefficients
    /// The error polynomial must have small coefficients for security
    pub eek_bound: Field,
    /// Bound for secret key polynomial (sk) coefficients
    /// The secret key must have small coefficients (from CBD distribution) for security
    pub sk_bound: Field,
    /// Bounds for r1 polynomials (modulus switching quotients) for each CRT basis
    /// These quotients can be negative, so bounds are symmetric around zero
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients) for each CRT basis
    /// These quotients are typically positive
    pub r2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    /// Creates a new `Configs` instance with the specified cryptographic parameters.
    ///
    /// # Arguments
    /// All parameters correspond to the fields of the `Configs` struct. See the struct
    /// documentation for details on each parameter.
    ///
    /// # Returns
    /// A new `Configs` instance ready for use with the `BfvPublicKey` circuit.
    pub fn new(
        qis: [Field; L],
        eek_bound: Field,
        sk_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, eek_bound, sk_bound, r1_bounds, r2_bounds }
    }
}

/// BFV Public Key Verification Circuit.
///
/// This circuit implements a zero-knowledge proof for the correct generation of a BFV
/// public key according to the BFV key generation protocol. It verifies that the public
/// key components (pk0, pk1) are correctly computed from the secret key, error polynomial,
/// and Common Reference String (CRS).
///
/// The circuit enforces the following core constraints:
/// 1. Range checks on all secret witnesses (secret key, error, quotients)
/// 2. Correct public key generation equations for each CRT basis:
///    - `pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i`
///    - `pk1_i = a_i`
///
/// The circuit uses the Schwartz-Zippel lemma to verify polynomial equations by
/// evaluating them at random challenge points generated via Fiat-Shamir.
///
/// # Public Key Generation Formula
///
/// For each CRT basis i:
/// - `pk0_i = -a_i * sk + eek + r2_i * cyclo + r1_i * q_i`
/// - `pk1_i = a_i`
///
/// Where:
/// - `a_i` is the i-th polynomial in the CRS (Common Reference String, one per modulus)
/// - `sk` is the secret key polynomial (same for all moduli, sampled from CBD)
/// - `eek` is the error polynomial (small coefficients, sampled from error distribution)
/// - `pk0_i`, `pk1_i` form the public key pair for modulus i
/// - `r1_i`, `r2_i` are quotient witnesses from modulus switching and cyclotomic reduction
/// - `cyclo = X^N + 1` is the cyclotomic polynomial
/// - `q_i` is the i-th CRT modulus
///
/// # Generic Parameters
/// * `N` - The degree of polynomials (ring dimension, typically 8192)
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
/// * `BIT_EEK` - Bit-width bound per coefficient for error polynomial `eek`
/// * `BIT_SK` - Bit-width bound per coefficient for secret key polynomial `sk`
/// * `BIT_R1` - Bit-width bound per coefficient for quotient polynomials `r1`
/// * `BIT_R2` - Bit-width bound per coefficient for quotient polynomials `r2`
///
/// # Circuit Inputs
/// * `a` - CRS polynomials (public inputs, one per CRT basis)
/// * `eek` - Error polynomial (secret witness)
/// * `sk` - Secret key polynomial (secret witness)
/// * `r1`, `r2` - Quotient polynomials (secret witnesses)
/// * `pk0`, `pk1` - Public key components (public outputs, one per CRT basis)
///
/// # Note
/// This circuit uses RNS (Residue Number System) representation for efficiency,
/// allowing operations to be performed independently modulo each CRT modulus.
pub struct BfvPublicKey<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<N, L>,

    // Common Reference String polynomials (public)
    // One polynomial per modulus i
    a: [Polynomial<N>; L],

    // Error polynomial (secret witness)
    // Small coefficients sampled from error distribution
    eek: Polynomial<N>,

    // Secret key polynomial (secret witness)
    // Small coefficients sampled from CBD (Centered Binomial Distribution)
    sk: Polynomial<N>,

    // Quotients from polynomial operations (secret witness)
    // r1[i] are quotients from modulus switching for modulus i (can be negative, degree 2*N-1)
    r1: [Polynomial<2 * N - 1>; L],
    // r2[i] are quotients from cyclotomic reduction for modulus i (typically positive, degree N-1)
    r2: [Polynomial<N - 1>; L],

    // BFV public key components (public output)
    // pk0[i] is the first component of the public key for modulus i
    pk0: [Polynomial<N>; L],
    // pk1[i] is the second component of the public key for modulus i (should equal a[i])
    pk1: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> BfvPublicKey<N, L, BIT_EEK, BIT_SK, BIT_R1, BIT_R2> {
    /// Creates a new `BfvPublicKey` circuit instance.
    ///
    /// This constructor initializes all the polynomials and parameters needed for
    /// the zero-knowledge proof of correct BFV public key generation.
    ///
    /// # Arguments
    /// * `configs` - Cryptographic parameters including bounds and moduli
    /// * `a` - CRS polynomials (Common Reference String, one per CRT basis)
    /// * `eek` - Error polynomial sampled from error distribution (secret witness)
    /// * `sk` - Secret key polynomial sampled from CBD (secret witness)
    /// * `r1` - Quotient polynomials from modulus switching (secret witnesses, degree 2N-1)
    /// * `r2` - Quotient polynomials from cyclotomic reduction (secret witnesses, degree N-1)
    /// * `pk0` - First component of public key for each CRT basis (public output)
    /// * `pk1` - Second component of public key for each CRT basis (public output, should equal `a`)
    ///
    /// # Returns
    /// A new `BfvPublicKey` instance ready for constraint checking via the `verify()` method
    pub fn new(
        configs: Configs<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        pk0: [Polynomial<N>; L],
        pk1: [Polynomial<N>; L],
    ) -> BfvPublicKey<N, L, BIT_EEK, BIT_SK, BIT_R1, BIT_R2> {
        BfvPublicKey { configs, a, eek, sk, r1, r2, pk0, pk1 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// This function serializes all polynomial coefficients (both public inputs and
    /// secret witnesses) into a 1D array in a deterministic order. The flattened data
    /// is used to generate the Fiat-Shamir challenges via the SAFE sponge API.
    ///
    /// The order of serialization is:
    /// 1. CRS polynomials `a` for each CRT basis
    /// 2. Error polynomial `eek`
    /// 3. Secret key polynomial `sk`
    /// 4. Quotient polynomials `r1` for each CRT basis
    /// 5. Quotient polynomials `r2` for each CRT basis
    ///
    /// # Returns
    /// A vector containing all polynomial coefficients in flattened form, ready for
    /// hashing to generate the Fiat-Shamir challenges.
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten CRS polynomials a (L polynomials of degree N)
        // These are public but included for completeness in the transcript
        inputs = flatten::<_, _, BIT_EEK>(inputs, self.a);

        // Flatten error polynomial eek (1 polynomial of degree N)
        // This is a secret witness that must remain hidden
        inputs = flatten::<_, _, BIT_EEK>(inputs, [self.eek]);

        // Flatten secret key polynomial sk (1 polynomial of degree N)
        // This is the most sensitive secret value
        inputs = flatten::<_, _, BIT_SK>(inputs, [self.sk]);

        // Flatten quotient polynomials (L polynomials each)
        // r1: quotients from modulus switching (degree 2*N-1)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        // r2: quotients from cyclotomic reduction (degree N-1)
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);

        inputs
    }

    /// Main verification function that performs all circuit checks.
    ///
    /// This function implements the complete zero-knowledge proof by verifying:
    /// 1. Range bounds on all secret witnesses (secret key, error, quotients)
    /// 2. Public key generation equations for each CRT basis (using Schwartz-Zippel)
    ///
    /// The proof uses the Schwartz-Zippel lemma: if polynomial equations hold when
    /// evaluated at random points, then the polynomials are identical with high probability.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any verification step fails.
    /// The circuit fails if:
    /// - Any witness is outside its expected bounds
    /// - Public key generation equations don't hold for any CRT basis
    pub fn verify(self) {
        // Step 1: Perform range checks on all secret witness values
        self.perform_range_checks();

        // Step 2: Generate Fiat-Shamir challenges from the transcript
        let gammas = self.generate_challenge();
        // Step 3: Verify public key equations for each modulus
        // For each modulus q_i, we evaluate all polynomials at a random challenge gamma
        // and verify the BFV public key generation relation holds
        for i in 0..L {
            let gamma = gammas.get(i);
            self.verify_public_key_for_modulus(i, gamma);
        }
    }

    /// Generates Fiat-Shamir challenge values using the SAFE cryptographic sponge.
    ///
    /// This function implements the Fiat-Shamir transform for the public key circuit:
    /// 1. Flattens all witness data (CRS, secrets, quotients) into a single array
    /// 2. Absorbs the flattened data into the SAFE sponge
    /// 3. Squeezes L challenge values (one per CRT basis)
    ///
    /// The challenges are used to evaluate polynomials for the Schwartz-Zippel lemma,
    /// which allows verification of polynomial equations by checking them at random
    /// points rather than checking all coefficients.
    ///
    /// # Returns
    /// Vector of challenge values [gamma_0, gamma_1, ..., gamma_{L-1}] where each
    /// `gamma_i` is used as the evaluation point for verifying the public key equation
    /// for CRT basis i.
    fn generate_challenge(self) -> Vec<Field> {
        // Domain separator for bfv_pk circuit - "bfv_pk" in hex
        let domain_separator = [
            0x62, 0x66, 0x76, 0x5f, 0x70, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(2 * L)
        let inputs = self.payload();
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        compute_safe(domain_separator, inputs, io_pattern)
    }

    /// Performs range checks on all secret witness values.
    ///
    /// This function constrains all secret witnesses to be within their expected bounds
    /// as specified in the `configs`. This is critical for security because it prevents
    /// attacks where malicious provers provide out-of-range values that could break the
    /// security properties of the BFV scheme.
    ///
    /// The function checks:
    /// - Error polynomial `eek` has small coefficients (required for security)
    /// - Secret key polynomial `sk` has small coefficients (required for security)
    /// - Quotient polynomials `r1` and `r2` are within bounds for each CRT basis
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// its expected bounds. The bounds are defined per polynomial type in the `configs`.
    fn perform_range_checks(self) {
        // Check that error polynomial has small coefficients
        // Small errors are crucial for both security and correctness in BFV
        self.eek.range_check_2bounds::<BIT_EEK>(self.configs.eek_bound, self.configs.eek_bound);

        // Check that secret key polynomial has small coefficients
        // Secret key must be small (from CBD distribution) for security
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        // Check quotient terms are within expected bounds (per modulus)
        for i in 0..L {
            // r1 quotients can be negative (modulus switching can produce negative quotients)
            // Use asymmetric bounds [R1_LOW_BOUNDS[i], R1_UP_BOUNDS[i]] for modulus i
            self.r1[i].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[i],
                self.configs.r1_bounds[i],
            );

            // r2 quotients are typically positive (cyclotomic reduction quotients)
            // Use symmetric bounds [-R2_BOUNDS[i], R2_BOUNDS[i]] for modulus i
            self.r2[i].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[i],
                self.configs.r2_bounds[i],
            );
        }
    }

    /// Verifies the BFV public key generation equations for a specific CRT basis using the Schwartz-Zippel lemma.
    ///
    /// This function verifies that the public key components for basis `i` satisfy:
    /// - `pk0_i(gamma) = -a_i(gamma) * sk(gamma) + eek(gamma) + r2_i(gamma) * cyclo(gamma) + r1_i(gamma) * q_i`
    /// - `pk1_i(gamma) = a_i(gamma)`
    ///
    /// Where:
    /// - `a_i` is the CRS polynomial for basis i
    /// - `sk` is the secret key polynomial
    /// - `eek` is the error polynomial
    /// - `r1_i`, `r2_i` are quotient witnesses
    /// - `cyclo(gamma) = gamma^N + 1` is the cyclotomic polynomial evaluated at gamma
    /// - `q_i` is the CRT modulus for basis i
    ///
    /// The Schwartz-Zippel lemma ensures that if these equations hold at a random point
    /// `gamma`, then the polynomials are identical with high probability.
    ///
    /// # Arguments
    /// * `i` - The index of the CRT basis to verify (0 <= i < L)
    /// * `gamma` - The Fiat-Shamir challenge value used as the evaluation point
    ///
    /// # Panics
    /// The circuit will fail if either public key equation doesn't hold for the specified basis.
    fn verify_public_key_for_modulus(self, i: u32, gamma: Field) {
        // Evaluate all polynomials at the random challenge point gamma
        // This reduces polynomial equations to field element equations

        // Evaluate CRS polynomials at gamma
        let a_at_gamma = self.a.map(|a_poly| a_poly.eval(gamma));

        // Evaluate secret values at gamma
        let eek_at_gamma = self.eek.eval(gamma);
        let sk_at_gamma = self.sk.eval(gamma);

        // Evaluate quotient polynomials at gamma
        let r1_at_gamma = self.r1.map(|r1_poly| r1_poly.eval(gamma));
        let r2_at_gamma = self.r2.map(|r2_poly| r2_poly.eval(gamma));

        // Evaluate public key polynomials at gamma
        let pk0_at_gamma = self.pk0.map(|pk0_poly| pk0_poly.eval(gamma));
        let pk1_at_gamma = self.pk1.map(|pk1_poly| pk1_poly.eval(gamma));

        // Evaluate the cyclotomic polynomial X^N + 1 at gamma
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Verify the BFV public key generation equations

        // Equation 1: pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
        // This is the main BFV public key equation
        let expected_pk0 = -a_at_gamma[i] * sk_at_gamma // -a_i * sk
            + eek_at_gamma // + eek (error term)
            + r2_at_gamma[i] * cyclo_at_gamma // + r2_i * (X^N + 1)
            + r1_at_gamma[i] * self.configs.qis[i]; // + r1_i * q_i

        assert_eq(pk0_at_gamma[i], expected_pk0);

        // Equation 2: pk1_i = a_i
        // The second component of BFV public key is just the CRS polynomial
        assert_eq(pk1_at_gamma[i], a_at_gamma[i]);
    }
}
