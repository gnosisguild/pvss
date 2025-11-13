use crate::math::polynomial::{flatten, Polynomial};
use safe::SafeSponge;

/// Cryptographic parameters for BFV public key circuit.
/// Contains the core mathematical constants used in the BFV encryption scheme.
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

/// Bound parameters for range checking in BFV public key circuit.
/// Contains all the bounds used to validate polynomial coefficients.
pub struct BoundParams<let L: u32> {
    /// Bound for error polynomials (eek)
    pub eek_bound: Field,
    /// Bound for secret key polynomials (sk)
    pub sk_bound: Field,
    /// Bounds for r1 polynomials (modulus switching quotients)
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients)
    pub r2_bounds: [Field; L],
}

impl<let L: u32> BoundParams<L> {
    /// Creates new bound parameters
    pub fn new(
        eek_bound: Field,
        sk_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        BoundParams { eek_bound, sk_bound, r1_bounds, r2_bounds }
    }
}

/// Complete parameters for BFV public key circuit.
/// Combines cryptographic parameters, bounds, and circuit-specific parameters.
pub struct Params<let N: u32, let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams<L>,
}

impl<let N: u32, let L: u32> Params<N, L> {
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        eek_bound: Field,
        sk_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(eek_bound, sk_bound, r1_bounds, r2_bounds);

        Params { crypto, bounds }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    /// Convenience method to access bound parameters
    pub fn bound_params(self) -> BoundParams<L> {
        self.bounds
    }
}

/// BFV Public Key Verification Circuit
///
/// Verifies that a BFV public key was correctly generated according to the protocol.
/// The BFV public key generation equation is:
/// pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
/// pk1_i = a_i
///
/// Where:
/// - a_i is the i-th polynomial in the CRS (one per modulus)
/// - sk is the secret key polynomial (same for all moduli)
/// - eek is the error polynomial (small coefficients)
/// - pk0_i, pk1_i form the public key pair for modulus i
/// - r1_i, r2_i are quotients from modulus switching and cyclotomic reduction
/// - L is the number of moduli, must equal the length of QIS array
/// - q_i = QIS[i] is the i-th modulus in the RNS representation
///
/// Note: This uses RNS (Residue Number System) representation for efficiency
pub struct BfvPublicKeyCircuit<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    params: Params<N, L>,

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

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> BfvPublicKeyCircuit<N, L, BIT_EEK, BIT_SK, BIT_R1, BIT_R2> {
    /// Creates a new BFV public key verification circuit
    pub fn new(
        params: Params<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        pk0: [Polynomial<N>; L],
        pk1: [Polynomial<N>; L],
    ) -> BfvPublicKeyCircuit<N, L, BIT_EEK, BIT_SK, BIT_R1, BIT_R2> {
        BfvPublicKeyCircuit { params, a, eek, sk, r1, r2, pk0, pk1 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    /// This creates a commitment to all the secret and public values used in the protocol
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten CRS polynomials a (L polynomials of degree N)
        // These are public but included for completeness in the transcript
        inputs = flatten::<_, _>(inputs, self.a);

        // Flatten error polynomial eek (1 polynomial of degree N)
        // This is a secret witness that must remain hidden
        inputs = flatten::<_, _>(inputs, [self.eek]);

        // Flatten secret key polynomial sk (1 polynomial of degree N)
        // This is the most sensitive secret value
        inputs = flatten::<_, _>(inputs, [self.sk]);

        // Flatten quotient polynomials (L polynomials each)
        // r1: quotients from modulus switching (degree 2*N-1)
        inputs = flatten::<_, _>(inputs, self.r1);
        // r2: quotients from cyclotomic reduction (degree N-1)
        inputs = flatten::<_, _>(inputs, self.r2);

        inputs
    }

    /// Main verification function for BFV public key correctness
    /// Uses the Fiat-Shamir heuristic to generate random challenges and verifies
    /// the public key equations at those challenge points
    pub fn verify_correct_public_key(self) {
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

    /// Generates Fiat-Shamir challenge values using a cryptographic sponge
    ///
    /// The sponge absorbs all witness values and squeezes out deterministic random field elements
    /// that will be used to evaluate polynomials for the Schwartz-Zippel lemma.
    ///
    /// # Returns
    /// Vector of challenge values [gamma_0, gamma_1, ..., gamma_{2L-1}]
    fn generate_challenge(self) -> Vec<Field> {
        // Domain separator for PVSS_pk_trbfv circuit - "PVSS_pk_trbfv" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(2 * L)
        let inputs = self.payload();
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }

    /// Performs comprehensive range checks on all secret witness values
    /// Ensures that secret keys, errors, and quotients are within cryptographically safe bounds
    fn perform_range_checks(self) {
        let bound_params = self.params.bound_params();

        // Check that error polynomial has small coefficients
        // Small errors are crucial for both security and correctness in BFV
        self.eek.range_check_2bounds::<BIT_EEK>(bound_params.eek_bound, bound_params.eek_bound);

        // Check that secret key polynomial has small coefficients
        // Secret key must be small (from CBD distribution) for security
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        // Check quotient terms are within expected bounds (per modulus)
        for i in 0..L {
            // r1 quotients can be negative (modulus switching can produce negative quotients)
            // Use asymmetric bounds [R1_LOW_BOUNDS[i], R1_UP_BOUNDS[i]] for modulus i
            self.r1[i].range_check_2bounds::<BIT_R1>(
                bound_params.r1_bounds[i],
                bound_params.r1_bounds[i],
            );

            // r2 quotients are typically positive (cyclotomic reduction quotients)
            // Use symmetric bounds [-R2_BOUNDS[i], R2_BOUNDS[i]] for modulus i
            self.r2[i].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[i],
                bound_params.r2_bounds[i],
            );
        }
    }

    /// Verifies the BFV public key generation equation for a specific modulus
    /// This is where the core BFV verification happens
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
            + r1_at_gamma[i] * self.params.crypto.qis[i]; // + r1_i * q_i

        assert_eq(pk0_at_gamma[i], expected_pk0);

        // Equation 2: pk1_i = a_i
        // The second component of BFV public key is just the CRS polynomial
        assert_eq(pk1_at_gamma[i], a_at_gamma[i]);
    }
}

