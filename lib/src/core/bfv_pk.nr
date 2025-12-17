use crate::math::helpers::{compute_safe, flatten};
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for BFV public key generation circuit.
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
/// Verifies:
/// 1. Range checks on all secret witnesses (secret key, error, quotients)
/// 2. Correct public key generation: pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
///    and pk1_i = a_i
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

    /// Computes commitment to the secret key
    fn commit_to_sk(self) -> Field {
        let sk_payload = Self::sk_payload(self.sk);

        // Domain separator - "PVSS_sk_comm" in hex
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

    /// Flattens sk into Vec<Field> for commitment
    fn sk_payload(sk: Polynomial<N>) -> Vec<Field> {
        flatten::<_, _, BIT_SK>(Vec::new(), [sk])
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    fn payload(self, sk_commitment: Field) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten CRS polynomials a (L polynomials of degree N)
        // These are public but included for completeness in the transcript
        inputs = flatten::<_, _, BIT_EEK>(inputs, self.a);

        // Flatten error polynomial eek (1 polynomial of degree N)
        // This is a secret witness that must remain hidden
        inputs = flatten::<_, _, BIT_EEK>(inputs, [self.eek]);

        // Use sk_commitment instead of full sk (saves N field elements!)
        inputs.push(sk_commitment);

        // Flatten quotient polynomials (L polynomials each)
        // r1: quotients from modulus switching (degree 2*N-1)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        // r2: quotients from cyclotomic reduction (degree N-1)
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);

        inputs
    }

    /// Main verification function
    pub fn verify(self) -> Field {
        // Step 1: Perform range checks on all secret witness values
        self.perform_range_checks();
        // Step 2: Compute sk commitment
        let sk_commitment = self.commit_to_sk();
        // Step 3: Generate Fiat-Shamir challenges using sk_commitment
        let gammas = self.generate_challenge(sk_commitment);
        // Step 4: Verify public key equations for each modulus
        for i in 0..L {
            let gamma = gammas.get(i);
            self.verify_public_key_for_modulus(i, gamma);
        }

        // Step 5: Return sk commitment for use in other circuits
        sk_commitment
    }

    /// Generates Fiat-Shamir challenge values using the SAFE cryptographic sponge
    fn generate_challenge(self, sk_commitment: Field) -> Vec<Field> {
        // Domain separator for bfv_pk circuit - "bfv_pk" in hex
        let domain_separator = [
            0x62, 0x66, 0x76, 0x5f, 0x70, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(2 * L)
        let inputs = self.payload(sk_commitment);
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        compute_safe(domain_separator, inputs, io_pattern)
    }

    /// Performs range checks on all secret witness values
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

    /// Verifies the BFV public key generation equations for a specific CRT basis using the Schwartz-Zippel lemma
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

        // pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
        let expected_pk0 = -a_at_gamma[i] * sk_at_gamma
            + eek_at_gamma
            + r2_at_gamma[i] * cyclo_at_gamma
            + r1_at_gamma[i] * self.configs.qis[i];

        assert_eq(pk0_at_gamma[i], expected_pk0);

        // Equation 2: pk1_i = a_i
        // The second component of BFV public key is just the CRS polynomial
        assert_eq(pk1_at_gamma[i], a_at_gamma[i]);
    }
}
