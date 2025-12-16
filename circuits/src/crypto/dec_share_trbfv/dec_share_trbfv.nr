use crate::math::polynomial::{flatten, Polynomial};
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for decryption share correctness circuit.
pub struct CryptographicParams<let L: u32> {
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking in decryption share circuit.
pub struct BoundParams<let L: u32> {
    pub decryption_share_bound: Field,
    pub r1_bounds: [Field; L],
    pub r2_bounds: [Field; L],
}

impl<let L: u32> BoundParams<L> {
    pub fn new(
        decryption_share_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        BoundParams { decryption_share_bound, r1_bounds, r2_bounds }
    }
}

/// Complete parameters for decryption share correctness circuit.
pub struct Params<let N: u32, let L: u32> {
    pub crypto: CryptographicParams<L>,
    pub bounds: BoundParams<L>,
}

impl<let N: u32, let L: u32> Params<N, L> {
    pub fn new(
        qis: [Field; L],
        decryption_share_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(decryption_share_bound, r1_bounds, r2_bounds);

        Params { crypto, bounds }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams<L> {
        self.bounds
    }
}

/// Decryption Share Correctness Circuit
///
/// Verifies:
/// 1. Commitment to s matches expected (from BFV decryption circuit - aggregated shares)
/// 2. Commitment to e matches expected (from BFV decryption circuit - aggregated noise shares)
/// 3. Correct computation of d = c_0 + c_1 * s + e (lifted formula)
///
/// Returns: Commitment to decryption shares d
pub struct DecryptionShareCorrectness<let N: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32> {
    /// Circuit parameters including bounds and cryptographic constants
    params: Params<N, L>,

    /// Expected commitment to aggregated shares s (from BFV decryption circuit)
    expected_s_commitment: Field,

    /// Expected commitment to aggregated noise e (from BFV decryption circuit)
    expected_e_commitment: Field,

    /// Ciphertext components (public inputs)
    c_0: [Polynomial<N>; L],
    c_1: [Polynomial<N>; L],

    /// Aggregated sum of shares s (secret witness)
    s: [Polynomial<N>; L],

    /// Aggregated sum of noise e (secret witness)
    e: [Polynomial<N>; L],

    /// Quotient polynomials for lifting to Z (secret witnesses)
    r_1: [Polynomial<2 * N - 1>; L],
    r_2: [Polynomial<N - 1>; L],

    /// Party's computed decryption share (public output)
    d: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_E: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_D: u32> DecryptionShareCorrectness<N, L, BIT_CT, BIT_S, BIT_E, BIT_R1, BIT_R2, BIT_D> {
    pub fn new(
        params: Params<N, L>,
        expected_s_commitment: Field,
        expected_e_commitment: Field,
        c_0: [Polynomial<N>; L],
        c_1: [Polynomial<N>; L],
        s: [Polynomial<N>; L],
        e: [Polynomial<N>; L],
        r_1: [Polynomial<2 * N - 1>; L],
        r_2: [Polynomial<N - 1>; L],
        d: [Polynomial<N>; L],
    ) -> Self {
        DecryptionShareCorrectness {
            params,
            expected_s_commitment,
            expected_e_commitment,
            c_0,
            c_1,
            s,
            e,
            r_1,
            r_2,
            d,
        }
    }

    /// Computes commitment to aggregated values (must match BFV decryption circuit)
    fn compute_aggregated_commitment(values: [Polynomial<N>; L]) -> Field {
        let mut inputs = Vec::new();

        for basis_idx in 0..L {
            for coeff_idx in 0..N {
                inputs.push(values[basis_idx].coefficients[coeff_idx]);
            }
        }

        // Domain separator - "PVSS_agg_sh" (must match BFV decryption circuit)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x61, 0x67, 0x67, 0x5f, 0x73, 0x68, 0x00, 0x00, 0x00,
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

    /// Verifies that s hashes to expected_s_commitment
    fn verify_s_commitment(self) {
        let computed_commitment = Self::compute_aggregated_commitment(self.s);
        assert_eq(computed_commitment, self.expected_s_commitment, "S commitment mismatch");
    }

    /// Verifies that e hashes to expected_e_commitment
    fn verify_e_commitment(self) {
        let computed_commitment = Self::compute_aggregated_commitment(self.e);
        assert_eq(computed_commitment, self.expected_e_commitment, "E commitment mismatch");
    }

    /// Commits to decryption shares d
    fn commit_to_decryption_shares(d: [Polynomial<N>; L]) -> Field {
        let mut inputs = Vec::new();

        for basis_idx in 0..L {
            for coeff_idx in 0..N {
                inputs.push(d[basis_idx].coefficients[coeff_idx]);
            }
        }

        // Domain separator - "PVSS_dec_sh" (decryption shares)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x64, 0x65, 0x63, 0x5f, 0x73, 0x68, 0x00, 0x00, 0x00,
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

    /// Flattens all witness data into a single vector for Fiat-Shamir challenge generation
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Use commitments instead of full polynomials (saves constraints)
        inputs.push(self.expected_s_commitment);
        inputs.push(self.expected_e_commitment);

        // Flatten ciphertext components (public inputs)
        inputs = flatten::<_, _, BIT_CT>(inputs, self.c_0);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.c_1);

        // Flatten quotient polynomials (secret witnesses)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r_1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r_2);

        // Flatten decryption shares (public outputs)
        inputs = flatten::<_, _, BIT_D>(inputs, self.d);

        inputs
    }

    /// Main verification function for decryption share correctness
    /// Returns commitment to decryption shares d
    pub fn verify_decryption_share_correctness(self) -> Field {
        // Step 1: Verify s commitment matches expected
        self.verify_s_commitment();

        // Step 2: Verify e commitment matches expected
        self.verify_e_commitment();

        // Step 3: Perform range checks on all secret witness values
        self.check_range_bounds();

        // Step 4: Generate Fiat-Shamir challenge from the transcript
        let gamma = self.generate_challenge();

        // Step 5: Verify decryption share computation for each CRT basis
        for i in 0..L {
            self.verify_decryption_share_computation(i, gamma);
        }

        // Step 6: Return commitment to decryption shares
        Self::commit_to_decryption_shares(self.d)
    }

    /// Performs comprehensive range checks on all secret witness values
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        // Check aggregated sums are within bounds
        for basis_idx in 0..L {
            self.s[basis_idx].range_check_2bounds::<BIT_S>(
                bound_params.r2_bounds[basis_idx],
                bound_params.r2_bounds[basis_idx],
            );
            self.e[basis_idx].range_check_2bounds::<BIT_E>(
                bound_params.r2_bounds[basis_idx],
                bound_params.r2_bounds[basis_idx],
            );
        }

        // Check quotient polynomials are within bounds
        for basis_idx in 0..L {
            self.r_1[basis_idx].range_check_2bounds::<BIT_R1>(
                bound_params.r1_bounds[basis_idx],
                bound_params.r1_bounds[basis_idx],
            );
            self.r_2[basis_idx].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[basis_idx],
                bound_params.r2_bounds[basis_idx],
            );
        }
    }

    /// Generates Fiat-Shamir challenge value using a cryptographic sponge
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        // Domain separator - "DecShare"
        let domain_separator = [
            0x44, 0x65, 0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

    /// Verifies the lifted decryption share computation formula for a specific CRT basis
    fn verify_decryption_share_computation(self, basis_idx: u32, gamma: Field) {
        let crypto_params = self.params.crypto_params();

        let c_0_at_gamma = self.c_0[basis_idx].eval(gamma);
        let c_1_at_gamma = self.c_1[basis_idx].eval(gamma);
        let s_at_gamma = self.s[basis_idx].eval(gamma);
        let e_at_gamma = self.e[basis_idx].eval(gamma);
        let r_1_at_gamma = self.r_1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r_2[basis_idx].eval(gamma);

        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // d_i = c_0i + c_1i * s + e_i + r_2_i * (X^N + 1) + r_1_i * q_i
        let expected_decryption_share = c_0_at_gamma
            + c_1_at_gamma * s_at_gamma
            + e_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * crypto_params.qis[basis_idx];

        let computed_decryption_share = self.d[basis_idx].eval(gamma);

        assert_eq(computed_decryption_share, expected_decryption_share);
    }
}
