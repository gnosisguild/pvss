use crate::math::polynomial::{flatten, Polynomial};
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for BFV public key circuit.
pub struct CryptographicParams<let L: u32> {
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking in BFV public key circuit.
pub struct BoundParams<let L: u32> {
    pub eek_bound: Field,
    pub sk_bound: Field,
    pub r1_bounds: [Field; L],
    pub r2_bounds: [Field; L],
}

impl<let L: u32> BoundParams<L> {
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
pub struct Params<let N: u32, let L: u32> {
    pub crypto: CryptographicParams<L>,
    pub bounds: BoundParams<L>,
}

impl<let N: u32, let L: u32> Params<N, L> {
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

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams<L> {
        self.bounds
    }
}

/// BFV Public Key Verification Circuit
///
/// Returns commitment to sk for use in other circuits (e.g., SK shares circuit)
pub struct BfvPublicKeyCircuit<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> {
    params: Params<N, L>,
    a: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1: [Polynomial<2 * N - 1>; L],
    r2: [Polynomial<N - 1>; L],
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_R2: u32> BfvPublicKeyCircuit<N, L, BIT_EEK, BIT_SK, BIT_R1, BIT_R2> {
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

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(sk_payload);
        let commitment = sponge.squeeze();
        sponge.finish();

        commitment.get(0)
    }

    /// Flattens sk into Vec<Field> for commitment
    fn sk_payload(sk: Polynomial<N>) -> Vec<Field> {
        flatten::<_, _, BIT_SK>(Vec::new(), [sk])
    }

    /// Flattens witness data (using sk_commitment instead of full sk) for challenge generation
    fn payload(self, sk_commitment: Field) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten CRS polynomials a
        inputs = flatten::<_, _, BIT_EEK>(inputs, self.a);

        // Flatten error polynomial eek
        inputs = flatten::<_, _, BIT_EEK>(inputs, [self.eek]);

        // Use sk_commitment instead of full sk (saves N field elements!)
        inputs.push(sk_commitment);

        // Flatten quotient polynomials
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2);

        inputs
    }

    /// Main verification function
    /// Returns commitment to sk for use in other circuits
    pub fn verify_correct_public_key(self) -> Field {
        // Step 1: Perform range checks
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

    /// Generates Fiat-Shamir challenges using sk_commitment
    fn generate_challenge(self, sk_commitment: Field) -> Vec<Field> {
        // Domain separator - "PVSS_pk_trbfv" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let inputs = self.payload(sk_commitment);
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }

    /// Performs range checks on all secret witness values
    fn perform_range_checks(self) {
        let bound_params = self.params.bound_params();

        self.eek.range_check_2bounds::<BIT_EEK>(bound_params.eek_bound, bound_params.eek_bound);
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        for i in 0..L {
            self.r1[i].range_check_2bounds::<BIT_R1>(
                bound_params.r1_bounds[i],
                bound_params.r1_bounds[i],
            );
            self.r2[i].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[i],
                bound_params.r2_bounds[i],
            );
        }
    }

    /// Verifies the BFV public key generation equation for a specific modulus
    fn verify_public_key_for_modulus(self, i: u32, gamma: Field) {
        let a_at_gamma = self.a.map(|a_poly| a_poly.eval(gamma));
        let eek_at_gamma = self.eek.eval(gamma);
        let sk_at_gamma = self.sk.eval(gamma);
        let r1_at_gamma = self.r1.map(|r1_poly| r1_poly.eval(gamma));
        let r2_at_gamma = self.r2.map(|r2_poly| r2_poly.eval(gamma));
        let pk0_at_gamma = self.pk0.map(|pk0_poly| pk0_poly.eval(gamma));
        let pk1_at_gamma = self.pk1.map(|pk1_poly| pk1_poly.eval(gamma));

        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
        let expected_pk0 = -a_at_gamma[i] * sk_at_gamma
            + eek_at_gamma
            + r2_at_gamma[i] * cyclo_at_gamma
            + r1_at_gamma[i] * self.params.crypto.qis[i];

        assert_eq(pk0_at_gamma[i], expected_pk0);
        assert_eq(pk1_at_gamma[i], a_at_gamma[i]);
    }
}
