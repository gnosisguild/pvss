use crate::math::modular_fns::mul_mod;
use crate::math::polynomial::{flatten, Polynomial};
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for EncryptionBfv circuit.
pub struct CryptographicParams<let L: u32> {
    /// Plaintext modulus t
    pub t: Field,
    /// Q mod t (for scaling message)
    pub q_mod_t: Field,
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Scaling factors for each basis: [k0_0, k0_1, ..., k0_{L-1}]
    pub k0is: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(t: Field, q_mod_t: Field, qis: [Field; L], k0is: [Field; L]) -> Self {
        CryptographicParams { t, q_mod_t, qis, k0is }
    }
}

/// Bound parameters for range checking.
pub struct BoundParams<let L: u32> {
    pub pk_bounds: [Field; L],
    pub e0_bound: Field,
    pub e1_bound: Field,
    pub u_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
    pub r2_bounds: [Field; L],
    pub p1_bounds: [Field; L],
    pub p2_bounds: [Field; L],
    pub msg_bound: Field,
}

impl<let L: u32> BoundParams<L> {
    pub fn new(
        pk_bounds: [Field; L],
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
        msg_bound: Field,
    ) -> Self {
        BoundParams {
            pk_bounds,
            e0_bound,
            e1_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            p1_bounds,
            p2_bounds,
            msg_bound,
        }
    }
}

/// Complete parameters for EncryptionBfv circuit.
pub struct Params<let N: u32, let L: u32> {
    pub crypto: CryptographicParams<L>,
    pub bounds: BoundParams<L>,
}

impl<let N: u32, let L: u32> Params<N, L> {
    pub fn new(
        t: Field,
        q_mod_t: Field,
        pk_bounds: [Field; L],
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
        msg_bound: Field,
        qis: [Field; L],
        k0is: [Field; L],
    ) -> Self {
        let crypto = CryptographicParams::new(t, q_mod_t, qis, k0is);
        let bounds = BoundParams::new(
            pk_bounds,
            e0_bound,
            e1_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            p1_bounds,
            p2_bounds,
            msg_bound,
        );

        Params { crypto, bounds }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams<L> {
        self.bounds
    }
}

/// EncryptionBfv - Correct Encryption Circuit under BFV public key
///
/// Verifies:
/// 1. Message commitment matches expected (from SK shares circuit)
/// 2. Correct BFV encryption of the message
pub struct EncryptionBfv<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> {
    params: Params<N, L>,
    /// Expected commitment to message (from SK shares verification circuit)
    expected_message_commitment: Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    e1: Polynomial<N>,
    /// Raw message polynomial (will be scaled to k1 inside circuit)
    message: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_MSG: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> EncryptionBfv<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_MSG, BIT_R1, BIT_R2, BIT_P1, BIT_P2> {
    pub fn new(
        params: Params<N, L>,
        expected_message_commitment: Field,
        pk0is: [Polynomial<N>; L],
        pk1is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e0is: [Polynomial<N>; L],
        e0_quotients: [Polynomial<N>; L],
        e1: Polynomial<N>,
        message: Polynomial<N>,
        r1is: [Polynomial<2 * N - 1>; L],
        r2is: [Polynomial<N - 1>; L],
        p1is: [Polynomial<2 * N - 1>; L],
        p2is: [Polynomial<N - 1>; L],
    ) -> Self {
        EncryptionBfv {
            params,
            expected_message_commitment,
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            u,
            e0,
            e0is,
            e0_quotients,
            e1,
            message,
            r1is,
            r2is,
            p1is,
            p2is,
        }
    }

    /// Computes commitment to message (must match SK shares circuit)
    fn compute_message_commitment(message: Polynomial<N>) -> Field {
        let mut inputs = Vec::new();

        for i in 0..N {
            inputs.push(message.coefficients[i]);
        }

        // Domain separator - "PVSS_sh_pm" (must match SK shares circuit)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00,
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

    /// Verifies that message hashes to expected_message_commitment
    fn verify_message_commitment(self) {
        let computed_commitment = Self::compute_message_commitment(self.message);
        assert_eq(
            computed_commitment,
            self.expected_message_commitment,
            "Message commitment mismatch",
        );
    }

    /// Computes the scaled message k1 from the raw message
    /// k1[i] = (q_mod_t * message[i]) mod t
    fn compute_scaled_message(self) -> Polynomial<N> {
        let crypto_params = self.params.crypto_params();
        let mut k1_coeffs: [Field; N] = [0; N];

        for i in 0..N {
            k1_coeffs[i] = mul_mod(
                crypto_params.q_mod_t,
                self.message.coefficients[i],
                crypto_params.t,
            );
        }

        Polynomial { coefficients: k1_coeffs }
    }

    /// Flattens all polynomials coefficients for challenge generation.
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk0is);
        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk1is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1is);

        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E1>(inputs, [self.e1]);
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u]);

        // Use message commitment instead of full message
        inputs.push(self.expected_message_commitment);

        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1is);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2is);
        inputs = flatten::<_, _, BIT_P1>(inputs, self.p1is);
        inputs = flatten::<_, _, BIT_P2>(inputs, self.p2is);

        inputs
    }

    /// Performs coefficient-wise CRT consistency check for e0 polynomial.
    fn check_e0_crt_consistency(self) {
        let crypto_params = self.params.crypto_params();

        for i in 0..L {
            for j in 0..N {
                assert(
                    self.e0.coefficients[j]
                        == self.e0is[i].coefficients[j]
                            + self.e0_quotients[i].coefficients[j] * crypto_params.qis[i],
                );
            }
        }
    }

    /// Verifies the correct encryption constraints.
    pub fn verify(self) -> bool {
        // Step 1: Verify message commitment matches expected
        self.verify_message_commitment();

        // Step 2: Perform range checks
        self.check_range_bounds();

        // Step 3: Check CRT consistency for e0
        self.check_e0_crt_consistency();

        // Step 4: Compute scaled message k1
        let k1 = self.compute_scaled_message();

        // Step 5: Generate Fiat-Shamir challenges
        let gammas = self.generate_challenge();

        // Step 6: Verify encryption constraints
        self.verify_evaluations(gammas, k1)
    }

    /// Performs range checks on all polynomial coefficients
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        self.u.range_check_2bounds::<BIT_U>(bound_params.u_bound, bound_params.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(bound_params.e0_bound, bound_params.e0_bound);
        self.e1.range_check_2bounds::<BIT_E1>(bound_params.e1_bound, bound_params.e1_bound);

        // Message should be in [0, t)
        self.message.range_check_standard::<BIT_MSG>(bound_params.msg_bound);

        for i in 0..L {
            self.pk0is[i].range_check_2bounds::<BIT_PK>(
                bound_params.pk_bounds[i],
                bound_params.pk_bounds[i],
            );
            self.pk1is[i].range_check_2bounds::<BIT_PK>(
                bound_params.pk_bounds[i],
                bound_params.pk_bounds[i],
            );

            self.r1is[i].range_check_2bounds::<BIT_R1>(
                bound_params.r1_up_bounds[i],
                bound_params.r1_low_bounds[i],
            );
            self.r2is[i].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[i],
                bound_params.r2_bounds[i],
            );

            self.p1is[i].range_check_2bounds::<BIT_P1>(
                bound_params.p1_bounds[i],
                bound_params.p1_bounds[i],
            );
            self.p2is[i].range_check_2bounds::<BIT_P2>(
                bound_params.p2_bounds[i],
                bound_params.p2_bounds[i],
            );
        }
    }

    /// Generates Fiat-Shamir challenge values
    fn generate_challenge(self) -> Vec<Field> {
        let inputs = self.payload();

        // Domain separator - "EncBfv"
        let domain_separator = [
            0x45, 0x6e, 0x63, 0x42, 0x66, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }

    /// Verifies encryption constraints using Fiat-Shamir challenges
    fn verify_evaluations(self, gammas: Vec<Field>, k1: Polynomial<N>) -> bool {
        let crypto_params = self.params.crypto_params();
        let gamma = gammas.get(0);

        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma);
        let e1_at_gamma = self.e1.eval(gamma);
        let k1_at_gamma = k1.eval(gamma);

        let mut sum = (0, 0);
        for i in 0..L {
            let pk0is_at_gamma = self.pk0is[i].eval(gamma);
            let r1i_at_gamma = self.r1is[i].eval(gamma);
            let r2i_at_gamma = self.r2is[i].eval(gamma);
            let e0is_at_gamma = self.e0is[i].eval(gamma);

            let pk0_u = (pk0is_at_gamma * u_at_gamma) + e0is_at_gamma;
            let mut ct0_rhs = pk0_u + (k1_at_gamma * crypto_params.k0is[i]);
            ct0_rhs += r1i_at_gamma * crypto_params.qis[i];
            ct0_rhs += r2i_at_gamma * cyclo_at_gamma;

            let ct0_lhs = self.ct0is[i].eval(gamma);

            let pk1is_at_gamma = self.pk1is[i].eval(gamma);
            let p1is_at_gamma = self.p1is[i].eval(gamma);
            let p2is_at_gamma = self.p2is[i].eval(gamma);

            let pk1_u = (pk1is_at_gamma * u_at_gamma) + e1_at_gamma;
            let mut ct1_rhs = pk1_u + p2is_at_gamma * cyclo_at_gamma;
            ct1_rhs += p1is_at_gamma * crypto_params.qis[i];

            let ct1_lhs = self.ct1is[i].eval(gamma);

            let gamma_i = if i == 0 { 1 } else { gammas.get(i) };

            sum = (
                sum.0 + ct0_lhs * gamma_i + ct1_lhs * gammas.get(i + L),
                sum.1 + ct0_rhs * gamma_i + ct1_rhs * gammas.get(i + L),
            );
        }

        sum.0 == sum.1
    }
}
