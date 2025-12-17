use crate::math::helpers::{compute_safe, flatten};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;
use dep::bignum::BigNum;
use dep::bignum::bignum::to_field;
use dep::bignum::Enclave_TRBFV_8192;

/// Cryptographic parameters for BFV decryption circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Plaintext modulus (denoted as `t` in BFV literature)
    pub plaintext_modulus: Field,
    /// Modular inverse: Q^(-1) mod t, where Q is the product of all CRT moduli
    pub q_inverse_mod_t: Field,
    /// Bound for secret key sum s (used for range checking)
    pub s_bound: Field,
    /// Bounds for u_i polynomials (per-basis decryption results) for each CRT basis
    pub u_i_bounds: [Field; L],
    /// Bound for global u polynomial (reconstructed from CRT bases)
    pub u_global_bound: Field,
    /// Bounds for r_1 polynomials (modulus switching quotients) for each CRT basis
    pub r1_bounds: [Field; L],
    /// Bounds for r_2 polynomials (cyclotomic reduction quotients) for each CRT basis
    pub r2_bounds: [Field; L],
    /// Global delta value: delta = floor(Q/t) where Q is the product of all q_i
    /// Used in the decoding formula to scale the plaintext
    pub delta: Field,
    /// Global half-delta value: delta_half = floor(delta / 2)
    /// Used to check the noise bound: |u_global - delta * m| < delta/2
    pub delta_half: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(
        qis: [Field; L],
        plaintext_modulus: Field,
        q_inverse_mod_t: Field,
        s_bound: Field,
        u_i_bounds: [Field; L],
        u_global_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
        delta: Field,
        delta_half: Field,
    ) -> Self {
        Configs {
            qis,
            plaintext_modulus,
            q_inverse_mod_t,
            s_bound,
            u_i_bounds,
            u_global_bound,
            r1_bounds,
            r2_bounds,
            delta,
            delta_half,
        }
    }
}

/// Honest Ciphertext Aggregation and Decryption Circuit for BFV.
///
/// Verifies:
/// 1. Ciphertext aggregation: H honest ciphertexts sum correctly
/// 2. Decryption formula: u_i = c_0i + c_1i * s + r_2_i * (X^N + 1) + r_1_i * q_i
/// 3. CRT reconstruction: u_i + quotient_i * q_i = u_global
/// 4. Correct decoding: |u_global - delta * m| < delta/2
pub struct BfvDec<let N: u32, let H: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_NOISE: u32> {
    /// Circuit parameters
    configs: Configs<L>,

    /// H honest party ciphertexts (public inputs)
    /// Format: honest_ciphertexts[party_idx][basis_idx] = (c_0, c_1)
    honest_c0: [[Polynomial<N>; L]; H],
    honest_c1: [[Polynomial<N>; L]; H],

    /// Sum of honest ciphertexts (public input)
    sum_c0: [Polynomial<N>; L],
    sum_c1: [Polynomial<N>; L],

    /// Secret key sum (secret witness)
    s: [Polynomial<N>; L],

    /// Per-basis decryption results u_i (secret witnesses)
    /// These must be bounded to prevent attacks
    u_i: [Polynomial<N>; L],

    /// Quotient polynomials for lifting (secret witnesses)
    r_1: [Polynomial<2 * N - 1>; L],
    r_2: [Polynomial<N - 1>; L],

    /// Global u polynomial (public input)
    /// This must be bounded to ensure valid decryption
    u_global: Polynomial<N>,

    /// CRT quotient polynomials (secret witnesses)
    crt_quotients: [Polynomial<N>; L],

    /// Message polynomial (public input)
    message: Polynomial<N>,
}

impl<let N: u32, let H: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_NOISE: u32> BfvDec<N, H, L, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_NOISE> {
    pub fn new(
        configs: Configs<L>,
        honest_c0: [[Polynomial<N>; L]; H],
        honest_c1: [[Polynomial<N>; L]; H],
        sum_c0: [Polynomial<N>; L],
        sum_c1: [Polynomial<N>; L],
        s: [Polynomial<N>; L],
        u_i: [Polynomial<N>; L],
        r_1: [Polynomial<2 * N - 1>; L],
        r_2: [Polynomial<N - 1>; L],
        u_global: Polynomial<N>,
        crt_quotients: [Polynomial<N>; L],
        message: Polynomial<N>,
    ) -> Self {
        BfvDec {
            configs,
            honest_c0,
            honest_c1,
            sum_c0,
            sum_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            message,
        }
    }

    /// Main verification function
    pub fn verify(self) {
        // Step 1: Verify ciphertext summation
        self.verify_ciphertext_summation();

        // Step 2: Perform range checks on secret witnesses
        self.check_range_bounds();

        // Step 3: Generate Fiat-Shamir challenge
        let gamma = self.generate_challenge();

        // Step 4: Verify decryption formula for each basis using Schwartz-Zippel
        for basis_idx in 0..L {
            self.verify_decryption_formula(basis_idx, gamma);
        }

        // Step 5: Verify CRT reconstruction
        self.verify_crt_reconstruction();

        // Step 6: Verify global noise bound (decoding correctness)
        self.verify_direct_decoding();
    }

    /// Verifies that H honest ciphertexts sum correctly to the claimed sum ciphertext
    fn verify_ciphertext_summation(self) {
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];
            let m = ModU128::new(q_l);

            // Verify c_0 summation
            for coeff_idx in 0..N {
                let mut sum = 0 as Field;
                for party_idx in 0..H {
                    sum = sum + self.honest_c0[party_idx][basis_idx].coefficients[coeff_idx];
                }
                let sum_reduced = m.reduce_mod(sum);
                assert(
                    sum_reduced == self.sum_c0[basis_idx].coefficients[coeff_idx],
                    "Ciphertext c_0 summation verification failed",
                );
            }

            // Verify c_1 summation
            for coeff_idx in 0..N {
                let mut sum = 0 as Field;
                for party_idx in 0..H {
                    sum = sum + self.honest_c1[party_idx][basis_idx].coefficients[coeff_idx];
                }
                let sum_reduced = m.reduce_mod(sum);
                assert(
                    sum_reduced == self.sum_c1[basis_idx].coefficients[coeff_idx],
                    "Ciphertext c_1 summation verification failed",
                );
            }
        }
    }

    /// Performs range checks on all secret witness values
    fn check_range_bounds(self) {
        // Check secret key sum is within bounds
        for basis_idx in 0..L {
            self.s[basis_idx].range_check_2bounds::<BIT_S>(
                self.configs.s_bound,
                self.configs.s_bound,
            );
        }

        // Check per-basis u_i are within bounds (CRITICAL for security)
        for basis_idx in 0..L {
            self.u_i[basis_idx].range_check_2bounds::<BIT_U>(
                self.configs.u_i_bounds[basis_idx],
                self.configs.u_i_bounds[basis_idx],
            );
        }

        // Check global u is within bounds (CRITICAL for security)
        self.u_global.range_check_2bounds::<BIT_U>(
            self.configs.u_global_bound,
            self.configs.u_global_bound,
        );

        // Check quotient polynomials are within bounds
        for basis_idx in 0..L {
            self.r_1[basis_idx].range_check_2bounds::<BIT_R1>(
                self.configs.r1_bounds[basis_idx],
                self.configs.r1_bounds[basis_idx],
            );
            self.r_2[basis_idx].range_check_2bounds::<BIT_R2>(
                self.configs.r2_bounds[basis_idx],
                self.configs.r2_bounds[basis_idx],
            );
        }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten honest ciphertexts (public inputs)
        for party_idx in 0..H {
            inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c0[party_idx]);
            inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c1[party_idx]);
        }

        // Flatten sum ciphertexts (public inputs)
        inputs = flatten::<_, _, BIT_CT>(inputs, self.sum_c0);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.sum_c1);

        // Flatten secret key sum (secret witness)
        inputs = flatten::<_, _, BIT_S>(inputs, self.s);

        // Flatten u_i (secret witnesses)
        inputs = flatten::<_, _, BIT_U>(inputs, self.u_i);

        // Flatten quotient polynomials (secret witnesses)
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r_1);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r_2);

        // Flatten global u (public input)
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u_global]);

        // Flatten CRT quotients (secret witnesses)
        inputs = flatten::<_, _, BIT_U>(inputs, self.crt_quotients);

        // Flatten message (public input)
        inputs = flatten::<_, _, BIT_NOISE>(inputs, [self.message]);

        inputs
    }

    /// Generates a Fiat-Shamir challenge value using the SAFE cryptographic sponge
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        // Domain separator for honest aggregation circuit - "HonestAgg" in hex
        let domain_separator = [
            0x48, 0x6f, 0x6e, 0x65, 0x73, 0x74, 0x41, 0x67, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let gammas = compute_safe(domain_separator, inputs, io_pattern);

        gammas.get(0)
    }

    /// Verifies the decryption formula for a specific CRT basis using the Schwartz-Zippel lemma
    fn verify_decryption_formula(self, basis_idx: u32, gamma: Field) {
        // Evaluate sum ciphertext components at gamma
        let c_0_at_gamma = self.sum_c0[basis_idx].eval(gamma);
        let c_1_at_gamma = self.sum_c1[basis_idx].eval(gamma);

        // Evaluate secret key sum at gamma
        let s_at_gamma = self.s[basis_idx].eval(gamma);

        // Evaluate quotient polynomials at gamma
        let r_1_at_gamma = self.r_1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r_2[basis_idx].eval(gamma);

        // Evaluate cyclotomic polynomial X^N + 1 at gamma
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Compute expected u_i using the lifted formula:
        // u_i = c_0i + c_1i * s + r_2_i * (X^N + 1) + r_1_i * q_i
        let expected_u = c_0_at_gamma
            + c_1_at_gamma * s_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * self.configs.qis[basis_idx];

        // Evaluate the claimed u_i at gamma
        let computed_u = self.u_i[basis_idx].eval(gamma);

        // Enforce equality
        assert_eq(computed_u, expected_u);
    }

    /// Verifies CRT reconstruction: u_i + quotient_i * q_i = u_global
    fn verify_crt_reconstruction(self) {
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];

            // Compute quotient_i * q_l
            let quotient_times_q = self.crt_quotients[basis_idx].mul_scalar(q_l);

            // Compute u_i + quotient_i * q_l
            let reconstructed = self.u_i[basis_idx].add(quotient_times_q);

            // Verify: u_i + quotient_i * q_l = u_global
            for coeff_idx in 0..N {
                assert(
                    reconstructed.coefficients[coeff_idx] == self.u_global.coefficients[coeff_idx],
                    "CRT reconstruction verification failed",
                );
            }
        }
    }

    /// Verifies the direct decoding of the message from the global decryption result
    fn verify_direct_decoding(self) {
        let t: Field = self.configs.plaintext_modulus;

        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1;
        for l in 0..L {
            q_modulus *= self.configs.qis[l];
        }

        // For centered arithmetic
        let q_bn = Enclave_TRBFV_8192::from(q_modulus);
        let q_half = (q_modulus as u128) / 2;

        // Verify decoding for each coefficient
        for coeff_idx in 0..N {
            // Compute (t * u_global) mod Q using BigNum
            let u_bn_q = Enclave_TRBFV_8192::from(self.u_global.coefficients[coeff_idx]);
            let t_bn_q = Enclave_TRBFV_8192::from(t);
            let t_times_u_bn_q = (t_bn_q * u_bn_q).umod(q_bn);
            let t_times_u_q = to_field(t_times_u_bn_q);
            let needs_centering = (t_times_u_q as u128) > q_half;

            let m = ModU128::new(t);

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Conceptually: (t*u)_Q - Q (negative value)
                // -Q^{-1} * (negative) = positive result
                let centered_positive = q_modulus - t_times_u_q;
                m.mul_mod(
                    self.configs.q_inverse_mod_t,
                    centered_positive, // Don't reduce mod t before multiplication!
                )
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // -Q^{-1} * (positive) = negative result = t - result
                let product = m.mul_mod(
                    self.configs.q_inverse_mod_t,
                    t_times_u_q, // Don't reduce mod t before multiplication!
                );
                if product == 0 {
                    0
                } else {
                    t - product
                }
            };

            // Verify: only check non-zero coefficients
            if self.message.coefficients[coeff_idx] != 0 {
                assert(computed_message == self.message.coefficients[coeff_idx]);
            }
        }
    }
}
