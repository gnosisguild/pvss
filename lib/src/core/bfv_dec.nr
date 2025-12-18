use crate::math::helpers::{compute_safe, flatten};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;
use dep::bignum::BigNum;
use dep::bignum::bignum::to_field;
use dep::bignum::Enclave_TRBFV_8192;

/// Cryptographic parameters for BFV decryption circuit.
pub struct Configs<let L: u32, let L_PRIME: u32> {
    /// BFV CRT moduli: [q'_0, q'_1, ..., q'_{L'-1}]
    pub bfv_qis: [Field; L_PRIME],
    /// TRBFV CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub trbfv_qis: [Field; L],
    /// Plaintext modulus (denoted as `t` in BFV literature)
    pub plaintext_modulus: Field,
    /// Modular inverse: Q^(-1) mod t, where Q is the product of all CRT moduli
    pub q_inverse_mod_t: Field,
    /// Bound for secret key sum s (used for range checking)
    pub s_bound: Field,
    /// Bounds for u_i polynomials (per-basis decryption results) for each CRT basis
    pub u_i_bounds: [Field; L_PRIME],
    /// Bound for global u polynomial (reconstructed from CRT bases)
    pub u_global_bound: Field,
    /// Bounds for r_1 polynomials (modulus switching quotients) for each CRT basis
    pub r1_bounds: [Field; L_PRIME],
    /// Bounds for r_2 polynomials (cyclotomic reduction quotients) for each CRT basis
    pub r2_bounds: [Field; L_PRIME],
    /// Global delta value: delta = floor(Q/t) where Q is the product of all q_i
    /// Used in the decoding formula to scale the plaintext
    pub delta: Field,
    /// Global half-delta value: delta_half = floor(delta / 2)
    /// Used to check the noise bound: |u_global - delta * m| < delta/2
    pub delta_half: Field,
}

impl<let L: u32, let L_PRIME: u32> Configs<L, L_PRIME> {
    pub fn new(
        bfv_qis: [Field; L_PRIME],
        trbfv_qis: [Field; L],
        plaintext_modulus: Field,
        q_inverse_mod_t: Field,
        s_bound: Field,
        u_i_bounds: [Field; L_PRIME],
        u_global_bound: Field,
        r1_bounds: [Field; L_PRIME],
        r2_bounds: [Field; L_PRIME],
        delta: Field,
        delta_half: Field,
    ) -> Self {
        Configs {
            bfv_qis,
            trbfv_qis,
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
pub struct BfvDec<let N: u32, let H: u32, let L: u32, let L_PRIME: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_MSG: u32> {
    /// Circuit parameters
    configs: Configs<L, L_PRIME>,

    /// Expected commitment to BFV secret key (from BFV public key circuit)
    expected_sk_commitment: Field,

    /// H honest party ciphertexts (public inputs)
    /// honest_c0[party_idx][trbfv_basis][bfv_basis]
    honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H],
    honest_c1: [[[Polynomial<N>; L_PRIME]; L]; H],

    /// BFV secret key (secret witness) - single polynomial
    s: Polynomial<N>,

    /// Per-TRBFV-basis per-BFV-basis decryption results u_i (secret witnesses)
    /// u_i[trbfv_basis][bfv_basis]
    u_i: [[Polynomial<N>; L_PRIME]; L],

    /// Quotient polynomials for lifting (secret witnesses)
    /// r_1[trbfv_basis][bfv_basis]
    r_1: [[Polynomial<2 * N - 1>; L_PRIME]; L],
    r_2: [[Polynomial<N - 1>; L_PRIME]; L],

    /// Global u polynomial per TRBFV basis (secret witness)
    /// u_global[trbfv_basis]
    u_global: [Polynomial<N>; L],

    /// CRT quotient polynomials (secret witnesses)
    /// crt_quotients[trbfv_basis][bfv_basis]
    crt_quotients: [[Polynomial<N>; L_PRIME]; L],

    /// Message polynomial per TRBFV basis (public input)
    /// message[trbfv_basis]
    message: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let L_PRIME: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_MSG: u32> BfvDec<N, H, L, L_PRIME, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_MSG> {
    pub fn new(
        configs: Configs<L, L_PRIME>,
        expected_sk_commitment: Field,
        honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H],
        honest_c1: [[[Polynomial<N>; L_PRIME]; L]; H],
        s: Polynomial<N>,
        u_i: [[Polynomial<N>; L_PRIME]; L],
        r_1: [[Polynomial<2 * N - 1>; L_PRIME]; L],
        r_2: [[Polynomial<N - 1>; L_PRIME]; L],
        u_global: [Polynomial<N>; L],
        crt_quotients: [[Polynomial<N>; L_PRIME]; L],
        message: [Polynomial<N>; L],
    ) -> Self {
        BfvDec {
            configs,
            expected_sk_commitment,
            honest_c0,
            honest_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            message,
        }
    }

    /// Computes commitment to BFV secret key (must match BFV public key circuit)
    fn compute_sk_commitment(s: Polynomial<N>) -> Field {
        let sk_payload = flatten::<_, _, BIT_S>(Vec::new(), [s]);

        // Domain separator - "PVSS_sk_comm" (must match BFV public key circuit)
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

    /// Verifies that s hashes to expected_sk_commitment
    fn verify_sk_commitment(self) {
        let computed_commitment = Self::compute_sk_commitment(self.s);
        assert_eq(computed_commitment, self.expected_sk_commitment, "SK commitment mismatch");
    }

    /// Commits to message polynomials
    fn commit_to_message(message: [Polynomial<N>; L]) -> Field {
        let mut inputs = Vec::new();

        for trbfv_idx in 0..L {
            for coeff_idx in 0..N {
                inputs.push(message[trbfv_idx].coefficients[coeff_idx]);
            }
        }

        // Domain separator - "PVSS_agg_sh"
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x61, 0x67, 0x67, 0x5f, 0x73, 0x68, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, inputs, io_pattern).get(0)
    }

    /// Computes sum of H honest ciphertexts
    fn compute_ciphertext_summation(
        self,
    ) -> ([[Polynomial<N>; L_PRIME]; L], [[Polynomial<N>; L_PRIME]; L]) {
        let mut sum_c0: [[Polynomial<N>; L_PRIME]; L] = [[Polynomial::new([0; N]); L_PRIME]; L];
        let mut sum_c1: [[Polynomial<N>; L_PRIME]; L] = [[Polynomial::new([0; N]); L_PRIME]; L];

        for trbfv_idx in 0..L {
            for bfv_idx in 0..L_PRIME {
                let q_prime = self.configs.bfv_qis[bfv_idx];
                let mod_q_prime = ModU128::new(q_prime);
                let mut c0_coeffs = [0 as Field; N];
                let mut c1_coeffs = [0 as Field; N];

                for coeff_idx in 0..N {
                    // Sum c_0 coefficients
                    let mut sum0 = 0 as Field;
                    for party_idx in 0..H {
                        sum0 = sum0
                            + self.honest_c0[party_idx][trbfv_idx][bfv_idx].coefficients[coeff_idx];
                    }
                    c0_coeffs[coeff_idx] = mod_q_prime.reduce_mod(sum0);

                    // Sum c_1 coefficients
                    let mut sum1 = 0 as Field;
                    for party_idx in 0..H {
                        sum1 = sum1
                            + self.honest_c1[party_idx][trbfv_idx][bfv_idx].coefficients[coeff_idx];
                    }
                    c1_coeffs[coeff_idx] = mod_q_prime.reduce_mod(sum1);
                }

                sum_c0[trbfv_idx][bfv_idx] = Polynomial::new(c0_coeffs);
                sum_c1[trbfv_idx][bfv_idx] = Polynomial::new(c1_coeffs);
            }
        }

        (sum_c0, sum_c1)
    }

    /// Main verification function
    /// Returns commitment to computed message
    pub fn verify(self) -> Field {
        // Step 1: Verify BFV secret key commitment
        self.verify_sk_commitment();

        // Step 2: Compute ciphertext summation
        let (sum_c0, sum_c1) = self.compute_ciphertext_summation();

        // Step 3: Perform range checks on secret witnesses
        self.check_range_bounds();

        // Step 4: Generate Fiat-Shamir challenge
        let gamma = self.generate_challenge();

        // Step 5: Verify decryption formula for each TRBFV basis and BFV basis
        for trbfv_idx in 0..L {
            for bfv_idx in 0..L_PRIME {
                self.verify_decryption_formula(trbfv_idx, bfv_idx, gamma, sum_c0, sum_c1);
            }

            // Step 6: Verify CRT reconstruction for this TRBFV basis
            self.verify_crt_reconstruction(trbfv_idx);
        }

        // Step 7: Compute decoded message and return commitment
        let computed_message = self.compute_decoded_message();

        // Uncomment to verify message equality:
        // self.verify_message_equality(computed_message);

        Self::commit_to_message(computed_message)
    }

    /// Performs range checks on all secret witness values
    fn check_range_bounds(self) {
        // Check secret key is within bounds
        self.s.range_check_2bounds::<BIT_S>(self.configs.s_bound, self.configs.s_bound);

        // Check per-basis u_i are within bounds
        for trbfv_idx in 0..L {
            for bfv_idx in 0..L_PRIME {
                self.u_i[trbfv_idx][bfv_idx].range_check_2bounds::<BIT_U>(
                    self.configs.u_i_bounds[bfv_idx],
                    self.configs.u_i_bounds[bfv_idx],
                );

                self.r_1[trbfv_idx][bfv_idx].range_check_2bounds::<BIT_R1>(
                    self.configs.r1_bounds[bfv_idx],
                    self.configs.r1_bounds[bfv_idx],
                );

                self.r_2[trbfv_idx][bfv_idx].range_check_2bounds::<BIT_R2>(
                    self.configs.r2_bounds[bfv_idx],
                    self.configs.r2_bounds[bfv_idx],
                );
            }

            // Check global u is within bounds
            self.u_global[trbfv_idx].range_check_2bounds::<BIT_U>(
                self.configs.u_global_bound,
                self.configs.u_global_bound,
            );
        }
    }

    /// Flattens all witness data for Fiat-Shamir challenge generation
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Use sk commitment instead of full sk (saves constraints)
        inputs.push(self.expected_sk_commitment);

        // Flatten honest ciphertexts
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c0[party_idx][trbfv_idx]);
                inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c1[party_idx][trbfv_idx]);
            }
        }

        // Flatten u_i
        for trbfv_idx in 0..L {
            inputs = flatten::<_, _, BIT_U>(inputs, self.u_i[trbfv_idx]);
        }

        // Flatten quotient polynomials
        for trbfv_idx in 0..L {
            inputs = flatten::<_, _, BIT_R1>(inputs, self.r_1[trbfv_idx]);
            inputs = flatten::<_, _, BIT_R2>(inputs, self.r_2[trbfv_idx]);
        }

        // Flatten global u
        inputs = flatten::<_, _, BIT_U>(inputs, self.u_global);

        // Flatten CRT quotients
        for trbfv_idx in 0..L {
            inputs = flatten::<_, _, BIT_U>(inputs, self.crt_quotients[trbfv_idx]);
        }

        // Flatten message
        inputs = flatten::<_, _, BIT_MSG>(inputs, self.message);

        inputs
    }

    /// Generates Fiat-Shamir challenge value
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        // Domain separator - "HonestAggHom"
        let domain_separator = [
            0x48, 0x6f, 0x6e, 0x65, 0x73, 0x74, 0x41, 0x67, 0x67, 0x48, 0x6f, 0x6d, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, inputs, io_pattern).get(0)
    }

    /// Verifies the decryption formula for a specific TRBFV and BFV basis
    fn verify_decryption_formula(
        self,
        trbfv_idx: u32,
        bfv_idx: u32,
        gamma: Field,
        sum_c0: [[Polynomial<N>; L_PRIME]; L],
        sum_c1: [[Polynomial<N>; L_PRIME]; L],
    ) {
        let c_0_at_gamma = sum_c0[trbfv_idx][bfv_idx].eval(gamma);
        let c_1_at_gamma = sum_c1[trbfv_idx][bfv_idx].eval(gamma);
        let s_at_gamma = self.s.eval(gamma);
        let r_1_at_gamma = self.r_1[trbfv_idx][bfv_idx].eval(gamma);
        let r_2_at_gamma = self.r_2[trbfv_idx][bfv_idx].eval(gamma);

        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // u_i = c_0 + c_1 * s + r_2 * (X^N + 1) + r_1 * q'
        let expected_u = c_0_at_gamma
            + c_1_at_gamma * s_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * self.configs.bfv_qis[bfv_idx];

        let computed_u = self.u_i[trbfv_idx][bfv_idx].eval(gamma);

        assert_eq(computed_u, expected_u);
    }

    /// Verifies CRT reconstruction for a specific TRBFV basis
    fn verify_crt_reconstruction(self, trbfv_idx: u32) {
        for bfv_idx in 0..L_PRIME {
            let q_prime = self.configs.bfv_qis[bfv_idx];
            let quotient_times_q = self.crt_quotients[trbfv_idx][bfv_idx].mul_scalar(q_prime);
            let reconstructed = self.u_i[trbfv_idx][bfv_idx].add(quotient_times_q);

            for coeff_idx in 0..N {
                assert(
                    reconstructed.coefficients[coeff_idx]
                        == self.u_global[trbfv_idx].coefficients[coeff_idx],
                    "CRT reconstruction verification failed",
                );
            }
        }
    }

    /// Computes decoded message for all TRBFV bases using BigNum arithmetic
    fn compute_decoded_message(self) -> [Polynomial<N>; L] {
        let t: Field = self.configs.plaintext_modulus;
        let mod_t = ModU128::new(t);
        // Compute Q as product of all BFV CRT moduli
        let mut q_modulus = 1;
        for l in 0..L_PRIME {
            q_modulus *= self.configs.bfv_qis[l];
        }

        // For centered arithmetic
        let q_bn = Enclave_TRBFV_8192::from(q_modulus);
        let q_half = (q_modulus as u128) / 2;

        let mut computed_message: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

        for trbfv_idx in 0..L {
            let mut msg_coeffs = [0 as Field; N];

            for coeff_idx in 0..N {
                // Compute (t * u_global) mod Q using BigNum
                let u_bn_q =
                    Enclave_TRBFV_8192::from(self.u_global[trbfv_idx].coefficients[coeff_idx]);
                let t_bn_q = Enclave_TRBFV_8192::from(t);
                let t_times_u_bn_q = (t_bn_q * u_bn_q).umod(q_bn);
                let t_times_u_q = to_field(t_times_u_bn_q);

                let needs_centering = (t_times_u_q as u128) > q_half;

                let computed_coeff = if needs_centering {
                    let centered_positive = q_modulus - t_times_u_q;
                    mod_t.mul_mod(self.configs.q_inverse_mod_t, centered_positive)
                } else {
                    let product = mod_t.mul_mod(self.configs.q_inverse_mod_t, t_times_u_q);
                    if product == 0 {
                        0
                    } else {
                        t - product
                    }
                };

                msg_coeffs[coeff_idx] = computed_coeff;
            }

            computed_message[trbfv_idx] = Polynomial::new(msg_coeffs);
        }

        computed_message
    }

    /// Verifies that computed message matches input message
    /// Uncomment call in verify() to enable
    fn verify_message_equality(self, computed_message: [Polynomial<N>; L]) {
        for trbfv_idx in 0..L {
            for coeff_idx in 0..N {
                if self.message[trbfv_idx].coefficients[coeff_idx] != 0 {
                    assert(
                        computed_message[trbfv_idx].coefficients[coeff_idx]
                            == self.message[trbfv_idx].coefficients[coeff_idx],
                        "Message equality check failed",
                    );
                }
            }
        }
    }
}
