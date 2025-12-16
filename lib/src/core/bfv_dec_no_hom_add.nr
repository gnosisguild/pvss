use crate::math::helpers::{compute_safe, flatten};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;

pub struct Config<let L: u32, let L_PRIME: u32> {
    /// BFV CRT moduli: [q'_0, q'_1, ..., q'_{L'-1}]
    pub bfv_qis: [Field; L_PRIME],
    /// BFV plaintext modulus (large enough for TRBFV values)
    pub bfv_plaintext_modulus: Field,
    /// BFV Q^{-1} mod t for decoding
    pub bfv_q_inverse_mod_t: Field,
    /// TRBFV CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub trbfv_qis: [Field; L],
    /// Bound for BFV secret key
    pub s_bound: Field,
    /// Bounds for u_i polynomials (per BFV basis)
    pub u_i_bounds: [Field; L_PRIME],
    /// Bound for global u polynomial
    pub u_global_bound: Field,
    /// Bounds for r_1 polynomials (per BFV basis)
    pub r1_bounds: [Field; L_PRIME],
    /// Bounds for r_2 polynomials (per BFV basis)
    pub r2_bounds: [Field; L_PRIME],
    /// Global delta value: delta = floor(Q/t) where Q is the product of all q_i
    /// Used in the decoding formula to scale the plaintext
    pub delta: Field,
    /// Global half-delta value: delta_half = floor(delta / 2)
    /// Used to check the noise bound: |u_global - delta * m| < delta/2
    pub delta_half: Field,
}

impl<let L: u32, let L_PRIME: u32> Config<L, L_PRIME> {
    pub fn new(
        bfv_qis: [Field; L_PRIME],
        bfv_plaintext_modulus: Field,
        bfv_q_inverse_mod_t: Field,
        trbfv_qis: [Field; L],
        s_bound: Field,
        u_i_bounds: [Field; L_PRIME],
        u_global_bound: Field,
        r1_bounds: [Field; L_PRIME],
        r2_bounds: [Field; L_PRIME],
        delta: Field,
        delta_half: Field,
    ) -> Self {
        Config {
            bfv_qis,
            bfv_plaintext_modulus,
            bfv_q_inverse_mod_t,
            trbfv_qis,
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

/// BFV Decryption and TRBFV Share Aggregation Circuit
///
/// This circuit verifies:
/// 1. BFV decryption of H*L ciphertexts (H honest parties * L TRBFV bases)
/// 2. Each ciphertext decrypts using L' BFV RNS bases
/// 3. CRT reconstruction for each ciphertext to u_global
/// 4. Decoding each u_global to decrypted_share
/// 5. For each TRBFV basis l: sigma_h decrypted_shares[h][l] mod trbfv_qi[l] = expected_share[l]
///
/// # Generic Parameters
/// * `N` - Number of polynomial coefficients
/// * `H` - Number of honest parties
/// * `L` - Number of TRBFV CRT bases
/// * `L_PRIME` - Number of BFV CRT bases
/// * `BIT_CT` - Bit width for ciphertext coefficients
/// * `BIT_S` - Bit width for BFV secret key
/// * `BIT_U` - Bit width for u_i and u_global coefficients
/// * `BIT_R1` - Bit width for r_1 quotients
/// * `BIT_R2` - Bit width for r_2 quotients
/// * `BIT_MSG` - Bit width for decoded message coefficients
pub struct BfvDecNoHomAdd<let N: u32, let H: u32, let L: u32, let L_PRIME: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_MSG: u32> {
    /// Circuit parameters
    configs: Config<L, L_PRIME>,

    /// H*L ciphertexts, each with L_prime BFV RNS components
    /// honest_c0[party_idx][trbfv_basis][bfv_basis]
    honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H],
    honest_c1: [[[Polynomial<N>; L_PRIME]; L]; H],

    /// BFV secret key - single polynomial (same for all bases because it's small)
    s: Polynomial<N>,

    /// Per-ciphertext per-BFV-basis decryption results
    /// u_i[party_idx][trbfv_basis][bfv_basis]
    u_i: [[[Polynomial<N>; L_PRIME]; L]; H],

    /// Per-ciphertext lifting quotients
    /// r_1[party_idx][trbfv_basis][bfv_basis]
    r_1: [[[Polynomial<2 * N - 1>; L_PRIME]; L]; H],
    r_2: [[[Polynomial<N - 1>; L_PRIME]; L]; H],

    /// Per-ciphertext CRT reconstructed result (one per H*L ciphertext)
    /// u_global[party_idx][trbfv_basis]
    u_global: [[Polynomial<N>; L]; H],

    /// Per-ciphertext CRT quotients
    /// crt_quotients[party_idx][trbfv_basis][bfv_basis]
    crt_quotients: [[[Polynomial<N>; L_PRIME]; L]; H],

    /// Decoded shares (message) (one per H*L ciphertext)
    /// decrypted_shares[party_idx][trbfv_basis]
    decrypted_shares: [[Polynomial<N>; L]; H],

    /// Expected aggregated TRBFV secret key shares (secret witness)
    /// expected_aggregated_shares[trbfv_basis]
    expected_aggregated_shares: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let L_PRIME: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_MSG: u32> BfvDecNoHomAdd<N, H, L, L_PRIME, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_MSG> {
    /// Creates a new circuit instance
    pub fn new(
        configs: Config<L, L_PRIME>,
        honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H],
        honest_c1: [[[Polynomial<N>; L_PRIME]; L]; H],
        s: Polynomial<N>,
        u_i: [[[Polynomial<N>; L_PRIME]; L]; H],
        r_1: [[[Polynomial<2 * N - 1>; L_PRIME]; L]; H],
        r_2: [[[Polynomial<N - 1>; L_PRIME]; L]; H],
        u_global: [[Polynomial<N>; L]; H],
        crt_quotients: [[[Polynomial<N>; L_PRIME]; L]; H],
        decrypted_shares: [[Polynomial<N>; L]; H],
        expected_aggregated_shares: [Polynomial<N>; L],
    ) -> Self {
        BfvDecNoHomAdd {
            configs,
            honest_c0,
            honest_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            decrypted_shares,
            expected_aggregated_shares,
        }
    }

    /// Main verification function
    pub fn verify(self) {
        // Step 1: Range checks on secret witnesses
        self.check_range_bounds();

        // Step 2: Generate Fiat-Shamir challenge
        let gamma = self.generate_challenge();

        // Step 3: For each ciphertext, verify BFV decryption
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                // Verify decryption formula for each BFV basis
                for bfv_idx in 0..L_PRIME {
                    self.verify_decryption_formula(party_idx, trbfv_idx, bfv_idx, gamma);
                }

                // Verify CRT reconstruction for this ciphertext
                self.verify_crt_reconstruction(party_idx, trbfv_idx);

                // Verify decoding for this ciphertext
                self.verify_decoding(party_idx, trbfv_idx);
            }
        }

        // Step 4: Verify TRBFV share aggregation
        self.verify_trbfv_aggregation();
    }

    /// Performs range checks on all secret witness values
    fn check_range_bounds(self) {
        // Check BFV secret key
        self.s.range_check_2bounds::<BIT_S>(self.configs.s_bound, self.configs.s_bound);

        // Check per-ciphertext per-BFV-basis witnesses
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                for bfv_idx in 0..L_PRIME {
                    // u_i bounds
                    self.u_i[party_idx][trbfv_idx][bfv_idx].range_check_2bounds::<BIT_U>(
                        self.configs.u_i_bounds[bfv_idx],
                        self.configs.u_i_bounds[bfv_idx],
                    );

                    // r_1 bounds
                    self.r_1[party_idx][trbfv_idx][bfv_idx].range_check_2bounds::<BIT_R1>(
                        self.configs.r1_bounds[bfv_idx],
                        self.configs.r1_bounds[bfv_idx],
                    );

                    // r_2 bounds
                    self.r_2[party_idx][trbfv_idx][bfv_idx].range_check_2bounds::<BIT_R2>(
                        self.configs.r2_bounds[bfv_idx],
                        self.configs.r2_bounds[bfv_idx],
                    );
                }

                // u_global bounds
                self.u_global[party_idx][trbfv_idx].range_check_2bounds::<BIT_U>(
                    self.configs.u_global_bound,
                    self.configs.u_global_bound,
                );
            }
        }
    }

    /// Flattens all witness data for Fiat-Shamir challenge generation
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten honest ciphertexts
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c0[party_idx][trbfv_idx]);
                inputs = flatten::<_, _, BIT_CT>(inputs, self.honest_c1[party_idx][trbfv_idx]);
            }
        }

        // Flatten secret key
        inputs = flatten::<_, _, BIT_S>(inputs, [self.s]);

        // Flatten u_i
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                inputs = flatten::<_, _, BIT_U>(inputs, self.u_i[party_idx][trbfv_idx]);
            }
        }

        // Flatten r_1, r_2
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                inputs = flatten::<_, _, BIT_R1>(inputs, self.r_1[party_idx][trbfv_idx]);
                inputs = flatten::<_, _, BIT_R2>(inputs, self.r_2[party_idx][trbfv_idx]);
            }
        }

        // Flatten u_global
        for party_idx in 0..H {
            inputs = flatten::<_, _, BIT_U>(inputs, self.u_global[party_idx]);
        }

        // Flatten crt_quotients
        for party_idx in 0..H {
            for trbfv_idx in 0..L {
                inputs = flatten::<_, _, BIT_U>(inputs, self.crt_quotients[party_idx][trbfv_idx]);
            }
        }

        // Flatten decrypted_shares
        for party_idx in 0..H {
            inputs = flatten::<_, _, BIT_MSG>(inputs, self.decrypted_shares[party_idx]);
        }

        // Flatten expected_aggregated_shares
        inputs = flatten::<_, _, BIT_MSG>(inputs, self.expected_aggregated_shares);

        inputs
    }

    /// Generates Fiat-Shamir challenge value
    fn generate_challenge(self) -> Field {
        let inputs = self.payload();

        // Domain separator - "BfvTrbfvAgg" in hex
        let domain_separator = [
            0x42, 0x66, 0x76, 0x54, 0x72, 0x62, 0x66, 0x76, 0x41, 0x67, 0x67, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, inputs, io_pattern).get(0)
    }

    /// Verifies BFV decryption formula for one ciphertext at one BFV basis
    ///
    /// Checks: u_i(gamma) = c_0(gamma) + c_1(gamma) * s(gamma) + r_2(gamma) * (gamma^N + 1) + r_1(gamma) * bfv_q_i
    fn verify_decryption_formula(self, party_idx: u32, trbfv_idx: u32, bfv_idx: u32, gamma: Field) {
        // Evaluate ciphertext at gamma
        let c_0_at_gamma = self.honest_c0[party_idx][trbfv_idx][bfv_idx].eval(gamma);
        let c_1_at_gamma = self.honest_c1[party_idx][trbfv_idx][bfv_idx].eval(gamma);

        // Evaluate secret key at gamma (same s for all)
        let s_at_gamma = self.s.eval(gamma);

        // Evaluate quotients at gamma
        let r_1_at_gamma = self.r_1[party_idx][trbfv_idx][bfv_idx].eval(gamma);
        let r_2_at_gamma = self.r_2[party_idx][trbfv_idx][bfv_idx].eval(gamma);

        // Cyclotomic polynomial X^N + 1 at gamma
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Expected: u_i = c_0 + c_1 * s + r_2 * (X^N + 1) + r_1 * q'_i
        let expected_u = c_0_at_gamma
            + c_1_at_gamma * s_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * self.configs.bfv_qis[bfv_idx];

        let computed_u = self.u_i[party_idx][trbfv_idx][bfv_idx].eval(gamma);

        assert_eq(computed_u, expected_u);
    }

    /// Verifies CRT reconstruction for one ciphertext
    /// u_i[l'] + quotient[l'] * q'_l' = u_global (for all l')
    fn verify_crt_reconstruction(self, party_idx: u32, trbfv_idx: u32) {
        for bfv_idx in 0..L_PRIME {
            let q_l = self.configs.bfv_qis[bfv_idx];

            // quotient * q'_l
            let quotient_times_q =
                self.crt_quotients[party_idx][trbfv_idx][bfv_idx].mul_scalar(q_l);

            // u_i + quotient * q'_l
            let reconstructed = self.u_i[party_idx][trbfv_idx][bfv_idx].add(quotient_times_q);

            // Verify equality with u_global
            for coeff_idx in 0..N {
                assert(
                    reconstructed.coefficients[coeff_idx]
                        == self.u_global[party_idx][trbfv_idx].coefficients[coeff_idx],
                    "CRT reconstruction failed",
                );
            }
        }
    }

    /// Verifies BFV decoding: u_global to decrypted_share
    fn verify_decoding(self, party_idx: u32, trbfv_idx: u32) {
        let t = self.configs.bfv_plaintext_modulus;

        // Compute Q = product of all BFV moduli
        let mut q_modulus = 1;
        for l in 0..L_PRIME {
            q_modulus *= self.configs.bfv_qis[l];
        }

        let q_half = (q_modulus as u128) / 2;

        let q_mod = ModU128::new(q_modulus);
        let t_mod = ModU128::new(t);
        for coeff_idx in 0..N {
            let t_times_u_q =
                q_mod.mul_mod(t, self.u_global[party_idx][trbfv_idx].coefficients[coeff_idx]);

            let needs_centering = (t_times_u_q as u128) > q_half;

            let computed_message = if needs_centering {
                let centered_positive = q_modulus - t_times_u_q;
                t_mod.mul_mod(self.configs.bfv_q_inverse_mod_t, centered_positive)
            } else {
                let product = t_mod.mul_mod(self.configs.bfv_q_inverse_mod_t, t_times_u_q);
                if product == 0 {
                    0
                } else {
                    t - product
                }
            };

            // Verify decoding
            if self.decrypted_shares[party_idx][trbfv_idx].coefficients[coeff_idx] != 0 {
                assert(
                    computed_message
                        == self.decrypted_shares[party_idx][trbfv_idx].coefficients[coeff_idx],
                );
            }
        }
    }

    /// Verifies TRBFV share aggregation
    /// For each TRBFV basis l: sigma_h decrypted_shares[h][l] mod trbfv_qi[l] = expected[l]
    fn verify_trbfv_aggregation(self) {
        for trbfv_idx in 0..L {
            let trbfv_q = self.configs.trbfv_qis[trbfv_idx];

            for coeff_idx in 0..N {
                // Sum shares from all honest parties
                let mut sum = 0 as Field;
                for party_idx in 0..H {
                    sum = sum + self.decrypted_shares[party_idx][trbfv_idx].coefficients[coeff_idx];
                }

                // Reduce mod TRBFV modulus
                let sum_reduced = ModU128::new(trbfv_q).reduce_mod(sum);

                // Verify against expected
                assert(
                    sum_reduced
                        == self.expected_aggregated_shares[trbfv_idx].coefficients[coeff_idx],
                    "TRBFV share aggregation failed",
                );
            }
        }
    }
}
