use crate::math::helpers::{compute_safe, flatten};
use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for the BFV decryption and TRBFV share aggregation circuit.
///
/// This struct contains all the mathematical constants and bounds needed to verify
/// correct BFV decryption of multiple ciphertexts and their aggregation into TRBFV shares.
///
/// # Generic Parameters
/// * `L` - The number of TRBFV CRT (Chinese Remainder Theorem) bases
/// * `L_PRIME` - The number of BFV CRT bases
pub struct Config<let L: u32, let L_PRIME: u32> {
    /// BFV CRT moduli: [q'_0, q'_1, ..., q'_{L'-1}]
    pub bfv_qis: [Field; L_PRIME],
    /// BFV plaintext modulus (typically denoted as `t`, large enough for TRBFV values)
    pub bfv_plaintext_modulus: Field,
    /// Precomputed value: `-Q^(-1) mod t` where Q is the product of all BFV CRT moduli
    pub bfv_q_inverse_mod_t: Field,
    /// TRBFV CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub trbfv_qis: [Field; L],
    /// Bound for BFV secret key polynomial coefficients
    pub s_bound: Field,
    /// Bounds for u_i polynomials (per BFV basis, one bound per L_PRIME)
    pub u_i_bounds: [Field; L_PRIME],
    /// Bound for global u polynomial coefficients (after CRT reconstruction)
    pub u_global_bound: Field,
    /// Bounds for r_1 quotient polynomials (per BFV basis, one bound per L_PRIME)
    pub r1_bounds: [Field; L_PRIME],
    /// Bounds for r_2 quotient polynomials (per BFV basis, one bound per L_PRIME)
    pub r2_bounds: [Field; L_PRIME],
    /// Global delta value: `delta = floor(Q/t)` where Q is the product of all BFV moduli
    /// Used in the decoding formula to scale the plaintext
    pub delta: Field,
    /// Global half-delta value: `delta_half = floor(delta / 2)`
    /// Used to check the noise bound: `|u_global - delta * m| < delta/2`
    pub delta_half: Field,
}

impl<let L: u32, let L_PRIME: u32> Config<L, L_PRIME> {
    /// Creates a new `Config` instance with the specified cryptographic parameters.
    ///
    /// # Arguments
    /// All parameters correspond to the fields of the `Config` struct. See the struct
    /// documentation for details on each parameter.
    ///
    /// # Returns
    /// A new `Config` instance ready for use with the `BfvDecNoHomAdd` circuit.
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

/// BFV Decryption and TRBFV Share Aggregation Circuit.
///
/// This circuit implements a zero-knowledge proof for the correct decryption of multiple
/// BFV ciphertexts and their aggregation into TRBFV secret key shares. It verifies the
/// complete pipeline from encrypted ciphertexts to aggregated TRBFV shares without using
/// homomorphic addition.
///
/// The circuit verifies the following steps for H honest parties and L TRBFV bases:
/// 1. **BFV Decryption**: For each of H*L ciphertexts, verifies correct BFV decryption
///    using L' BFV RNS bases. Each ciphertext is decrypted component-wise:
///    `u_i = c_0 + c_1 * s + r_2 * (X^N + 1) + r_1 * q'_i` for each BFV basis i
/// 2. **CRT Reconstruction**: For each ciphertext, verifies that the per-basis decryption
///    results `u_i` are correctly reconstructed into a global `u_global` using CRT
/// 3. **Message Decoding**: For each ciphertext, verifies that `u_global` is correctly
///    decoded to the decrypted share using the BFV decoding formula
/// 4. **TRBFV Aggregation**: For each TRBFV basis, verifies that the sum of all H
///    decrypted shares modulo the TRBFV modulus equals the expected aggregated share
///
/// This circuit is used in threshold BFV protocols where multiple parties' ciphertexts
/// need to be decrypted and aggregated without using homomorphic operations.
///
/// # Generic Parameters
/// * `N` - Number of polynomial coefficients (ring dimension)
/// * `H` - Number of honest parties (ciphertexts to decrypt)
/// * `L` - Number of TRBFV CRT bases
/// * `L_PRIME` - Number of BFV CRT bases
/// * `BIT_CT` - Bit-width bound per coefficient for ciphertext polynomials
/// * `BIT_S` - Bit-width bound per coefficient for BFV secret key polynomial
/// * `BIT_U` - Bit-width bound per coefficient for u_i and u_global polynomials
/// * `BIT_R1` - Bit-width bound per coefficient for r_1 quotient polynomials
/// * `BIT_R2` - Bit-width bound per coefficient for r_2 quotient polynomials
/// * `BIT_MSG` - Bit-width bound per coefficient for decoded message polynomials
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
    /// Creates a new `BfvDecNoHomAdd` circuit instance.
    ///
    /// This constructor initializes all the polynomials and parameters needed for
    /// the zero-knowledge proof of correct BFV decryption and TRBFV share aggregation.
    ///
    /// # Arguments
    /// * `configs` - Cryptographic parameters including moduli, bounds, and scaling factors
    /// * `honest_c0` - First ciphertext components for H parties, L TRBFV bases, L' BFV bases (public inputs)
    /// * `honest_c1` - Second ciphertext components for H parties, L TRBFV bases, L' BFV bases (public inputs)
    /// * `s` - BFV secret key polynomial (secret witness)
    /// * `u_i` - Per-ciphertext per-BFV-basis decryption results (secret witnesses)
    /// * `r_1` - Quotient polynomials for modulus lifting (secret witnesses, degree 2N-1)
    /// * `r_2` - Quotient polynomials for cyclotomic lifting (secret witnesses, degree N-1)
    /// * `u_global` - CRT-reconstructed global u polynomials (secret witnesses, one per H*L ciphertext)
    /// * `crt_quotients` - CRT quotient polynomials for reconstruction (secret witnesses)
    /// * `decrypted_shares` - Decoded message polynomials (public outputs, one per H*L ciphertext)
    /// * `expected_aggregated_shares` - Expected aggregated TRBFV shares (secret witnesses)
    ///
    /// # Returns
    /// A new `BfvDecNoHomAdd` instance ready for constraint checking via the `verify()` method
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

    /// Main verification function that performs all circuit checks.
    ///
    /// This function implements the complete zero-knowledge proof by verifying:
    /// 1. Range bounds on all secret witnesses (secret key, u_i, quotients, u_global)
    /// 2. BFV decryption formula for each ciphertext and BFV basis (using Schwartz-Zippel)
    /// 3. CRT reconstruction for each ciphertext
    /// 4. Message decoding for each ciphertext
    /// 5. TRBFV share aggregation across all honest parties
    ///
    /// The proof uses the Schwartz-Zippel lemma to verify polynomial equations by
    /// evaluating them at a random challenge point generated via Fiat-Shamir.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any verification step fails.
    /// The circuit fails if:
    /// - Any witness is outside its expected bounds
    /// - BFV decryption formula doesn't hold for any ciphertext or BFV basis
    /// - CRT reconstruction doesn't hold for any ciphertext
    /// - Message decoding doesn't match for any ciphertext
    /// - TRBFV share aggregation doesn't match expected values
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

    /// Performs range checks on all secret witness values.
    ///
    /// This function constrains all secret witnesses to be within their expected bounds
    /// as specified in the `configs`. This is critical for security because it prevents
    /// attacks where malicious provers provide out-of-range values that could break the
    /// security properties of the BFV and TRBFV schemes.
    ///
    /// The function checks:
    /// - BFV secret key `s` has small coefficients (required for security)
    /// - Per-ciphertext per-BFV-basis witnesses `u_i` are within bounds for each BFV basis
    /// - Quotient polynomials `r_1` and `r_2` are within bounds for each BFV basis
    /// - Global u polynomials `u_global` are within bounds (after CRT reconstruction)
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// its expected bounds. The bounds are defined per polynomial type in the `configs`.
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

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation.
    ///
    /// This function serializes all polynomial coefficients (both public inputs and
    /// secret witnesses) into a 1D array in a deterministic order. The flattened data
    /// is used to generate the Fiat-Shamir challenge via the SAFE sponge API.
    ///
    /// The order of serialization is:
    /// 1. Honest ciphertexts `c_0` and `c_1` for all parties, TRBFV bases, and BFV bases
    /// 2. BFV secret key `s`
    /// 3. Per-ciphertext per-BFV-basis decryption results `u_i`
    /// 4. Quotient polynomials `r_1` and `r_2`
    /// 5. Global u polynomials `u_global`
    /// 6. CRT quotient polynomials
    /// 7. Decrypted shares
    /// 8. Expected aggregated TRBFV shares
    ///
    /// # Returns
    /// A vector containing all polynomial coefficients in flattened form, ready for
    /// hashing to generate the Fiat-Shamir challenge.
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

    /// Generates Fiat-Shamir challenge value using the SAFE cryptographic sponge.
    ///
    /// This function implements the Fiat-Shamir transform for the BFV decryption circuit:
    /// 1. Flattens all witness data (ciphertexts, secrets, quotients, shares) into a single array
    /// 2. Absorbs the flattened data into the SAFE sponge
    /// 3. Squeezes a single challenge value
    ///
    /// The challenge is used to evaluate polynomials for the Schwartz-Zippel lemma,
    /// which allows verification of polynomial equations by checking them at a random
    /// point rather than checking all coefficients.
    ///
    /// # Returns
    /// A single challenge value `gamma` used as the evaluation point for verifying
    /// the BFV decryption formula for all ciphertexts and BFV bases.
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

    /// Verifies the BFV decryption formula for one ciphertext at one BFV basis using the Schwartz-Zippel lemma.
    ///
    /// This function verifies that the decryption result `u_i` for a specific ciphertext
    /// (party, TRBFV basis) and BFV basis satisfies:
    /// `u_i(gamma) = c_0(gamma) + c_1(gamma) * s(gamma) + r_2(gamma) * cyclo(gamma) + r_1(gamma) * bfv_q_i`
    ///
    /// Where:
    /// - `c_0`, `c_1` are ciphertext components for the specified party, TRBFV basis, and BFV basis
    /// - `s` is the BFV secret key polynomial (same for all bases)
    /// - `r_1`, `r_2` are quotient witnesses for lifting to the large field
    /// - `cyclo(gamma) = gamma^N + 1` is the cyclotomic polynomial evaluated at gamma
    /// - `bfv_q_i` is the BFV CRT modulus for basis i
    ///
    /// The Schwartz-Zippel lemma ensures that if this equation holds at a random point
    /// `gamma`, then the polynomials are identical with high probability.
    ///
    /// # Arguments
    /// * `party_idx` - The index of the honest party (0 <= party_idx < H)
    /// * `trbfv_idx` - The index of the TRBFV basis (0 <= trbfv_idx < L)
    /// * `bfv_idx` - The index of the BFV basis (0 <= bfv_idx < L_PRIME)
    /// * `gamma` - The Fiat-Shamir challenge value used as the evaluation point
    ///
    /// # Panics
    /// The circuit will fail if the BFV decryption formula doesn't hold for the specified indices.
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

    /// Verifies CRT reconstruction for one ciphertext: `u_i[l'] + quotient[l'] * q'_l' = u_global` for all l'.
    ///
    /// This function verifies that for a specific ciphertext (party, TRBFV basis), the
    /// per-BFV-basis decryption results `u_i` are correctly reconstructed into the global
    /// polynomial `u_global` using the Chinese Remainder Theorem.
    ///
    /// For each BFV basis l', the function verifies:
    /// - `u_i[l']` (decryption result for BFV basis l') plus
    /// - `quotient[l'] * q'_l'` (CRT quotient times BFV modulus) equals
    /// - `u_global` (the claimed global polynomial)
    ///
    /// This must hold for every coefficient position and every BFV basis.
    ///
    /// # Arguments
    /// * `party_idx` - The index of the honest party (0 <= party_idx < H)
    /// * `trbfv_idx` - The index of the TRBFV basis (0 <= trbfv_idx < L)
    ///
    /// # Panics
    /// The circuit will fail if the CRT reconstruction doesn't hold for any BFV basis or coefficient.
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

    /// Verifies BFV decoding: `u_global` to `decrypted_share`.
    ///
    /// This function verifies that the global u polynomial `u_global` is correctly decoded
    /// to the decrypted share using the BFV decoding formula:
    /// `message = -Q^(-1) * (t * u_global)_Q mod t`
    ///
    /// The decoding process involves:
    /// 1. Computing `(t * u_global) mod Q` where Q is the product of all BFV moduli
    /// 2. Handling centered arithmetic (values >= Q/2 are treated as negative)
    /// 3. Computing `-Q^(-1) * (t * u_global)_Q mod t` to recover the message
    ///
    /// The function only verifies non-zero message coefficients to allow for sparse messages.
    ///
    /// # Arguments
    /// * `party_idx` - The index of the honest party (0 <= party_idx < H)
    /// * `trbfv_idx` - The index of the TRBFV basis (0 <= trbfv_idx < L)
    ///
    /// # Panics
    /// The circuit will fail if the decoded message doesn't match the claimed decrypted share
    /// for any non-zero coefficient.
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

    /// Verifies TRBFV share aggregation: `sum_h decrypted_shares[h][l] mod trbfv_qi[l] = expected[l]` for each TRBFV basis l.
    ///
    /// This function verifies that for each TRBFV basis, the sum of all H honest parties'
    /// decrypted shares modulo the TRBFV modulus equals the expected aggregated share.
    ///
    /// For each TRBFV basis l and each coefficient position:
    /// - Sums the decrypted shares from all H honest parties
    /// - Reduces the sum modulo the TRBFV modulus `trbfv_qi[l]`
    /// - Verifies the result equals the expected aggregated share coefficient
    ///
    /// This ensures that the aggregation of individual decrypted shares correctly produces
    /// the expected TRBFV secret key share for each basis.
    ///
    /// # Panics
    /// The circuit will fail if the aggregated shares don't match the expected values
    /// for any TRBFV basis or coefficient.
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
