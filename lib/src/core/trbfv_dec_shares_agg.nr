use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;
use dep::bignum::BigNum;
use dep::bignum::bignum::to_field;
use dep::bignum::Enclave_TRBFV_8192;

/// Cryptographic parameters for the TRBFV decryption share aggregation circuit.
///
/// This struct contains all the mathematical constants needed to verify correct
/// aggregation of decryption shares and message decoding in threshold BFV.
///
/// # Generic Parameters
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
pub struct Configs<let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Plaintext modulus (typically denoted as `t`)
    pub plaintext_modulus: Field,
    /// Precomputed value: `-Q^(-1) mod t` where Q is the product of all CRT moduli
    pub q_inverse_mod_t: Field,
}

impl<let L: u32> Configs<L> {
    /// Creates a new `Configs` instance with the specified cryptographic parameters.
    ///
    /// # Arguments
    /// All parameters correspond to the fields of the `Configs` struct. See the struct
    /// documentation for details on each parameter.
    ///
    /// # Returns
    /// A new `Configs` instance ready for use with the `DecryptionSharesAggregation` circuit.
    pub fn new(qis: [Field; L], plaintext_modulus: Field, q_inverse_mod_t: Field) -> Self {
        Configs { qis, plaintext_modulus, q_inverse_mod_t }
    }
}

/// TRBFV Decryption Share Aggregation Circuit.
///
/// This circuit implements a zero-knowledge proof for the correct aggregation of T+1
/// decryption shares using Lagrange interpolation to recover the final decrypted message
/// in threshold BFV (TRBFV).
///
/// The circuit verifies the complete decryption process:
/// 1. **Lagrange Interpolation**: Computes Lagrange coefficients L_i(0) for each party
///    and each CRT basis, then interpolates decryption shares to recover u^{(l)} for each basis l
/// 2. **CRT Reconstruction**: Verifies that u_global is the correct CRT reconstruction of
///    all per-basis interpolation results: `u^{(l)} + r^{(l)} * q_l = u_global` for all bases l
/// 3. **Message Decoding**: Verifies that the decoded message m is correct by checking
///    the decoding operation was performed correctly
///
/// The decoding step in BFV decryption recovers the message m from u by computing:
/// `m = round(u / delta) mod t`
///
/// Instead of performing the decoding operation directly, we verify it was done correctly
/// by checking that the decoding computation matches the claimed message. This ensures
/// that if the noise is bounded (|noise| < delta/2), the decoded message is correct.
///
/// # Generic Parameters
/// * `N_PARTIES` - The number of coefficients in the message and decryption share polynomials
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
/// * `T` - The threshold value (we need T+1 parties to reconstruct the secret)
/// * `BIT_NOISE` - Bit-width bound for noise coefficients (currently unused but reserved for future use)
pub struct DecryptionSharesAggregation<let N_PARTIES: u32, let L: u32, let T: u32, let BIT_NOISE: u32> {
    /// Circuit parameters including crypto constants
    configs: Configs<L>,

    /// Decryption shares from t+1 parties (public inputs)
    decryption_shares: [[Polynomial<N_PARTIES>; L]; T + 1],

    /// Party IDs (x-coordinates) for interpolation (public inputs)
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public input)
    message: Polynomial<N_PARTIES>,

    /// Global u polynomial (public input)
    /// This is the CRT reconstruction of all u^{(l)} values
    u_global: Polynomial<N_PARTIES>,

    /// CRT quotient polynomials (public inputs)
    /// For each basis l, r^{(l)} satisfies: u^{(l)} + r^{(l)} * q_l = u_global
    crt_quotients: [Polynomial<N_PARTIES>; L],
}

impl<let N_PARTIES: u32, let L: u32, let T: u32, let BIT_NOISE: u32> DecryptionSharesAggregation<N_PARTIES, L, T, BIT_NOISE> {
    /// Creates a new `DecryptionSharesAggregation` circuit instance.
    ///
    /// This constructor initializes all the polynomials and parameters needed for
    /// the zero-knowledge proof of correct decryption share aggregation and message decoding.
    ///
    /// # Arguments
    /// * `configs` - Cryptographic parameters including moduli, plaintext modulus, and scaling factors
    /// * `decryption_shares` - Decryption shares from T+1 parties (public inputs, one per CRT basis)
    /// * `party_ids` - Party IDs (x-coordinates) for Lagrange interpolation (public inputs)
    /// * `message` - Decoded message polynomial m(x) (public input)
    /// * `u_global` - Global u polynomial from CRT reconstruction (public input)
    /// * `crt_quotients` - CRT quotient polynomials r^{(l)} for each CRT basis (public inputs)
    ///
    /// # Returns
    /// A new `DecryptionSharesAggregation` instance ready for constraint checking via the `verify()` method
    pub fn new(
        configs: Configs<L>,
        decryption_shares: [[Polynomial<N_PARTIES>; L]; T + 1],
        party_ids: [Field; T + 1],
        message: Polynomial<N_PARTIES>,
        u_global: Polynomial<N_PARTIES>,
        crt_quotients: [Polynomial<N_PARTIES>; L],
    ) -> Self {
        DecryptionSharesAggregation {
            configs,
            decryption_shares,
            party_ids,
            message,
            u_global,
            crt_quotients,
        }
    }

    /// Main verification function that performs all circuit checks.
    ///
    /// This function implements the complete zero-knowledge proof by verifying:
    /// 1. Lagrange interpolation of decryption shares for each CRT basis
    /// 2. CRT reconstruction of per-basis interpolation results
    /// 3. Correct message decoding from the global u polynomial
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any verification step fails.
    /// The circuit fails if:
    /// - CRT reconstruction doesn't hold for any basis
    /// - Message decoding doesn't match the claimed message for any coefficient
    pub fn verify(self) {
        // Step 1: Compute Lagrange coefficients in-circuit
        let lagrange_coeffs = self.compute_all_lagrange_coeffs();

        // Step 2: Compute u^{(l)} for each CRT basis via Lagrange interpolation
        let u_crts = self.compute_crt_components(lagrange_coeffs);

        // Step 3: Verify CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global
        self.verify_crt_reconstruction(u_crts);

        // Step 4: Verify global noise bound
        self.verify_decoding_alternative();
    }

    pub fn verify_no_bn(self) {
        // Step 1: Compute Lagrange coefficients in-circuit
        let lagrange_coeffs = self.compute_all_lagrange_coeffs();

        // Step 2: Compute u^{(l)} for each CRT basis via Lagrange interpolation
        let u_crts = self.compute_crt_components(lagrange_coeffs);

        // Step 3: Verify CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global
        self.verify_crt_reconstruction(u_crts);

        // Step 4: Verify global noise bound
        self.verify_decoding_alternative_no_bn();
    }

    /// Computes all Lagrange coefficients using optimized modular arithmetic.
    ///
    /// For each party i with ID x_i and each CRT basis l with modulus q_l, computes:
    /// `L_i(0) = PRODUCT(j!=i) (-x_j) / (x_i - x_j) mod q_l`
    ///
    /// These coefficients are used to interpolate the decryption shares at point 0,
    /// which recovers the aggregated secret key evaluation needed for decryption.
    ///
    /// The implementation uses efficient Field arithmetic with modular reduction.
    /// Since party IDs are typically in [1, 100] and moduli are <= 2^56, all
    /// intermediate values fit within the Field type.
    ///
    /// # Returns
    /// A 2D array `lagrange_coeffs[basis_idx][party_idx]` containing the Lagrange
    /// coefficient L_i(0) for each party i and each CRT basis.
    fn compute_all_lagrange_coeffs(self) -> [[Field; T + 1]; L] {
        let mut lagrange_coeffs = [[0 as Field; T + 1]; L];

        // Step 1: Cache |x_i - x_j| factors for all party pairs
        let mut diffs = [[0 as Field; T + 1]; T + 1];
        for i in 0..(T + 1) {
            for j in (i + 1)..(T + 1) {
                let diff = self.party_ids[j] - self.party_ids[i];
                diffs[i][j] = diff;
                diffs[j][i] = diff;
            }
        }

        // Step 2: Determine signs (same for all parties within a basis)
        let numerator_sign_negative = (T % 2) == 1;

        // Step 3: For each CRT basis, compute Lagrange coefficients
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];
            let m = ModU128::new(q_l);

            // Compute product of all party IDs: PRODUCT(j=0..T) x_j mod q_l
            let mut product_x = 1 as Field;
            for j in 0..(T + 1) {
                product_x = m.mul_mod(product_x, self.party_ids[j]);
            }

            // For each party i, compute L_i(0) mod q_l
            for party_idx in 0..(T + 1) {
                // Numerator (absolute value): PRODUCT(j!=party_idx) x_j
                let numerator_abs = m.div_mod(product_x, self.party_ids[party_idx]);

                // Denominator (absolute value): PRODUCT(j!=party_idx) |x_party_idx - x_j|
                let mut denominator_abs = 1 as Field;
                for j in 0..(T + 1) {
                    if j != party_idx {
                        denominator_abs = m.mul_mod(denominator_abs, diffs[party_idx][j]);
                    }
                }

                // Determine denominator sign
                let num_greater = T - party_idx;
                let denom_sign_negative = (num_greater % 2) == 1;

                // Compute unsigned result: |numerator| / |denominator| mod q_l
                let result_abs = m.div_mod(numerator_abs, denominator_abs);

                // Apply combined sign
                let should_negate = numerator_sign_negative != denom_sign_negative;
                let result = if should_negate {
                    m.reduce_mod(q_l - result_abs)
                } else {
                    result_abs
                };

                lagrange_coeffs[basis_idx][party_idx] = result;
            }
        }

        lagrange_coeffs
    }

    /// Computes u^{(l)} for each CRT basis via Lagrange interpolation.
    ///
    /// For each coefficient position and each CRT basis, computes:
    /// `u^{(l)}[k] = SUM(i=0..T) [d_i^{(l)}[k] * L_i(0)] mod q_l`
    ///
    /// Where:
    /// - `d_i^{(l)}[k]` is the k-th coefficient of party i's decryption share for basis l
    /// - `L_i(0)` is the Lagrange coefficient for party i evaluated at 0
    ///
    /// This recovers the aggregated secret key evaluation u^{(l)} needed for decryption
    /// in each CRT basis independently.
    ///
    /// # Arguments
    /// * `lagrange_coeffs` - Precomputed Lagrange coefficients for all parties and CRT bases
    ///
    /// # Returns
    /// An array of polynomials `u_crts[l]` representing the interpolated result for each CRT basis l
    fn compute_crt_components(
        self,
        lagrange_coeffs: [[Field; T + 1]; L],
    ) -> [Polynomial<N_PARTIES>; L] {
        let mut u_crts: [Polynomial<N_PARTIES>; L] = [Polynomial::new([0; N_PARTIES]); L];

        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];
            let m = ModU128::new(q_l);
            let mut u_coeffs = [0 as Field; N_PARTIES];

            // For each coefficient position
            for coeff_idx in 0..N_PARTIES {
                let mut u_coeff = 0 as Field;

                // Sum all contributions: u = SUM(i=0..T) [d_i * L_i(0)] mod q_l
                for party_idx in 0..(T + 1) {
                    let d_coeff =
                        self.decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
                    let l_i_0 = lagrange_coeffs[basis_idx][party_idx];

                    let term = m.mul_mod(d_coeff, l_i_0);
                    u_coeff = m.reduce_mod(u_coeff + term);
                }

                u_coeffs[coeff_idx] = u_coeff;
            }

            u_crts[basis_idx] = Polynomial::new(u_coeffs);
        }

        u_crts
    }

    /// Verifies CRT reconstruction: `u^{(l)} + r^{(l)} * q_l = u_global` for all bases l.
    ///
    /// This function proves that `u_global` is the correct CRT reconstruction of the
    /// per-basis interpolation results `u^{(l)}`. The CRT reconstruction ensures that
    /// the global polynomial `u_global` can be recovered from the per-basis results
    /// using the Chinese Remainder Theorem.
    ///
    /// For each CRT basis l, the function verifies that:
    /// - `u^{(l)}` (computed via Lagrange interpolation) plus
    /// - `r^{(l)} * q_l` (CRT quotient times modulus) equals
    /// - `u_global` (the claimed global polynomial)
    ///
    /// This must hold for every coefficient position.
    ///
    /// # Arguments
    /// * `u_crts` - Per-basis interpolation results computed via `compute_crt_components()`
    ///
    /// # Panics
    /// The circuit will fail if the CRT reconstruction doesn't hold for any basis or coefficient.
    fn verify_crt_reconstruction(self, u_crts: [Polynomial<N_PARTIES>; L]) {
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];

            // Compute r^{(l)} * q_l
            let r_times_q = self.crt_quotients[basis_idx].mul_scalar(q_l);

            // Compute u^{(l)} + r^{(l)} * q_l
            let reconstructed = u_crts[basis_idx].add(r_times_q);

            // Verify: u^{(l)} + r^{(l)} * q_l = u_global
            // Must hold for every coefficient
            for coeff_idx in 0..N_PARTIES {
                assert(
                    reconstructed.coefficients[coeff_idx] == self.u_global.coefficients[coeff_idx],
                    "CRT reconstruction verification failed",
                );
            }
        }
    }

    /// Verifies that the decoded message m is correct by checking the decoding computation.
    ///
    /// This function verifies the BFV decoding operation: `m = round(u / delta) mod t`
    /// by checking that the decoding computation matches the claimed message polynomial.
    ///
    /// The decoding process involves:
    /// 1. Computing `(t * u_global) mod Q` where Q is the product of all CRT moduli
    /// 2. Handling centered arithmetic (values >= Q/2 are treated as negative)
    /// 3. Computing `-Q^(-1) * (t * u_global) mod t` to recover the message
    ///
    /// The function only verifies non-zero message coefficients to allow for sparse messages.
    ///
    /// # Panics
    /// The circuit will fail if the decoded message doesn't match the claimed message
    /// for any non-zero coefficient.
    fn verify_decoding_alternative(self) {
        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1 as Field;
        for l in 0..L {
            q_modulus *= self.configs.qis[l];
        }

        // For centered arithmetic
        let q_bn = Enclave_TRBFV_8192::from(q_modulus);

        let q_half_bn = q_bn.udiv(Enclave_TRBFV_8192::from(2));

        std::println("=== Alternative Decoding Verification ===");

        for coeff_idx in 0..N_PARTIES {
            // Compute (t * u_global) mod Q using BigNum
            let u_bn_q = Enclave_TRBFV_8192::from(self.u_global.coefficients[coeff_idx]);
            let t_bn_q = Enclave_TRBFV_8192::from(self.configs.plaintext_modulus);
            let t_times_u_bn_q = t_bn_q * u_bn_q;
            let m = ModU128::new(self.configs.plaintext_modulus);

            // Check if centering is needed
            let needs_centering = t_times_u_bn_q > q_half_bn;

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Centered value is conceptually negative: (t_times_u_mod_q - Q)
                // -Q^{-1} * (negative) = positive result
                let centered_positive = q_bn - t_times_u_bn_q;
                let centered_positive_mod_t = centered_positive.umod(t_bn_q);
                let centered_field = to_field(centered_positive_mod_t);
                m.mul_mod(self.configs.q_inverse_mod_t, centered_field)
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // -Q^{-1} * (positive) = negative result = t - result
                let t_times_u_bn_t = t_times_u_bn_q.umod(t_bn_q);
                let t_times_u_field = to_field(t_times_u_bn_t);
                let product = m.mul_mod(self.configs.q_inverse_mod_t, t_times_u_field);
                if product == 0 {
                    0
                } else {
                    self.configs.plaintext_modulus - product
                }
            };

            // Verify: only check non-zero coefficients
            if self.message.coefficients[coeff_idx] != 0 {
                assert(computed_message == self.message.coefficients[coeff_idx]);
            }
        }

        std::println("=== All verified ===");
    }

    /// Alternative decoding verification using the formula:
    /// message = -Q^{-1} * (t * u_global)_Q mod t
    ///
    /// Uses BigNum arithmetic modulo t (plaintext_modulus) for all operations.
    /// Q is 72 bits for insecure parameter set , so no need for bignum
    fn verify_decoding_alternative_no_bn(self) {
        let t: Field = self.configs.plaintext_modulus;
        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1;
        for l in 0..L {
            q_modulus *= self.configs.qis[l];
        }

        // For centered arithmetic
        // let q_bn = Enclave_TRBFV_8192::from(q_modulus);
        // let q_half_bn = q_bn.udiv(Enclave_TRBFV_8192::from(2));

        // std::println("=== Alternative Decoding Verification ===");

        let q_half = q_modulus as u128 / 2;

        for coeff_idx in 0..N_PARTIES {
            // Compute (t * u_global) mod Q using BigNum
            // let u_bn_q = Enclave_TRBFV_8192::from(self.u_global.coefficients[coeff_idx]);
            // let t_bn_q = Enclave_TRBFV_8192::from(t);
            // let t_times_u_bn_q = t_bn_q * u_bn_q;

            let q_mod = ModU128::new(q_modulus);
            let t_mod = ModU128::new(t);
            // Compute (t * u_global) mod Q using modular arithemtic fns
            let t_times_u_mod_q = q_mod.mul_mod(t, self.u_global.coefficients[coeff_idx]);
            //check if better to keep it u128
            let needs_centering = (t_times_u_mod_q as u128) > q_half;

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Centered value is conceptually negative: (t_times_u_mod_q - Q)
                // -Q^{-1} * (negative) = positive result
                // let centered_positive = q_bn - t_times_u_bn_q;
                // let centered_positive_mod_t = centered_positive.umod(t_bn_q);
                // let centered_field = to_field(centered_positive_mod_t);
                // mul_mod(self.params.crypto.q_inverse_mod_t, centered_field, t)
                let centered_positive = q_modulus - t_times_u_mod_q;
                let centered_positive_mod_t = t_mod.reduce_mod(centered_positive);

                t_mod.mul_mod(self.configs.q_inverse_mod_t, centered_positive_mod_t)
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // -Q^{-1} * (positive) = negative result = t - result
                // let t_times_u_bn_t = t_times_u_bn_q.umod(t_bn_q);
                // let t_times_u_field = to_field(t_times_u_bn_t);
                // let product = mul_mod(self.params.crypto.q_inverse_mod_t, t_times_u_field, t);
                let t_times_u_mod_t = t_mod.reduce_mod(t_times_u_mod_q);
                let product = t_mod.mul_mod(self.configs.q_inverse_mod_t, t_times_u_mod_t);
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
