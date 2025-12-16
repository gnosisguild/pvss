use crate::math::modular_fns::{div_mod, mul_mod, reduce_mod};
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for decryption share aggregation circuit.
pub struct CryptographicParams<let L: u32> {
    pub qis: [Field; L],
    pub plaintext_modulus: Field,
    pub q_inverse_mod_t: Field,
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L], plaintext_modulus: Field, q_inverse_mod_t: Field) -> Self {
        CryptographicParams { qis, plaintext_modulus, q_inverse_mod_t }
    }
}

pub struct BoundParams {
    pub delta: Field,
    pub delta_half: Field,
}

impl BoundParams {
    pub fn new(delta: Field, delta_half: Field) -> Self {
        BoundParams { delta, delta_half }
    }
}

/// Complete parameters for decryption share aggregation circuit.
pub struct Params<let N: u32, let L: u32, let T: u32> {
    pub crypto: CryptographicParams<L>,
    pub bounds: BoundParams,
}

impl<let N: u32, let L: u32, let T: u32> Params<N, L, T> {
    pub fn new(
        qis: [Field; L],
        plaintext_modulus: Field,
        q_inverse_mod_t: Field,
        delta: Field,
        delta_half: Field,
    ) -> Self {
        let crypto = CryptographicParams::new(qis, plaintext_modulus, q_inverse_mod_t);
        let bounds = BoundParams::new(delta, delta_half);
        Params { crypto, bounds }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams {
        self.bounds
    }
}

/// Decryption Share Aggregation Circuit (Circuit 8: dec-result-trbfv)
///
/// Verifies:
/// 1. Lagrange interpolation to compute u^{(l)} for each CRT basis
/// 2. CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global
/// 3. Decoding verification: message = -Q^{-1} * (t * u_global)_Q mod t
pub struct DecryptionShareAggregation<let N: u32, let L: u32, let T: u32, let BIT_NOISE: u32> {
    /// Circuit parameters including crypto constants
    params: Params<N, L, T>,

    /// Decryption shares from t+1 parties (public inputs)
    decryption_shares: [[Polynomial<N>; L]; T + 1],

    /// Party IDs (x-coordinates) for interpolation (public inputs)
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public output)
    message: Polynomial<N>,

    /// Global u polynomial (secret witness)
    u_global: Polynomial<N>,

    /// CRT quotient polynomials (secret witnesses)
    crt_quotients: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let T: u32, let BIT_NOISE: u32> DecryptionShareAggregation<N, L, T, BIT_NOISE> {
    pub fn new(
        params: Params<N, L, T>,
        decryption_shares: [[Polynomial<N>; L]; T + 1],
        party_ids: [Field; T + 1],
        message: Polynomial<N>,
        u_global: Polynomial<N>,
        crt_quotients: [Polynomial<N>; L],
    ) -> Self {
        DecryptionShareAggregation {
            params,
            decryption_shares,
            party_ids,
            message,
            u_global,
            crt_quotients,
        }
    }

    /// Main verification function
    pub fn verify(self) {
        // Step 1: Compute Lagrange coefficients in-circuit
        let lagrange_coeffs = self.compute_all_lagrange_coeffs();

        // Step 2: Compute u^{(l)} for each CRT basis via Lagrange interpolation
        let u_crts = self.compute_crt_components(lagrange_coeffs);

        // Step 3: Verify CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global
        self.verify_crt_reconstruction(u_crts);

        // Step 4: Verify decoding
        self.verify_decoding();
    }

    /// Computes all Lagrange coefficients using optimized modular arithmetic
    fn compute_all_lagrange_coeffs(self) -> [[Field; T + 1]; L] {
        let mut lagrange_coeffs = [[0 as Field; T + 1]; L];
        let crypto_params = self.params.crypto_params();

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
            let q_l = crypto_params.qis[basis_idx];

            // Compute product of all party IDs: PRODUCT(j=0..T) x_j mod q_l
            let mut product_x = 1 as Field;
            for j in 0..(T + 1) {
                product_x = mul_mod(product_x, self.party_ids[j], q_l);
            }

            // For each party i, compute L_i(0) mod q_l
            for party_idx in 0..(T + 1) {
                // Numerator (absolute value): PRODUCT(j!=party_idx) x_j
                let numerator_abs = div_mod(product_x, self.party_ids[party_idx], q_l);

                // Denominator (absolute value): PRODUCT(j!=party_idx) |x_party_idx - x_j|
                let mut denominator_abs = 1 as Field;
                for j in 0..(T + 1) {
                    if j != party_idx {
                        denominator_abs = mul_mod(denominator_abs, diffs[party_idx][j], q_l);
                    }
                }

                // Determine denominator sign
                let num_greater = T - party_idx;
                let denom_sign_negative = (num_greater % 2) == 1;

                // Compute unsigned result: |numerator| / |denominator| mod q_l
                let result_abs = div_mod(numerator_abs, denominator_abs, q_l);

                // Apply combined sign
                let should_negate = numerator_sign_negative != denom_sign_negative;
                let result = if should_negate {
                    reduce_mod(q_l - result_abs, q_l)
                } else {
                    result_abs
                };

                lagrange_coeffs[basis_idx][party_idx] = result;
            }
        }

        lagrange_coeffs
    }

    /// Computes u^{(l)} for each CRT basis via Lagrange interpolation
    fn compute_crt_components(self, lagrange_coeffs: [[Field; T + 1]; L]) -> [Polynomial<N>; L] {
        let mut u_crts: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        let crypto_params = self.params.crypto_params();

        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];
            let mut u_coeffs = [0 as Field; N];

            // For each coefficient position
            for coeff_idx in 0..N {
                let mut u_coeff = 0 as Field;

                // Sum all contributions: u = SUM(i=0..T) [d_i * L_i(0)] mod q_l
                for party_idx in 0..(T + 1) {
                    let d_coeff =
                        self.decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
                    let l_i_0 = lagrange_coeffs[basis_idx][party_idx];

                    let term = mul_mod(d_coeff, l_i_0, q_l);
                    u_coeff = reduce_mod(u_coeff + term, q_l);
                }

                u_coeffs[coeff_idx] = u_coeff;
            }

            u_crts[basis_idx] = Polynomial::new(u_coeffs);
        }

        u_crts
    }

    /// Verifies CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global for all bases l
    fn verify_crt_reconstruction(self, u_crts: [Polynomial<N>; L]) {
        let crypto_params = self.params.crypto_params();

        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            // Compute r^{(l)} * q_l
            let r_times_q = self.crt_quotients[basis_idx].mul_scalar(q_l);

            // Compute u^{(l)} + r^{(l)} * q_l
            let reconstructed = u_crts[basis_idx].add(r_times_q);

            // Verify: u^{(l)} + r^{(l)} * q_l = u_global
            for coeff_idx in 0..N {
                assert(
                    reconstructed.coefficients[coeff_idx] == self.u_global.coefficients[coeff_idx],
                    "CRT reconstruction verification failed",
                );
            }
        }
    }

    /// Alternative decoding verification using the formula:
    /// message = -Q^{-1} * (t * u_global)_Q mod t
    fn verify_decoding(self) {
        let t: Field = self.params.crypto.plaintext_modulus;

        // Compute Q as product of all CRT moduli
        let mut q_modulus = 1;
        for l in 0..L {
            q_modulus *= self.params.crypto.qis[l];
        }

        let q_half = q_modulus as u128 / 2;

        for coeff_idx in 0..N {
            let t_times_u_mod_q = mul_mod(t, self.u_global.coefficients[coeff_idx], q_modulus);

            let needs_centering = t_times_u_mod_q as u128 > q_half;

            let computed_message = if needs_centering {
                let centered_positive = q_modulus - t_times_u_mod_q;
                let centered_positive_mod_t = reduce_mod(centered_positive, t);

                mul_mod(
                    self.params.crypto.q_inverse_mod_t,
                    centered_positive_mod_t,
                    t,
                )
            } else {
                let t_times_u_mod_t = reduce_mod(t_times_u_mod_q, t);

                let product = mul_mod(self.params.crypto.q_inverse_mod_t, t_times_u_mod_t, t);
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
