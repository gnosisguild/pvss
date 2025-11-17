use crate::math::modular_fns::{div_mod, mul_mod, reduce_mod};
use crate::math::polynomial::Polynomial;
use dep::bignum::BigNum;
use dep::bignum::Enclave_100;

/// Cryptographic parameters for decryption share aggregation circuit.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Plaintext modulus
    pub plaintext_modulus: Field,
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L], plaintext_modulus: Field) -> Self {
        CryptographicParams { qis, plaintext_modulus }
    }
}

pub struct BoundParams {
    /// Global delta value: delta = floor(q/t) where q = product of all q_i
    pub delta: Field,
    /// Global half-delta value for noise bound checking: delta_half = floor(delta / 2)
    pub delta_half: Field,
}

impl BoundParams {
    /// Creates new bound parameters
    pub fn new(delta: Field, delta_half: Field) -> Self {
        BoundParams { delta, delta_half }
    }
}

/// Complete parameters for decryption share aggregation circuit.
pub struct Params<let N: u32, let L: u32, let T: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams,
}

impl<let N: u32, let L: u32, let T: u32> Params<N, L, T> {
    pub fn new(qis: [Field; L], plaintext_modulus: Field, delta: Field, delta_half: Field) -> Self {
        let crypto = CryptographicParams::new(qis, plaintext_modulus);
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

/// Decryption Share Aggregation Circuit
///
/// This circuit aggregates t+1 decryption shares using Lagrange interpolation
/// to recover the final decrypted message. The process involves:
///
/// 1. Each of t+1 parties provides a polynomial d_i(x) of degree N-1 with their party ID x_i
/// 2. Compute Lagrange coefficients L_i(0) for each party and each CRT basis
/// 3. For each coefficient position (0 to N-1), apply Lagrange interpolation independently
///    to get u^{(l)} for each CRT basis l
/// 4. Verify CRT reconstruction: u^{(l)} + r^{(l)} * q_l = u_global for all bases l
/// 5. Compute global noise: noise = u_global - delta * m
/// 6. Verify noise bound: |noise| < delta/2
///
/// The decoding step in BFV decryption recovers the message m from u by computing:
///    m = round(u / delta) mod t
///
/// Instead of performing the decoding operation directly, we verify it was done correctly
/// by checking that the noise (u - delta*m) is bounded. If ||noise|| < delta/2, then
/// the decoded message m is guaranteed to be correct and unique in the plaintext space [0, t).
///
/// # Generic Parameters
/// * `N` - The message degree (number of coefficients in the message and decryption share polynomials)
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
/// * `T` - The threshold value (we need T+1 parties to reconstruct)
/// * `BIT_NOISE` - Bit-width bound for noise coefficients
pub struct DecryptionShareAggregation<let N: u32, let L: u32, let T: u32, let BIT_NOISE: u32> {
    /// Circuit parameters including crypto constants
    params: Params<N, L, T>,

    /// Decryption shares from t+1 parties (public inputs)
    decryption_shares: [[Polynomial<N>; L]; T + 1],

    /// Party IDs (x-coordinates) for interpolation (public inputs)
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public input)
    message: Polynomial<N>,

    /// Global u polynomial (public input)
    /// This is the CRT reconstruction of all u^{(l)} values
    u_global: Polynomial<N>,

    /// CRT quotient polynomials (public inputs)
    /// For each basis l, r^{(l)} satisfies: u^{(l)} + r^{(l)} * q_l = u_global
    crt_quotients: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let T: u32, let BIT_NOISE: u32> DecryptionShareAggregation<N, L, T, BIT_NOISE> {
    /// Creates a new decryption share aggregation circuit instance
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

        // Step 4: Verify global noise bound
        self.verify_global_noise_bound();
    }

    /// Computes all Lagrange coefficients using optimized modular arithmetic
    ///
    /// For each party i with ID x_i in [1, 100] and each CRT basis l with modulus q_l, computes:
    /// L_i(0) = PRODUCT(j!=i) (-x_j) / (x_i - x_j) mod q_l
    ///
    /// Uses efficient Field arithmetic with modular reduction instead of BigNum.
    /// Since party IDs <= 100 and moduli <= 2^56, all intermediate values fit in Field.
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
    ///
    /// This proves that u_global is the correct CRT reconstruction of the per-basis
    /// interpolation results u^{(l)}.
    fn verify_crt_reconstruction(self, u_crts: [Polynomial<N>; L]) {
        let crypto_params = self.params.crypto_params();

        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            // Compute r^{(l)} * q_l
            let r_times_q = self.crt_quotients[basis_idx].mul_scalar(q_l);

            // Compute u^{(l)} + r^{(l)} * q_l
            let reconstructed = u_crts[basis_idx].add(r_times_q);

            // Verify: u^{(l)} + r^{(l)} * q_l = u_global
            // Must hold for every coefficient
            for coeff_idx in 0..N {
                assert(
                    reconstructed.coefficients[coeff_idx] == self.u_global.coefficients[coeff_idx],
                    "CRT reconstruction verification failed",
                );
            }
        }
    }
    #[allow(brillig_constraint_warning)]
    fn verify_global_noise_bound(self) {
        let bound_params = self.params.bound_params();

        // Compute delta * m
        let delta_m = self.message.mul_scalar(bound_params.delta);

        // Compute noise = u_global - delta * m using Enclave_100
        let mut noise_coeffs = [0 as Field; N];
        for coeff_idx in 0..N {
            // Convert Field values to Enclave_100
            let u_global_bn = Enclave_100::from(self.u_global.coefficients[coeff_idx]);
            let delta_m_bn = Enclave_100::from(delta_m.coefficients[coeff_idx]);

            // Perform constrained subtraction
            let noise_bn: Enclave_100 = u_global_bn - delta_m_bn;

            // Convert back to Field using limbs_to_field
            let limbs = noise_bn.get_limbs();

            // Convert back to Field: limbs[0] + limbs[1] * 2^120
            noise_coeffs[coeff_idx] =
                (limbs[0] as Field) + (limbs[1] as Field) * (2 as Field).pow_32(120);
        }

        // Verify noise bound: |noise| < delta_half
        let noise_poly = Polynomial::new(noise_coeffs);
        noise_poly.range_check_2bounds::<BIT_NOISE>(
            bound_params.delta_half,
            bound_params.delta_half,
        );
    }
}
