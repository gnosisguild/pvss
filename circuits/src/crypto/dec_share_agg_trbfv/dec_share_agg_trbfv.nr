use crate::math::mod_fns::{div_mod, mul_mod, reduce_mod, sub};
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for decryption share aggregation circuit.
/// Contains the core mathematical constants used in the threshold scheme.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Plaintext modulus
    pub plaintext_modulus: Field,
}

impl<let L: u32> CryptographicParams<L> {
    /// Creates new cryptographic parameters
    pub fn new(qis: [Field; L], plaintext_modulus: Field) -> Self {
        CryptographicParams { qis, plaintext_modulus }
    }
}

/// Complete parameters for decryption share aggregation circuit.
pub struct Params<let N: u32, let T: u32, let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Ring dimension (number of polynomial coefficients)
    pub n: u32,
    /// Number of CRT bases
    pub l: u32,
    /// Threshold (number of parties needed - 1, we need t+1 parties)
    pub threshold: u32,
    /// Delta values for each RNS modulus: delta_l = q_l / t
    pub deltas: [Field; L],
    /// Half-delta values for noise bound checking: delta_half_l = delta_l / 2
    pub delta_halves: [Field; L],
}

impl<let N: u32, let T: u32, let L: u32> Params<N, T, L> {
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        plaintext_modulus: Field,
        n: u32,
        l: u32,
        threshold: u32,
        deltas: [Field; L],
        delta_halves: [Field; L],
    ) -> Self {
        let crypto = CryptographicParams::new(qis, plaintext_modulus);
        Params { crypto, n, l, threshold, deltas, delta_halves }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
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
/// 4. This gives us N interpolated values u_k(0) which form a polynomial u(x) of degree N-1
/// 5. We verify correct decoding by checking the noise bound: ||u - delta*m|| < delta/2
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
///        Note: This may be smaller than the full ring dimension if we only need part of the message
/// * `T` - The threshold value (we need T+1 parties to reconstruct)
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
/// * `BIT_NOISE` - Bit-width bound for noise coefficients
pub struct DecryptionShareAggregation<let N: u32, let T: u32, let L: u32, let BIT_NOISE: u32> {
    /// Circuit parameters including crypto constants
    params: Params<N, T, L>,

    /// Decryption shares from t+1 parties (public inputs)
    decryption_shares: [[Polynomial<N>; L]; T + 1],

    /// Party IDs (x-coordinates) for interpolation (public inputs)
    party_ids: [Field; T + 1],

    /// Message polynomial m(x) (public input)
    message: Polynomial<N>,
}

impl<let N: u32, let T: u32, let L: u32, let BIT_NOISE: u32> DecryptionShareAggregation<N, T, L, BIT_NOISE> {
    /// Creates a new decryption share aggregation circuit instance
    pub fn new(
        params: Params<N, T, L>,
        decryption_shares: [[Polynomial<N>; L]; T + 1],
        party_ids: [Field; T + 1],
        message: Polynomial<N>,
    ) -> Self {
        DecryptionShareAggregation { params, decryption_shares, party_ids, message }
    }

    /// Main verification function
    pub fn verify(self) {
        // Compute Lagrange coefficients in-circuit
        let lagrange_coeffs = self.compute_all_lagrange_coeffs();

        // Perform Lagrange interpolation and verify decoding for each basis
        for basis_idx in 0..L {
            self.verify_lagrange_interpolation_and_decoding(basis_idx, lagrange_coeffs);
        }
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
        // With party IDs in [1, 100], differences are in [1, 99]
        let mut diffs = [[0 as Field; T + 1]; T + 1];
        for i in 0..(T + 1) {
            for j in (i + 1)..(T + 1) {
                let diff = self.party_ids[j] - self.party_ids[i];
                diffs[i][j] = diff;
                diffs[j][i] = diff;
            }
        }

        // Step 2: Determine signs (same for all parties within a basis)
        // Numerator: PRODUCT(j!=i) (-x_j) has T negative signs
        let numerator_sign_negative = (T % 2) == 1;

        // Step 3: For each CRT basis, compute Lagrange coefficients
        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            // Compute product of all party IDs: PRODUCT(j=0..T) x_j mod q_l
            // Use iterative multiplication with reduction to keep result in [0, q_l)
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
                // Count negative factors: when j > party_idx, we have (x_party_idx - x_j) < 0
                let num_greater = T - party_idx;
                let denom_sign_negative = (num_greater % 2) == 1;

                // Compute unsigned result: |numerator| / |denominator| mod q_l
                let result_abs = div_mod(numerator_abs, denominator_abs, q_l);

                // If signs are different, negate; if same, keep positive
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

    /// Performs Lagrange interpolation and verifies correct decoding via noise bound check
    fn verify_lagrange_interpolation_and_decoding(
        self,
        basis_idx: u32,
        lagrange_coeffs: [[Field; T + 1]; L],
    ) {
        let q_l = self.params.crypto.qis[basis_idx];
        let delta_l = self.params.deltas[basis_idx];
        let delta_half = self.params.delta_halves[basis_idx];

        let mut noise_coeffs = [0 as Field; N];

        // Perform Lagrange interpolation with modular reduction
        for coeff_idx in 0..N {
            let mut u_coeff = 0 as Field;

            // Sum all contributions: u = SUM(i=0..T) [d_i * L_i(0)] mod q_l
            for party_idx in 0..(T + 1) {
                let d_coeff = self.decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
                let l_i_0 = lagrange_coeffs[basis_idx][party_idx];

                // Accumulate: u += d_i * L_i(0) mod q_l
                let term = mul_mod(d_coeff, l_i_0, q_l);
                u_coeff = reduce_mod(u_coeff + term, q_l);
            }

            // Compute noise: noise = u - delta_l*m mod q_l
            let m_coeff = self.message.coefficients[coeff_idx];
            let delta_m = mul_mod(delta_l, m_coeff, q_l);

            let noise = sub(u_coeff, delta_m, q_l);

            noise_coeffs[coeff_idx] = noise;
        }

        // Verify noise bound: noise in [-delta_half, delta_half]
        let noise_poly = Polynomial { coefficients: noise_coeffs };
        noise_poly.range_check_2bounds::<BIT_NOISE>(delta_half, delta_half);
    }
}
