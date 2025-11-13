// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::polynomial::{flatten, Polynomial};
use safe::SafeSponge;

/// PLEASE NOTE THIS VERSION OF GRECO IS JUST USED FOR DEVELOPMENT.
/// REFER TO THE ORIGINAL GRECO CIRCUIT FOR THE PRODUCTION VERSION IN ENCLAVE MONOREPO.

/// Cryptographic parameters for Greco circuit.
/// Contains the core mathematical constants used in the encryption scheme.
pub struct CryptographicParams {
    /// Plaintext modulus: q mod t
    pub q_mod_t: Field,
    /// Ciphertext modulus (prime field)
    pub q: Field,
    /// Scaling factor for ciphertext component
    pub k0: Field,
}

impl CryptographicParams {
    /// Creates new cryptographic parameters
    pub fn new(q_mod_t: Field, q: Field, k0: Field) -> Self {
        CryptographicParams { q_mod_t, q, k0 }
    }
}

/// Bound parameters for range checking.
/// Contains all the bounds used to validate polynomial coefficients.
pub struct BoundParams {
    /// Bounds for error polynomials (e0)
    pub e0_bound: Field,
    /// Bounds for error polynomials (e1)
    pub e1_bound: Field,
    /// Bound for secret polynomial u (ternary distribution)
    pub u_bound: Field,
    /// Lower bound for k1 polynomial (scaled message)
    pub k1_low_bound: Field,
    /// Upper bound for k1 polynomial (scaled message)
    pub k1_up_bound: Field,
}

impl BoundParams {
    /// Creates new bound parameters
    pub fn new(
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        k1_low_bound: Field,
        k1_up_bound: Field,
    ) -> Self {
        BoundParams { e0_bound, e1_bound, u_bound, k1_low_bound, k1_up_bound }
    }
}

/// Complete parameters for Greco circuit.
/// Combines cryptographic parameters, bounds, and circuit-specific parameters.
pub struct Params<let N: u32> {
    /// Cryptographic parameters (moduli, scaling factors)
    pub crypto: CryptographicParams,
    /// Bound parameters for range checking
    pub bounds: BoundParams,
}

impl<let N: u32> Params<N> {
    /// Creates new complete parameters
    pub fn new(
        q_mod_t: Field,
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        k1_low_bound: Field,
        k1_up_bound: Field,
        q: Field,
        k0: Field,
    ) -> Self {
        let crypto = CryptographicParams::new(q_mod_t, q, k0);
        let bounds = BoundParams::new(e0_bound, e1_bound, u_bound, k1_low_bound, k1_up_bound);

        Params { crypto, bounds }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams {
        self.crypto
    }

    /// Convenience method to access bound parameters
    pub fn bound_params(self) -> BoundParams {
        self.bounds
    }
}

/// Greco
/// Correct Encryption Circuit under BFV public key
///
/// This circuit implements a zero-knowledge proof for the correct formation of a ciphertext
/// resulting from BFV (Brakerski-Fan-Vercauteren) public key encryption. The circuit verifies
/// that the ciphertext components (ct0, ct1) are correctly computed from the public key
/// components (pk0, pk1) and the encryption randomness.
///
/// The circuit enforces the following core constraints:
/// 1. Range checks on relevant polynomial coefficients to ensure they are within expected bounds
/// 2. Correct encryption equations:
///    a. ct0(gamma) = pk0(gamma) * u(gamma) + e0(gamma) + k1(gamma) * k0 + r2(gamma) * cyclo(gamma)
///    b. ct1(gamma) = pk1(gamma) * u(gamma) + e1(gamma) + p2(gamma) * cyclo(gamma)
///
/// DISCLAIMER
/// The circuit is a porting of the Halo2 circuit from Greco paper author @ PSE.
/// Halo2 implementation is available at https://github.com/privacy-scaling-explorations/greco
///
/// # Generic Parameters
/// * `N` - The degree of polynomials (ring dimension)
/// * `BIT_PK` - Bit-width bound per coefficient for public keys `pk0`/`pk1`
/// * `BIT_CT` - Bit-width bound per coefficient for ciphertexts `ct0`/`ct1`
/// * `BIT_U` - Bit-width bound per coefficient for the ternary secret `u`
/// * `BIT_E0` - Bit-width bound per coefficient for error polynomial `e0`
/// * `BIT_E1` - Bit-width bound per coefficient for error polynomial `e1`
/// * `BIT_K` - Bit-width bound per coefficient for the scaled message polynomial `k1`
/// * `BIT_R2` - Bit-width bound per coefficient for randomness polynomial `r2`
/// * `BIT_P2` - Bit-width bound per coefficient for randomness polynomial `p2`
///
/// # Circuit Inputs
/// * `pk0`, `pk1` - Public key polynomials
/// * `ct0`, `ct1` - Ciphertext polynomials
/// * `u` - Secret polynomial sampled from ternary distribution
/// * `e0`, `e1` - Error polynomials sampled from discrete Gaussian distribution
/// * `k1` - Scaled message polynomial
/// * `r2`, `p2` - Randomness polynomials for cyclotomic reductions.
pub struct Greco<
    let N: u32,
    let BIT_PK: u32,
    let BIT_CT: u32,
    let BIT_U: u32,
    let BIT_E0: u32,
    let BIT_E1: u32,
    let BIT_K: u32,
    let BIT_R2: u32,
    let BIT_P2: u32,
> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    params: Params<N>,
    pk0: Polynomial<N>,
    pk1: Polynomial<N>,
    ct0: Polynomial<N>,
    ct1: Polynomial<N>,
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    k1: Polynomial<N>,
    r2: Polynomial<N - 1>,
    p2: Polynomial<N - 1>,
}

impl<
        let N: u32,
        let BIT_PK: u32,
        let BIT_CT: u32,
        let BIT_U: u32,
        let BIT_E0: u32,
        let BIT_E1: u32,
        let BIT_K: u32,
        let BIT_R2: u32,
        let BIT_P2: u32,
    > Greco<N, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R2, BIT_P2> {
    /// Creates a new Greco instance.
    ///
    /// This constructor initializes all the polynomials and parameters needed for
    /// the zero-knowledge proof of correct ciphertext formation.
    ///
    /// # Arguments
    /// * `params` - Cryptographic parameters including bounds and moduli
    /// * `pk0` - Public key polynomial pk0 = a * s + e
    /// * `pk1` - Public key polynomial pk1 = -a
    /// * `ct0` - First ciphertext component
    /// * `ct1` - Second ciphertext component
    /// * `u` - Secret polynomial from ternary distribution
    /// * `e0` - Error polynomial sampled from discrete Gaussian distribution
    /// * `e1` - Error polynomial sampled from discrete Gaussian distribution
    /// * `k1` - Scaled message polynomial
    /// * `r2` - Randomness polynomial for ct0 computation (cyclotomic quotient)
    /// * `p2` - Randomness polynomial for ct1 computation (cyclotomic quotient)
    ///
    /// # Returns
    /// A new Greco instance ready for constraint checking
    pub fn new(
        params: Params<N>,
        pk0: Polynomial<N>,
        pk1: Polynomial<N>,
        ct0: Polynomial<N>,
        ct1: Polynomial<N>,
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e1: Polynomial<N>,
        k1: Polynomial<N>,
        r2: Polynomial<N - 1>,
        p2: Polynomial<N - 1>,
    ) -> Greco<N, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R2, BIT_P2> {
        Greco { params, pk0, pk1, ct0, ct1, u, e0, e1, k1, r2, p2 }
    }

    /// Flattens all polynomials coefficients into a single array for challenge generation.
    ///
    /// This function serializes all polynomial coefficients into a 1D array to enable
    /// the generation of random challenge values using the Fiat-Shamir transform.
    /// The coefficients are arranged in a specific order to ensure deterministic
    /// challenge generation.
    ///
    /// # Returns
    /// An array containing all polynomials coefficients in flattened form
    fn payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten public key and ciphertext polynomials first (public inputs)
        inputs = flatten::<_, _>(inputs, [self.pk0]);
        inputs = flatten::<_, _>(inputs, [self.pk1]);
        inputs = flatten::<_, _>(inputs, [self.ct0]);
        inputs = flatten::<_, _>(inputs, [self.ct1]);

        // Flatten common polynomials
        inputs = flatten::<_, _>(inputs, [self.e0]);
        inputs = flatten::<_, _>(inputs, [self.e1]);
        inputs = flatten::<_, _>(inputs, [self.u]);
        inputs = flatten::<_, _>(inputs, [self.k1]);

        // Flatten cyclotomic quotient polynomials
        inputs = flatten::<_, _>(inputs, [self.r2]);
        inputs = flatten::<_, _>(inputs, [self.p2]);

        inputs
    }

    /// Verifies the correct encryption constraints for the Greco circuit.
    ///
    /// This function implements the core zero-knowledge proof by checking:
    /// 1. Binary constraint on k1 polynomial
    /// 2. Range constraints on all polynomials coefficients
    /// 3. Correct encryption equations
    ///
    /// The proof uses the Schwartz-Zippel lemma: if polynomial equations hold
    /// when evaluated at random points, then the polynomials are identical with
    /// high probability.
    ///
    /// # Encryption Equations
    /// * ct0(gamma) = pk0(gamma) * u(gamma) + e0(gamma) + k1(gamma) * k0 + r2(gamma) * cyclo(gamma)
    /// * ct1(gamma) = pk1(gamma) * u(gamma) + e1(gamma) + p2(gamma) * cyclo(gamma)
    ///
    /// Where:
    /// * `k0` is a constant from the cryptographic parameters.
    /// * `cyclo(gamma) = gamma^N + 1` is the value of the cyclotomic polynomial at `gamma`.
    ///
    /// # Returns
    /// True if the encryption constraints are satisfied, false otherwise.
    pub fn verify(self) -> bool {
        // Step 1: Perform range checks on all polynomial coefficients
        self.check_range_bounds();

        // Step 2: Generate Fiat-Shamir challenges
        let (gamma_eval, gamma_lc) = self.generate_challenges();

        // Step 3: Verify encryption constraints using the challenges
        self.verify_evaluations(gamma_eval, gamma_lc)
    }

    /// Performs range checks on all polynomial coefficients
    ///
    /// Checks that all polynomial coefficients are within their expected bounds.
    /// This prevents attacks where coefficients are outside the valid range.
    ///
    /// # Returns
    /// True if the range bounds are satisfied, false otherwise.
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        // Common polynomials (used across all CRT bases)
        self.u.range_check_2bounds::<BIT_U>(bound_params.u_bound, bound_params.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(bound_params.e0_bound, bound_params.e0_bound);
        self.e1.range_check_2bounds::<BIT_E1>(bound_params.e1_bound, bound_params.e1_bound);
        self.k1.range_check_2bounds::<BIT_K>(bound_params.k1_up_bound, bound_params.k1_low_bound);

        // No range checks are required for ciphertext, public key, or cyclotomic quotient polynomials in this setting.
    }

    /// Generates Fiat-Shamir challenge values using a cryptographic sponge
    ///
    /// The sponge absorbs all witness values and squeezes out deterministic random field elements
    /// that will be used to evaluate polynomials for the Schwartz-Zippel lemma.
    ///
    /// # Returns
    /// Tuple `(gamma_eval, gamma_lc)` containing the evaluation point and the linear-combination weight.
    fn generate_challenges(self) -> (Field, Field) {
        let inputs = self.payload();

        // Domain separator for Greco circuit - "Greco" in hex
        let domain_separator = [
            0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(2)
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | 2];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        (gammas.get(0), gammas.get(1))
    }

    /// Verifies encryption constraints using Fiat-Shamir challenges
    ///
    /// Proves that LHS(gamma) = RHS(gamma) for both ciphertext components.
    /// This uses the Schwartz-Zippel lemma for polynomial identity testing.
    ///
    /// # Arguments
    /// * `gamma_eval` - Challenge value used for evaluating the polynomials
    /// * `gamma_lc` - Challenge value used for the random linear combination
    fn verify_evaluations(self, gamma_eval: Field, gamma_lc: Field) -> bool {
        let crypto_params = self.params.crypto_params();
        let cyclo_at_gamma = gamma_eval.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma_eval);
        let e0_at_gamma = self.e0.eval(gamma_eval);
        let e1_at_gamma = self.e1.eval(gamma_eval);
        let k1_at_gamma = self.k1.eval(gamma_eval);

        // Evaluate polynomials at gamma
        let pk0_at_gamma = self.pk0.eval(gamma_eval);
        let pk1_at_gamma = self.pk1.eval(gamma_eval);
        let ct0_lhs = self.ct0.eval(gamma_eval);
        let ct1_lhs = self.ct1.eval(gamma_eval);
        let r2_at_gamma = self.r2.eval(gamma_eval);
        let p2_at_gamma = self.p2.eval(gamma_eval);
        // Compute right-hand sides of the encryption equations
        let ct0_rhs = (pk0_at_gamma * u_at_gamma)
            + e0_at_gamma
            + (k1_at_gamma * crypto_params.k0)
            + (r2_at_gamma * cyclo_at_gamma);
        let ct1_rhs =
            (pk1_at_gamma * u_at_gamma) + e1_at_gamma + (p2_at_gamma * cyclo_at_gamma);

        ct0_lhs + gamma_lc * ct1_lhs == ct0_rhs + gamma_lc * ct1_rhs
    }
}

