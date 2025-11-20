use crate::math::modular_fns::{reduce_mod, sub};
use crate::math::polynomial::{flatten, Polynomial};
use crate::math::safe::SafeSponge;
use dep::bignum::BigNum;
use dep::bignum::bignum::to_field;
use dep::bignum::Enclave_Bfv_100;
use std::ops::Div;

/// Cryptographic parameters for honest ciphertext aggregation and decryption circuit
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

/// Bound parameters for range checking
pub struct BoundParams<let L: u32> {
    /// Bound for secret key sum s
    pub s_bound: Field,
    /// Bounds for u_i polynomials (per-basis decryption results)
    pub u_i_bounds: [Field; L],
    /// Bound for global u polynomial
    pub u_global_bound: Field,
    /// Bounds for r_1 polynomials (modulus quotients)
    pub r1_bounds: [Field; L],
    /// Bounds for r_2 polynomials (cyclotomic quotients)
    pub r2_bounds: [Field; L],
    /// Global delta value: delta = floor(q/t) where q = product of all q_i
    pub delta: Field,
    /// Global half-delta value: delta_half = floor(delta / 2)
    pub delta_half: Field,
}

impl<let L: u32> BoundParams<L> {
    pub fn new(
        s_bound: Field,
        u_i_bounds: [Field; L],
        u_global_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
        delta: Field,
        delta_half: Field,
    ) -> Self {
        BoundParams { s_bound, u_i_bounds, u_global_bound, r1_bounds, r2_bounds, delta, delta_half }
    }
}

/// Complete parameters for the circuit
pub struct Params<let N: u32, let H: u32, let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams<L>,
}

impl<let N: u32, let H: u32, let L: u32> Params<N, H, L> {
    pub fn new(
        qis: [Field; L],
        plaintext_modulus: Field,
        s_bound: Field,
        u_i_bounds: [Field; L],
        u_global_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
        delta: Field,
        delta_half: Field,
    ) -> Self {
        let crypto = CryptographicParams::new(qis, plaintext_modulus);
        let bounds = BoundParams::new(
            s_bound,
            u_i_bounds,
            u_global_bound,
            r1_bounds,
            r2_bounds,
            delta,
            delta_half,
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

/// Honest Ciphertext Aggregation and Decryption Circuit
///
/// This circuit verifies:
/// 1. H honest ciphertexts sum correctly to sum_ciphertext
/// 2. Decryption formula: u_i = c_0i + c_1i * s + r_2_i * (X^N + 1) + r_1_i * q_i
/// 3. CRT reconstruction: u_i + quotient_i * q_i = u_global
/// 4. Correct decoding: |u_global - delta * m| < delta/2
///
/// # Generic Parameters
/// * `N` - Number of polynomial coefficients
/// * `H` - Number of honest party ciphertexts
/// * `L` - Number of CRT bases
/// * `BIT_CT` - Bit width for ciphertext coefficients
/// * `BIT_S` - Bit width for secret key sum
/// * `BIT_U` - Bit width for u_i and u_global coefficients
/// * `BIT_R1` - Bit width for r_1 quotients
/// * `BIT_R2` - Bit width for r_2 quotients
/// * `BIT_NOISE` - Bit width for noise bound checking
pub struct HonestCiphertextAggregationDecryption<let N: u32, let H: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_NOISE: u32> {
    /// Circuit parameters
    params: Params<N, H, L>,

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

impl<let N: u32, let H: u32, let L: u32, let BIT_CT: u32, let BIT_S: u32, let BIT_U: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_NOISE: u32> HonestCiphertextAggregationDecryption<N, H, L, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_NOISE> {
    /// Creates a new circuit instance
    pub fn new(
        params: Params<N, H, L>,
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
        HonestCiphertextAggregationDecryption {
            params,
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
        self.verify_decoding();
    }

    /// Verifies that H honest ciphertexts sum correctly to sum_ciphertext
    /// For each basis l and each coefficient k:
    ///   sum(honest_c0[i][l][k]) mod q_l == sum_c0[l][k]
    ///   sum(honest_c1[i][l][k]) mod q_l == sum_c1[l][k]
    fn verify_ciphertext_summation(self) {
        let crypto_params = self.params.crypto_params();

        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            // Verify c_0 summation
            for coeff_idx in 0..N {
                let mut sum = 0 as Field;
                for party_idx in 0..H {
                    sum = sum + self.honest_c0[party_idx][basis_idx].coefficients[coeff_idx];
                }
                let sum_reduced = reduce_mod(sum, q_l);
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
                let sum_reduced = reduce_mod(sum, q_l);
                assert(
                    sum_reduced == self.sum_c1[basis_idx].coefficients[coeff_idx],
                    "Ciphertext c_1 summation verification failed",
                );
            }
        }
    }

    /// Performs range checks on all secret witness values
    ///
    /// CRITICAL: This includes bounds on u_i and u_global to prevent attacks
    /// where malicious provers provide out-of-range decryption results
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        // Check secret key sum is within bounds
        for basis_idx in 0..L {
            self.s[basis_idx].range_check_2bounds::<BIT_S>(
                bound_params.s_bound,
                bound_params.s_bound,
            );
        }

        // Check per-basis u_i are within bounds (CRITICAL for security)
        for basis_idx in 0..L {
            self.u_i[basis_idx].range_check_2bounds::<BIT_U>(
                bound_params.u_i_bounds[basis_idx],
                bound_params.u_i_bounds[basis_idx],
            );
        }

        // Check global u is within bounds (CRITICAL for security)
        self.u_global.range_check_2bounds::<BIT_U>(
            bound_params.u_global_bound,
            bound_params.u_global_bound,
        );

        // Check quotient polynomials are within bounds
        for basis_idx in 0..L {
            self.r_1[basis_idx].range_check_2bounds::<BIT_R1>(
                bound_params.r1_bounds[basis_idx],
                bound_params.r1_bounds[basis_idx],
            );
            self.r_2[basis_idx].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[basis_idx],
                bound_params.r2_bounds[basis_idx],
            );
        }
    }

    /// Flattens all witness data for Fiat-Shamir challenge generation
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

    /// Generates Fiat-Shamir challenge value
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

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas.get(0)
    }

    /// Verifies the decryption formula for a specific CRT basis using Schwartz-Zippel
    ///
    /// Checks: u_i(gamma) = c_0i(gamma) + c_1i(gamma) * s(gamma) + r_2_i(gamma) * (gamma^N + 1) + r_1_i(gamma) * q_i
    fn verify_decryption_formula(self, basis_idx: u32, gamma: Field) {
        let crypto_params = self.params.crypto_params();

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
            + r_1_at_gamma * crypto_params.qis[basis_idx];

        // Evaluate the claimed u_i at gamma
        let computed_u = self.u_i[basis_idx].eval(gamma);

        // Enforce equality
        assert_eq(computed_u, expected_u);
    }

    /// Verifies CRT reconstruction: u_i + quotient_i * q_i = u_global
    fn verify_crt_reconstruction(self) {
        let crypto_params = self.params.crypto_params();

        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

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
    fn verify_decoding(self) {
        let crypto_params = self.params.crypto_params();
        let bound_params = self.params.bound_params();
        let delta_m = self.message.mul_scalar(bound_params.delta);

        let mut q_modulus = 1;
        for l in 0..L {
            q_modulus *= crypto_params.qis[l];
        }

        let q_half = q_modulus as u128 / 2;
        let mut noise_centered = [0 as Field; N];

        for coeff_idx in 0..N {
            let noise = sub(
                self.u_global.coefficients[coeff_idx],
                delta_m.coefficients[coeff_idx],
                q_modulus,
            );
            // Center and take absolute value in BigNum (must be done here!)
            noise_centered[coeff_idx] = if noise as u128 > q_half {
                q_modulus - noise
            } else {
                noise
            };
        }
        // Range check
        let noise_poly = Polynomial::new(noise_centered);
        noise_poly.range_check_2bounds::<BIT_NOISE>(
            bound_params.delta_half,
            bound_params.delta_half,
        );
    }
    //Use this function if BFV_modulus > 128 bits
    // fn verify_decoding(self) {
    //     let bound_params = self.params.bound_params();
    //     let delta_m = self.message.mul_scalar(bound_params.delta);

    //     let q_bn = Enclave_Bfv_100::modulus();
    //     let q_half_bn = q_bn.udiv(Enclave_Bfv_100::from(2));
        
    //     let mut noise_centered_fields = [0 as Field; N];
        
    //     for coeff_idx in 0..N {
    //         let u_global_bn = Enclave_Bfv_100::from(self.u_global.coefficients[coeff_idx]);
    //         let delta_m_bn = Enclave_Bfv_100::from(delta_m.coefficients[coeff_idx]);
    //         let noise_bn = u_global_bn - delta_m_bn;
        
    //         // Center and take absolute value in BigNum (must be done here!)
    //         let noise_centered_bn = if noise_bn > q_half_bn {
    //             q_bn - noise_bn
    //         } else {
    //             noise_bn
    //         };
        
    //         // Convert absolute value to Field
    //         let limbs = noise_centered_bn.get_limbs();
    //         noise_centered_fields[coeff_idx] =
    //             (limbs[0] as Field) + (limbs[1] as Field) * (2 as Field).pow_32(120);
    //     }

    //     // Range check
    //     let noise_poly = Polynomial::new(noise_centered_fields);
    //     noise_poly.range_check_2bounds::<BIT_NOISE>(
    //         bound_params.delta_half,
    //         bound_params.delta_half,
    //     );
    // }
}
