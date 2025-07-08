//! Input Bounds Calculation and Constraint Checking for PVSS
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.

use blake3::Hasher;
use fhe::bfv::BfvParameters;
use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, Signed, ToPrimitive};
use polynomial::{
    range_check_centered, range_check_standard, range_check_standard_2bounds, reduce_and_center,
};
use std::sync::Arc;

use crate::vectors::InputValidationVectors;

/// Stores computed upper/lower bounds for key input vectors used in ZK validation.
/// Also carries precomputed values (e.g. tag, q mod t) for downstream constraint checks or serialization.
#[derive(Clone, Debug)]
pub struct InputValidationBounds {
    /// Symmetric bound for secret key coefficients: `[-sk, sk]`
    pub sk: BigInt,
    /// Symmetric bound for error distribution: `[-e, e]`
    pub e: BigInt,
    /// Bound for public key polynomial `a`: `[-a, a]`
    pub a: BigInt,
    /// Lower bound vector for `r1` polynomials
    pub r1_low: Vec<BigInt>,
    /// Upper bound vector for `r1` polynomials
    pub r1_up: Vec<BigInt>,
    /// Symmetric bound vector for `r2`, `pk0`, and `pk1`
    pub r2: Vec<BigInt>,

    // Auxiliary fields for circuit generation / serialization
    /// RNS moduli used in BFV at the given level
    pub moduli: Vec<u64>,
    /// Truncated sk bound for Noir-compatible serialization
    pub sk_bound: u64,
    /// Truncated e bound
    pub e_bound: u64,
    /// Truncated a bound
    pub a_bound: u64,
    /// Signed r1 lower bounds (for centered checks)
    pub r1_low_bounds: Vec<i64>,
    /// Unsigned r1 upper bounds
    pub r1_up_bounds: Vec<u64>,
    /// Unsigned r2 bounds
    pub r2_bounds: Vec<u64>,

    /// Precomputed `q mod t`, reduced and centered
    pub q_mod_t: BigInt,
    /// Total expected size of the input vector arrays
    pub size: usize,
    /// Hash-based tag binding circuit configuration to constraint system
    pub tag: BigUint,
}

impl InputValidationBounds {
    /// Checks whether the provided vectors are within the bounds defined by this struct.
    ///
    /// This is used in unit testing or proof system sanity checks to ensure
    /// constraint satisfaction before circuit invocation.
    pub fn check_constraints(&self, vecs: &InputValidationVectors, p: &BigInt) {
        let vecs_std = vecs.standard_form(p);

        // Check that secret key and error vectors are within symmetric bounds
        assert!(range_check_centered(&vecs.sk, &-&self.sk, &self.sk));
        assert!(range_check_centered(&vecs.e, &-&self.e, &self.e));
        assert!(range_check_standard(&vecs_std.sk, &self.sk, &p));
        assert!(range_check_standard(&vecs_std.e, &self.e, &p));

        // Check that public key polynomial a is in the correct centered range
        assert!(range_check_centered(&vecs.a, &-&self.a, &self.a));
        assert!(range_check_standard(&vecs_std.a, &self.a, &p));

        // Check each modulus-dependent bound for ciphertext and randomness polynomials
        for i in 0..self.r2.len() {
            // Ciphertext terms pk0i and pk1i must be in symmetric range per modulus
            assert!(range_check_centered(
                &vecs.pk0is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));
            assert!(range_check_centered(
                &vecs.pk1is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));

            // r2i randomness component must be within the same range as a and ciphertext
            assert!(range_check_centered(
                &vecs.r2is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));
            assert!(range_check_standard(&vecs_std.r2is[i], &self.r2[i], &p));

            // r1i is a derived polynomial and requires asymmetric bounds (different low/high)
            assert!(range_check_centered(
                &vecs.r1is[i],
                &self.r1_low[i],
                &self.r1_up[i]
            ));
            assert!(range_check_standard_2bounds(
                &vecs_std.r1is[i],
                &self.r1_low[i],
                &self.r1_up[i],
                &p
            ));
        }
    }

    /// Computes bounds for a given encryption parameter set and level.
    ///
    /// These bounds are used to validate polynomial coefficient magnitudes in ZK circuits.
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let n = BigInt::from(params.degree());
        let t = BigInt::from(params.plaintext());
        let ctx = params.ctx_at_level(level)?;

        // Compute centered value of q mod t to capture wraparound behavior
        let q_mod_t = reduce_and_center(
            &BigInt::from(ctx.modulus().clone()),
            &t,
            &(BigInt::from(params.plaintext() / 2)),
        );

        // Approximate bounds from discrete Gaussian sampling: ceil(6 * sqrt(variance))
        let gauss_bound = BigInt::from(
            f64::ceil(6.0 * f64::sqrt(params.variance() as f64))
                .to_i64()
                .ok_or("Failed to convert variance to i64")?,
        );

        let sk_bound = gauss_bound.clone();
        let e_bound = gauss_bound.clone();

        // Plaintext bounds differ if modulus is even
        let ptxt_up_bound = (t.clone() - 1u32) / 2u32;
        let ptxt_low_bound = if &t % 2u32 == BigInt::from(1) {
            (-(&t - 1u32)) / 2u32
        } else {
            (-(&t - 1u32)) / 2u32 - 1u32
        };

        // Calculate qi-based bounds
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_low_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_up_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());

            // Compute k0qi = inv(-t) mod qi for normalization
            let k0qi = BigInt::from(
                qi.inv(qi.neg(params.plaintext()))
                    .ok_or("Failed to compute k0qi")?,
            );

            r2_bounds[i] = qi_bound.clone();

            // Compute asymmetric range for r1 bounds per modulus
            r1_low_bounds[i] = (&ptxt_low_bound * k0qi.abs()
                - ((&n * &gauss_bound + 2u32) * &qi_bound + &gauss_bound))
                / &qi_bigint;
            r1_up_bounds[i] = (&ptxt_up_bound * k0qi.abs()
                + ((&n * &gauss_bound + 2u32) * &qi_bound + &gauss_bound))
                / &qi_bigint;
        }

        // a and r2 have the same bound semantics
        let a_bound = r2_bounds[0].clone();

        // Convert bounds to primitive types for serialization into Noir or test fixtures
        let a_bound_u64 = a_bound.to_u64().unwrap_or(0);
        let sk_bound_u64 = sk_bound.to_u64().unwrap_or(19);
        let e_bound_u64 = e_bound.to_u64().unwrap_or(19);

        let r1_low_bounds_i64 = r1_low_bounds
            .iter()
            .map(|b| b.to_i64().unwrap_or(0))
            .collect();
        let r1_up_bounds_u64 = r1_up_bounds
            .iter()
            .map(|b| b.to_u64().unwrap_or(0))
            .collect();
        let r2_bounds_u64 = r2_bounds.iter().map(|b| b.to_u64().unwrap_or(0)).collect();

        // Compute a hash-based tag to bind parameters to the circuit shape
        let mut hasher = Hasher::new();
        hasher.update(&params.degree().to_le_bytes());
        hasher.update(&a_bound_u64.to_le_bytes());
        hasher.update(
            &ctx.moduli()
                .iter()
                .flat_map(|m| m.to_le_bytes())
                .collect::<Vec<u8>>(),
        );

        let _domain_separator = BigUint::from_bytes_le(hasher.finalize().as_bytes());

        // Using r2_bounds length as a reference to calculate size (const L = r2_bounds.len())
        let size = (10 * params.degree() - 4) * r2_bounds.len() + 4 * params.degree();
        hasher.update(&BigUint::from_usize(size).unwrap().to_bytes_le());
        hasher.update(
            &BigUint::from_usize(2 * r2_bounds.len())
                .unwrap()
                .to_bytes_le(),
        );

        let tag = BigUint::from_bytes_le(hasher.finalize().as_bytes()) % ctx.modulus();

        Ok(Self {
            sk: sk_bound,
            e: e_bound,
            a: a_bound,
            r1_low: r1_low_bounds,
            r1_up: r1_up_bounds,
            r2: r2_bounds,
            moduli,
            sk_bound: sk_bound_u64,
            e_bound: e_bound_u64,
            a_bound: a_bound_u64,
            r1_low_bounds: r1_low_bounds_i64,
            r1_up_bounds: r1_up_bounds_u64,
            r2_bounds: r2_bounds_u64,
            q_mod_t,
            size,
            tag,
        })
    }
}
