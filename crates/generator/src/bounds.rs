//! Bounds calculation and constraint checking for Greco zero-knowledge proofs.
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

/// The `InputValidationBounds` struct holds the bounds for various vectors and polynomials used in the input validation process.
/// These bounds are calculated from a set of BFV encryption parameters and represent limits on the values of different fields
/// to ensure that the inputs remain within valid ranges during operations.
#[derive(Clone, Debug)]
pub struct InputValidationBounds {
    // Original fields for backward compatibility
    pub sk: BigInt,
    pub e: BigInt,
    pub a: BigInt,
    pub r1_low: Vec<BigInt>,
    pub r1_up: Vec<BigInt>,
    pub r2: Vec<BigInt>,

    // Additional fields for Noir generation to match old format
    pub moduli: Vec<u64>,
    pub sk_bound: u64,
    pub e_bound: u64,
    pub a_bound: u64,
    pub r1_low_bounds: Vec<i64>,
    pub r1_up_bounds: Vec<u64>,
    pub r2_bounds: Vec<u64>,
    pub q_mod_t: BigInt,
    pub size: usize,
    pub tag: BigUint,
}

impl InputValidationBounds {
    /// Checks the constraints of the input validation vectors against the bounds stored in `InputValidationBounds`.
    ///
    /// # Arguments
    ///
    /// * `vecs` - A reference to `InputValidationVectors`, which contains the vectors to be validated.
    /// * `p` - The prime modulus used in the encryption scheme.
    ///
    /// This function checks whether the coefficients of the vectors `u`, `e0`, `e1`, `k1`, and others are within
    /// the specified ranges, using both centered and standard range checks. It asserts that the vectors stay within
    /// these predefined bounds.
    pub fn check_constraints(&self, vecs: &InputValidationVectors, p: &BigInt) {
        let vecs_std = vecs.standard_form(p);

        // constraint. The coefficients of u, e0, e1 should be in the range [-⌈6σ⌋, ⌈6σ⌋]
        // where ⌈6σ⌋ is the upper bound of the discrete Gaussian distribution
        assert!(range_check_centered(&vecs.sk, &-&self.sk, &self.sk));
        assert!(range_check_centered(&vecs.e, &-&self.e, &self.e));
        assert!(range_check_standard(&vecs_std.sk, &self.sk, &p));
        assert!(range_check_standard(&vecs_std.e, &self.e, &p));

        // constraint. The coefficients of pk0i and pk1i should be in range [-(qi-1)/2 , (qi-1)/2]
        assert!(range_check_centered(&vecs.a, &-&self.a, &self.a));
        assert!(range_check_standard(&vecs_std.a, &self.a, &p));

        // Perform asserts for polynomials depending on each qi
        for i in 0..self.r2.len() {
            // constraint. The coefficients of ct0i and ct1i should be in the range [-(qi-1)/2, (qi-1)/2]
            assert!(range_check_centered(
                &vecs.ct0is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));
            assert!(range_check_centered(
                &vecs.ct1is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));

            // constraint. The coefficients of r2i should be in the range [-(qi-1)/2, (qi-1)/2]
            assert!(range_check_centered(
                &vecs.r2is[i],
                &-&self.r2[i],
                &self.r2[i]
            ));
            assert!(range_check_standard(&vecs_std.r2is[i], &self.r2[i], &p));

            // constraint. The coefficients of (ct0i - ct0i_hat - r2i * cyclo) / qi = r1i should be in the range
            // $[
            //      \frac{ \frac{-(t - 1)}{2} \cdot |K_{0,i}| - ((N \cdot B +2) \cdot \frac{q_i - 1}{2} + B )}{q_i},
            //      \frac{ \frac{t - 1}{2} \cdot |K_{0,i}| +  (N \cdot B+2) \cdot \frac{q_i - 1}{2} + B }{q_i}
            // ]$
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

    /// Compute the input validation bounds from a set of BFV encryption parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - A reference to the BFV parameters.
    /// * `level` - The encryption level, which determines the number of moduli used.
    ///
    /// # Returns
    ///
    /// A new `InputValidationBounds` instance containing the bounds for vectors and polynomials
    /// based on the BFV parameters and the specified level.
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> Result<InputValidationBounds, Box<dyn std::error::Error>> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let t = BigInt::from(params.plaintext());
        let ctx = params.ctx_at_level(level)?;

        let half_modulus = params.plaintext() / 2;
        let q_mod_t = reduce_and_center(
            &BigInt::from(ctx.modulus().clone()),
            &BigInt::from(params.plaintext()),
            &BigInt::from(half_modulus),
        );
        //let q_mod_t = BigUint::from(ctx.modulus() % params.plaintext());

        // Note: the secret key in fhe.rs is sampled from a discrete gaussian distribution
        // rather than a ternary distribution as in bfv.py.
        let gauss_bound = BigInt::from(
            f64::ceil(6_f64 * f64::sqrt(params.variance() as f64))
                .to_i64()
                .ok_or_else(|| "Failed to convert variance to i64".to_string())?,
        );
        let sk_bound = gauss_bound.clone();
        let e_bound = gauss_bound.clone();

        //Note we have two different variables for lower bound and upper bound, as in the case
        //where the plaintext modulus is even, the lower bound cannot be calculated by just
        //negating the upper bound. For instance, if t = 8, then the lower bound will be -4 and the
        //upper bound will be 3
        let ptxt_up_bound = (t.clone() - BigInt::from(1)) / BigInt::from(2);
        let ptxt_low_bound = if (t.clone() % BigInt::from(2)) == BigInt::from(1) {
            (-&(t.clone() - BigInt::from(1))) / BigInt::from(2)
        } else {
            ((-&(t.clone() - BigInt::from(1))) / BigInt::from(2)) - BigInt::from(1)
        };

        // Calculate qi-based bounds
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds: Vec<BigInt> = vec![BigInt::from(0); num_moduli];
        let mut r1_low_bounds: Vec<BigInt> = vec![BigInt::from(0); num_moduli];
        let mut r1_up_bounds: Vec<BigInt> = vec![BigInt::from(0); num_moduli];

        // Collect moduli and k0is for Noir generation
        let mut moduli: Vec<u64> = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            moduli.push(qi.modulus());

            // Calculate the k0qi for the bounds (these are also constant wrt BFV params)
            let k0qi = BigInt::from(
                qi.inv(qi.neg(params.plaintext()))
                    .ok_or_else(|| "Failed to calculate modulus inverse for k0qi".to_string())?,
            );

            r2_bounds[i] = qi_bound.clone();

            r1_low_bounds[i] = (&ptxt_low_bound * num_bigint::BigInt::abs(&k0qi)
                - &((&n * &gauss_bound + 2) * &qi_bound + &gauss_bound))
                / &qi_bigint;
            r1_up_bounds[i] = (&ptxt_up_bound * num_bigint::BigInt::abs(&k0qi)
                + ((&n * &gauss_bound + 2) * &qi_bound + &gauss_bound))
                / &qi_bigint;
        }

        // A bound and R2 bound are same
        let a_bound = r2_bounds[0].clone();

        // Convert BigInt bounds to u64/i64 for Noir generation
        let a_bound_u64 = r2_bounds[0].to_u64().unwrap_or(0);
        let sk_bound_u64 = sk_bound.to_u64().unwrap_or(19);
        let e_bound_u64 = e_bound.to_u64().unwrap_or(19);

        let r1_low_bounds_i64: Vec<i64> = r1_low_bounds
            .iter()
            .map(|b| b.to_i64().unwrap_or(0))
            .collect();
        let r1_up_bounds_u64: Vec<u64> = r1_up_bounds
            .iter()
            .map(|b| b.to_u64().unwrap_or(0))
            .collect();
        let r2_bounds_u64: Vec<u64> = r2_bounds.iter().map(|b| b.to_u64().unwrap_or(0)).collect();

        // Compute TAG using proper hashing
        let mut hasher = Hasher::new();
        hasher.update(params.degree().to_le_bytes().as_slice());
        hasher.update(a_bound_u64.clone().to_le_bytes().as_slice());
        hasher.update(
            &ctx.moduli()
                .iter()
                .flat_map(|num| num.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let _domain_separator = BigUint::from_bytes_le(hasher.finalize().as_bytes());

        // Using r2_bounds length as a reference to calculate dimension of the polynomials (const L)
        let size = (10 * params.degree() - 4) * r2_bounds.len() + 4 * params.degree();
        let io_pattern = [
            BigUint::from_usize(size).unwrap(),
            BigUint::from_usize(2 * r2_bounds.len()).unwrap(),
        ]
        .map(|x| x.to_bytes_le());
        hasher.update(io_pattern[0].as_slice());
        hasher.update(io_pattern[1].as_slice());

        let tag = BigUint::from_bytes_le(hasher.finalize().as_bytes()) % ctx.modulus().clone();

        Ok(InputValidationBounds {
            sk: sk_bound.clone(),
            e: e_bound.clone(),
            a: a_bound.clone(),
            r1_low: r1_low_bounds,
            r1_up: r1_up_bounds,
            r2: r2_bounds,

            // Additional fields for Noir generation
            moduli: moduli.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigInt;
    use std::str::FromStr;

    fn setup_test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[18014398492704769])
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_bounds_computation_with_different_levels() {
        let params = setup_test_params();

        // Test at level 0
        let bounds_l0 = InputValidationBounds::compute(&params, 0).unwrap();
        assert_eq!(bounds_l0.moduli.len(), 1);

        // Test that computing at level 1 returns an error since we only have one modulus
        let bounds_l1 = InputValidationBounds::compute(&params, 1);
        assert!(bounds_l1.is_err());
    }

    #[test]
    fn test_tag_computation_deterministic() {
        let params = setup_test_params();

        // Compute bounds twice
        let bounds1 = InputValidationBounds::compute(&params, 0).unwrap();
        let bounds2 = InputValidationBounds::compute(&params, 0).unwrap();

        // TAG should be deterministic
        assert_eq!(bounds1.tag, bounds2.tag);
    }

    #[test]
    fn test_bounds_validation() {
        let params = setup_test_params();
        let bounds = InputValidationBounds::compute(&params, 0).unwrap();

        // Create test vectors within bounds
        let mut vecs = InputValidationVectors::new(1, 2048);

        // Fill with values within bounds
        vecs.sk[0] = bounds.sk.clone() - BigInt::from(1);
        vecs.e[0] = bounds.e.clone() - BigInt::from(1);

        // Test with ZKP modulus
        let p = BigInt::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        // Should not panic
        bounds.check_constraints(&vecs, &p);
    }

    #[test]
    #[should_panic]
    fn test_bounds_validation_failure() {
        let params = setup_test_params();
        let bounds = InputValidationBounds::compute(&params, 0).unwrap();

        // Create test vectors outside bounds
        let mut vecs = InputValidationVectors::new(1, 2048);

        // Fill with values outside bounds
        vecs.sk[0] = bounds.sk.clone() + BigInt::from(1); // Exceeds bound

        // Test with ZKP modulus
        let p = BigInt::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();

        // Should panic
        bounds.check_constraints(&vecs, &p);
    }

    #[test]
    fn test_bounds_conversion() {
        let params = setup_test_params();
        let bounds = InputValidationBounds::compute(&params, 0).unwrap();

        // Test that u64/i64 conversions match BigInt values
        assert_eq!(bounds.sk_bound, bounds.sk.to_u64().unwrap());
        assert_eq!(bounds.e_bound, bounds.e.to_u64().unwrap());
    }
}
