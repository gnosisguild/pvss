//! Input validation vectors for PVSS zero-knowledge proofs.
//!
//! This module defines the core data structure and computation logic for generating
//! input validation vectors used in publicly verifiable secret sharing (PVSS) protocols.
//! These vectors are used in zero-knowledge proofs to validate correct BFV encryption.

use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_math::rq::{Poly, Representation};
use itertools::izip;
use num_bigint::BigInt;
use num_traits::Zero;
use polynomial::*;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use std::sync::Arc;

use crate::utils::{to_string_1d_vec, to_string_2d_vec};

/// Represents a full set of vectors required to validate an encrypted share
/// within a PVSS scheme using zero-knowledge proofs.
#[derive(Clone, Debug)]
pub struct InputValidationVectors {
    pub ct0is: Vec<Vec<BigInt>>,
    pub ct1is: Vec<Vec<BigInt>>,
    pub r1is: Vec<Vec<BigInt>>,
    pub r2is: Vec<Vec<BigInt>>,
    pub a: Vec<BigInt>,
    pub sk: Vec<BigInt>,
    pub e: Vec<BigInt>,
}

impl InputValidationVectors {
    /// Initializes an empty vector structure with appropriate sizes.
    pub fn new(num_moduli: usize, degree: usize) -> Self {
        InputValidationVectors {
            ct0is: vec![vec![BigInt::zero(); degree]; num_moduli],
            ct1is: vec![vec![BigInt::zero(); degree]; num_moduli],
            r1is: vec![vec![BigInt::zero(); 2 * (degree - 1) + 1]; num_moduli],
            r2is: vec![vec![BigInt::zero(); degree - 1]; num_moduli],
            a: vec![BigInt::zero(); degree],
            sk: vec![BigInt::zero(); degree],
            e: vec![BigInt::zero(); degree],
        }
    }

    /// Applies modular reduction of all coefficients in the structure using the ZKP modulus `p`.
    pub fn standard_form(&self, p: &BigInt) -> Self {
        InputValidationVectors {
            ct0is: reduce_coefficients_2d(&self.ct0is, p),
            ct1is: reduce_coefficients_2d(&self.ct1is, p),
            r1is: reduce_coefficients_2d(&self.r1is, p),
            r2is: reduce_coefficients_2d(&self.r2is, p),
            a: reduce_coefficients(&self.a, p),
            sk: reduce_coefficients(&self.sk, p),
            e: reduce_coefficients(&self.e, p),
        }
    }

    /// Serializes the validation vectors to JSON.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "a": to_string_1d_vec(&self.a),
            "sk": to_string_1d_vec(&self.sk),
            "e": to_string_1d_vec(&self.e),
            "r2is": to_string_2d_vec(&self.r2is),
            "r1is": to_string_2d_vec(&self.r1is),
            "ct0is": to_string_2d_vec(&self.ct0is),
            "ct1is": to_string_2d_vec(&self.ct1is),
        })
    }

    /// Verifies that all vectors conform to the expected sizes for the given parameters.
    pub fn check_correct_lengths(&self, num_moduli: usize, degree: usize) -> bool {
        let check_2d_lengths = |vec: &Vec<Vec<BigInt>>, outer: usize, inner: usize| {
            vec.len() == outer && vec.iter().all(|v| v.len() == inner)
        };

        let check_1d_lengths = |vec: &Vec<BigInt>, len: usize| vec.len() == len;

        // Use all to combine all checks into a single statement
        [
            // 2D vector checks
            check_2d_lengths(&self.ct0is, num_moduli, degree),
            check_2d_lengths(&self.ct1is, num_moduli, degree),
            check_2d_lengths(&self.r1is, num_moduli, 2 * (degree - 1) + 1),
            check_2d_lengths(&self.r2is, num_moduli, degree - 1),
            // 1D vector checks
            check_1d_lengths(&self.a, degree),
            check_1d_lengths(&self.sk, degree),
            check_1d_lengths(&self.e, degree),
        ]
        .iter()
        .all(|&check| check)
    }

    /// Computes the full input validation vector structure for PVSS ZK proofs.
    ///
    /// The logic verifies that the ciphertext corresponds to a valid encryption
    /// and reconstructs its derivation components, such as error polynomials and randomness.
    pub fn compute(
        sk_rns: &Poly,
        e_rns: &Poly,
        a: &Poly,
        ct: &Ciphertext,
        params: &Arc<BfvParameters>,
    ) -> Result<InputValidationVectors, Box<dyn std::error::Error>> {
        // Get context, plaintext modulus, and degree
        let ctx = params.ctx_at_level(0)?;
        let n: u64 = ctx.degree as u64;

        // Extract single vectors of u and e1 as Vec<BigInt>, center and reverse
        let mut a_copy = a.clone();
        let mut sk_rns_copy = sk_rns.clone();
        let mut e_rns_copy = e_rns.clone();

        a_copy.change_representation(Representation::PowerBasis);
        sk_rns_copy.change_representation(Representation::PowerBasis);
        e_rns_copy.change_representation(Representation::PowerBasis);

        let a: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    a_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        let sk: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    sk_rns_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        let e: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    e_rns_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        // Extract and convert ciphertext and plaintext polynomials
        let mut ct0 = ct.c[0].clone();
        let mut ct1 = -ct.c[1].clone();
        ct0.change_representation(Representation::PowerBasis);
        ct1.change_representation(Representation::PowerBasis);

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];

        cyclo[0] = BigInt::from(1u64); // x^N term
        cyclo[n as usize] = BigInt::from(1u64); // x^0 term

        // Initialize matrices to store results
        let num_moduli = ctx.moduli().len();
        let mut res = InputValidationVectors::new(num_moduli, n as usize);

        let ct0_coeffs = ct0.coefficients();
        let ct1_coeffs = ct1.coefficients();

        let ct0_coeffs_rows = ct0_coeffs.rows();
        let ct1_coeffs_rows = ct1_coeffs.rows();

        // Perform the main computation logic
        let results: Vec<(usize, Vec<BigInt>, Vec<BigInt>, Vec<BigInt>, Vec<BigInt>)> =
            izip!(ctx.moduli_operators(), ct0_coeffs_rows, ct1_coeffs_rows,)
                .enumerate()
                .par_bridge()
                .map(|(i, (qi, ct0_coeffs, ct1_coeffs))| {
                    // --------------------------------------------------- ct0i ---------------------------------------------------

                    // Convert to vectors of bigint, center, and reverse order.
                    let mut ct0i: Vec<BigInt> =
                        ct0_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                    let mut ct1i: Vec<BigInt> =
                        ct1_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();

                    let qi_bigint = BigInt::from(qi.modulus());

                    reduce_and_center_coefficients_mut(&mut ct0i, &qi_bigint);
                    reduce_and_center_coefficients_mut(&mut ct1i, &qi_bigint);

                    // Calcualte ct0i_hat = pk1 * sk + e
                    let ct0i_hat = {
                        let pk0i_poly = Polynomial::new(a.clone());
                        let sk_poly = Polynomial::new(sk.clone());
                        let pk0i_times_u = pk0i_poly.mul(&sk_poly);
                        assert_eq!((pk0i_times_u.coefficients().len() as u64) - 1, 2 * (n - 1));
                        let e_poly = Polynomial::new(e.clone());
                        pk0i_times_u.add(&e_poly).coefficients().to_vec()
                    };
                    assert_eq!((ct0i_hat.len() as u64) - 1, 2 * (n - 1));

                    // Check whether ct0i_hat mod R_qi (the ring) is equal to ct0i
                    let mut ct0i_hat_mod_rqi = ct0i_hat.clone();
                    reduce_in_ring(&mut ct0i_hat_mod_rqi, &cyclo, &qi_bigint);
                    assert_eq!(&ct0i, &ct0i_hat_mod_rqi);

                    // Compute r2i numerator = ct0i - ct0i_hat and reduce/center the polynomial
                    let ct0i_poly = Polynomial::new(ct0i.clone());
                    let ct0i_hat_poly = Polynomial::new(ct0i_hat.clone());
                    let ct0i_minus_ct0i_hat = ct0i_poly.sub(&ct0i_hat_poly).coefficients().to_vec();
                    assert_eq!((ct0i_minus_ct0i_hat.len() as u64) - 1, 2 * (n - 1));
                    let mut ct0i_minus_ct0i_hat_mod_zqi = ct0i_minus_ct0i_hat.clone();
                    reduce_and_center_coefficients_mut(
                        &mut ct0i_minus_ct0i_hat_mod_zqi,
                        &qi_bigint,
                    );

                    // Compute r2i as the quotient of numerator divided by the cyclotomic polynomial
                    // to produce: (ct0i - ct0i_hat) / (x^N + 1) mod Z_qi. Remainder should be empty.
                    let ct0i_minus_ct0i_hat_poly =
                        Polynomial::new(ct0i_minus_ct0i_hat_mod_zqi.clone());
                    let cyclo_poly = Polynomial::new(cyclo.clone());
                    let (r2i_poly, r2i_rem_poly) =
                        ct0i_minus_ct0i_hat_poly.div(&cyclo_poly).unwrap();
                    let r2i = r2i_poly.coefficients().to_vec();
                    let r2i_rem = r2i_rem_poly.coefficients().to_vec();
                    assert!(r2i_rem.iter().all(|x| x.is_zero()));
                    assert_eq!((r2i.len() as u64) - 1, n - 2); // Order(r2i) = N - 2

                    // Assert that (ct0i - ct0i_hat) = (r2i * cyclo) mod Z_qi
                    let r2i_poly = Polynomial::new(r2i.clone());
                    let r2i_times_cyclo = r2i_poly.mul(&cyclo_poly).coefficients().to_vec();
                    let mut r2i_times_cyclo_mod_zqi = r2i_times_cyclo.clone();
                    reduce_and_center_coefficients_mut(&mut r2i_times_cyclo_mod_zqi, &qi_bigint);
                    assert_eq!(&ct0i_minus_ct0i_hat_mod_zqi, &r2i_times_cyclo_mod_zqi);
                    assert_eq!((r2i_times_cyclo.len() as u64) - 1, 2 * (n - 1));

                    // Calculate r1i = (ct0i - ct0i_hat - r2i * cyclo) / qi mod Z_p. Remainder should be empty.
                    let ct0i_minus_ct0i_hat_poly = Polynomial::new(ct0i_minus_ct0i_hat.clone());
                    let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                    let r1i_num = ct0i_minus_ct0i_hat_poly
                        .sub(&r2i_times_cyclo_poly)
                        .coefficients()
                        .to_vec();
                    assert_eq!((r1i_num.len() as u64) - 1, 2 * (n - 1));

                    let r1i_num_poly = Polynomial::new(r1i_num.clone());
                    let qi_poly = Polynomial::new(vec![qi_bigint.clone()]);
                    let (r1i_poly, r1i_rem_poly) = r1i_num_poly.div(&qi_poly).unwrap();
                    let r1i = r1i_poly.coefficients().to_vec();
                    let r1i_rem = r1i_rem_poly.coefficients().to_vec();
                    assert!(r1i_rem.iter().all(|x| x.is_zero()));
                    assert_eq!((r1i.len() as u64) - 1, 2 * (n - 1)); // Order(r1i) = 2*(N-1)
                    let r1i_poly_check = Polynomial::new(r1i.clone());
                    assert_eq!(
                        &r1i_num,
                        &r1i_poly_check.mul(&qi_poly).coefficients().to_vec()
                    );

                    // Assert that ct0i = ct0i_hat + r1i * qi + r2i * cyclo mod Z_p
                    let r1i_poly = Polynomial::new(r1i.clone());
                    let r1i_times_qi = r1i_poly.scalar_mul(&qi_bigint).coefficients().to_vec();
                    let ct0i_hat_poly = Polynomial::new(ct0i_hat.clone());
                    let r1i_times_qi_poly = Polynomial::new(r1i_times_qi.clone());
                    let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                    let mut ct0i_calculated = ct0i_hat_poly
                        .add(&r1i_times_qi_poly)
                        .add(&r2i_times_cyclo_poly)
                        .coefficients()
                        .to_vec();

                    while ct0i_calculated.len() > 0 && ct0i_calculated[0].is_zero() {
                        ct0i_calculated.remove(0);
                    }

                    assert_eq!(&ct0i, &ct0i_calculated);

                    // ct1 = a = pk1
                    assert_eq!(&ct1i, &a);
                    (i, r2i, r1i, ct0i, ct1i)
                })
                .collect();

        // Merge results into the `res` structure after parallel execution
        for (i, r2i, r1i, ct0i, ct1i) in results.into_iter() {
            res.r2is[i] = r2i;
            res.r1is[i] = r1i;
            res.ct0is[i] = ct0i;
            res.ct1is[i] = ct1i;
        }

        // Set final result vectors
        res.sk = sk;
        res.e = e;
        res.a = a;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::{BfvParametersBuilder, PublicKey, SecretKey};
    use num_bigint::BigInt;
    use rand::{rngs::StdRng, SeedableRng};
    use std::str::FromStr;

    fn setup_test_params() -> (Arc<BfvParameters>, SecretKey, PublicKey) {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[18014398492704769])
            .build_arc()
            .unwrap();

        let mut rng = StdRng::seed_from_u64(0);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        (params, sk, pk)
    }

    #[test]
    fn test_vector_lengths() {
        let vecs = InputValidationVectors::new(1, 2048);
        assert!(vecs.check_correct_lengths(1, 2048));
        assert!(!vecs.check_correct_lengths(2, 2048));
        assert!(!vecs.check_correct_lengths(1, 1024));
    }

    #[test]
    fn test_standard_form() {
        let vecs = InputValidationVectors::new(1, 2048);
        let p = BigInt::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let std_form = vecs.standard_form(&p);

        // Check that all vectors are properly reduced
        assert!(std_form.sk.iter().all(|x| x < &p));
        assert!(std_form.e.iter().all(|x| x < &p));
    }

    #[test]
    fn test_vector_computation() {
        let (params, sk, _pk) = setup_test_params();

        // Use extended encryption to get the polynomial data
        let mut rng = StdRng::seed_from_u64(0);
        let (ct, a, sk_rns, e_rns) = PublicKey::new_extended(&sk, &mut rng).unwrap();

        let vecs = InputValidationVectors::compute(&sk_rns, &e_rns, &a, &ct, &params).unwrap();

        // Check dimensions
        assert!(vecs.check_correct_lengths(1, params.degree()));
    }

    #[test]
    fn test_vector_json_format() {
        let vecs = InputValidationVectors::new(1, 4);
        let json = vecs.to_json();

        // Check all required fields are present
        let required_fields = ["r2is", "r1is", "ct0is", "ct1is", "a", "sk", "e"];

        for field in required_fields.iter() {
            assert!(json.get(field).is_some(), "Missing field: {}", field);
        }
    }
}
