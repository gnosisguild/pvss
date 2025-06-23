use num_bigint::BigInt;
use num_traits::FromPrimitive;
use polynomial::Polynomial;
use rand::distributions::Uniform;
use rand::prelude::*;

const SIGMA: f64 = 3.2;

// TODO: should this return 19, -19 all the time?
fn gaussian_bound() -> i64 {
    (SIGMA * 6.0).ceil() as i64
}

fn sample_small_secret<R: Rng>(rng: &mut R, degree: usize) -> Polynomial {
    let dist = Uniform::new_inclusive(-1, 1);
    let coeffs: Vec<BigInt> = (0..=degree)
        .map(|_| BigInt::from(dist.sample(rng)))
        .collect();
    Polynomial::new(coeffs)
}

fn sample_error<R: Rng>(rng: &mut R, degree: usize, bound: i64) -> Polynomial {
    let dist = Uniform::new_inclusive(-bound, bound);
    let coeffs: Vec<BigInt> = (0..=degree)
        .map(|_| BigInt::from(dist.sample(rng)))
        .collect();
    Polynomial::new(coeffs)
}

fn keygen<R: Rng>(rng: &mut R, a: &Polynomial) -> (Polynomial, (Polynomial, Polynomial)) {
    let degree = a.degree();
    let bound = gaussian_bound();

    let sk = sample_small_secret(rng, degree);
    let e_ek = sample_error(rng, degree, bound);

    let a_times_sk = a.mul(&sk);
    let minus_a_times_sk = a_times_sk.neg();
    let b = minus_a_times_sk.add(&e_ek);

    let q = BigInt::from_i128(16777216).unwrap();
    let b_mod_q = b.reduce_and_center(&q);
    let a_mod_q = a.reduce_and_center(&q);

    (sk, (b_mod_q, a_mod_q))
}
