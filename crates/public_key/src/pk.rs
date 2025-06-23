use num_bigint::BigInt;
use num_traits::Zero;
use polynomial::Polynomial;
use rand::distributions::Uniform;
use rand::prelude::*;

const N: usize = 8; // Example degree (replace with your real cyclotomic degree, e.g. 1024)
const Q: i64 = 1 << 15; // Example modulus q (should match your system parameter)
const SIGMA: f64 = 3.2;

fn gaussian_bound(sigma: f64) -> i64 {
    (sigma * 6.0).ceil() as i64
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

fn keygen<R: Rng>(rng: &mut R, a: &Polynomial, q: &BigInt, sigma: f64) -> (Polynomial, Polynomial) {
    let degree = a.degree();
    let bound = gaussian_bound(sigma);

    let sk = sample_small_secret(rng, degree);
    let e_ek = sample_error(rng, degree, bound);

    let a_times_sk = a.mul(&sk);
    let minus_a_times_sk = a_times_sk.neg();
    let b = minus_a_times_sk.add(&e_ek);
    let b_mod_q = b.reduce_and_center(q);

    (sk, b_mod_q)
}
