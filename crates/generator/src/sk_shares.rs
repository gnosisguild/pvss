//! PVSS Shamir-Share Generator & Prover I/O (TOML layout exactly as requested)
//!
//! This module prepares witness values and parameters for a PVSS circuit that
//! verifies Shamir secret sharing of a TRBFV secret key across an RNS basis,
//! and serializes them to `Prover.toml`.

use fhe::trbfv::ShamirSecretSharing;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt};
use num_traits::{ToPrimitive, Zero};
use pvw::{params::PvwParameters, PvwParametersBuilder};
use rand::rngs::ThreadRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct SssInputs {
    pub n_parties: usize,
    pub t: usize,         // shares needed; Shamir degree = t - 1
    pub moduli: Vec<u64>, // RNS moduli (length L)
    pub k_dim: usize,
    pub degree: usize, // number of coefficients (N)

    // Witness payloads
    pub sk: Vec<BigInt>,                // [N] constant-first (one coeff per slot)
    pub f: Vec<Vec<Vec<BigInt>>>,       // [N][L][t] constant-first
    pub y: Vec<Vec<Vec<BigInt>>>,       // [N][L][P]
    pub r: Vec<Vec<Vec<BigInt>>>,       // [N][L][P]
    pub d: Vec<Vec<BigInt>>,            // [N][L]
    pub f_randomness: Vec<Vec<BigInt>>, // [N][L]
    pub x_coords: Vec<BigInt>,          // [P]
}

// ---------- helpers ----------

fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}

fn geometric_sum_u128(base: usize, terms: usize) -> u128 {
    if terms == 0 {
        return 0;
    }
    let mut s: u128 = 0;
    let mut pow: u128 = 1;
    for _ in 0..terms {
        s = s.saturating_add(pow);
        pow = pow.saturating_mul(base as u128);
    }
    s
}

/// r-bounds:
/// - r_lower_bound = 0
/// - r_upper_bound = (1 + n + ... + n^{t-1}) - 1 (clamped to u64)
fn derive_sss_r_bounds(n_parties: usize, t: usize) -> (i64, u64) {
    let s = geometric_sum_u128(n_parties, t);
    let upper = s.saturating_sub(1);
    (
        0_i64,
        if upper > u64::MAX as u128 {
            u64::MAX
        } else {
            upper as u64
        },
    )
}

/// sk_bound = max |sk[i]| (clamped to u64)
fn derive_sk_bound_from_sk(sk: &[BigInt]) -> u64 {
    sk.iter()
        .map(|c| {
            let abs = if c.sign() == Sign::Minus {
                -c
            } else {
                c.clone()
            };
            abs.to_u128().unwrap_or(u128::MAX)
        })
        .max()
        .map(|m| {
            if m > u64::MAX as u128 {
                u64::MAX
            } else {
                m as u64
            }
        })
        .unwrap_or(0)
}

/// BN254 modulus for canonical field encoding as strings.
fn bn254_modulus() -> BigInt {
    BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}

/// Reduce into canonical field rep in [0, p) and stringify.
fn to_fp_str(p: &BigInt, x: &BigInt) -> String {
    let mut r = x % p;
    if r.sign() == Sign::Minus {
        r += p;
    }
    r.to_string()
}

// ---------- witness generation ----------

pub fn compute_sss_inputs(
    n_parties: usize,
    k_dim: usize,
    degree: usize,
    moduli: &[u64],
    t: usize,
    mut rng: ThreadRng,
) -> Result<SssInputs, Box<dyn std::error::Error>> {
    assert!(t >= 1, "T must be ≥ 1");
    assert!(t <= n_parties, "threshold T must be ≤ number of parties");

    let (variance, bound1, bound2) =
        PvwParameters::suggest_correct_parameters(n_parties, k_dim, degree, moduli)
            .unwrap_or((1, 100, 200));

    let pvw_params = PvwParametersBuilder::new()
        .set_parties(n_parties)
        .set_dimension(k_dim)
        .set_l(degree)
        .set_moduli(moduli)
        .set_secret_variance(variance)
        .set_error_bounds_u32(bound1, bound2)
        .build_arc()?;

    let moduli = moduli.to_vec();
    let l = moduli.len();

    if let Some(min_q) = moduli.iter().copied().min() {
        assert!(
            (n_parties as u64) < min_q,
            "N_PARTIES must be < min(QIS) for distinct x-coordinates"
        );
    }

    let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

    let sk_bn: Vec<BigUint> = Vec::from(&pvw_params.sample_secret_polynomial(&mut rng)?);
    let mut sk: Vec<BigInt> = sk_bn.iter().map(|x| x.to_bigint().unwrap()).collect();
    assert!(
        sk.len() >= degree,
        "PVW secret returned fewer than N coefficients"
    );
    sk.truncate(degree);

    let mut f = vec![vec![vec![BigInt::zero(); t]; l]; degree];
    let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
    let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
    let mut d = vec![vec![BigInt::zero(); l]; degree];
    let mut f_randomness = vec![vec![BigInt::zero(); l]; degree];

    for i in 0..degree {
        let a_i = &sk[i];
        for (j, &qj_u) in moduli.iter().enumerate() {
            let qj = BigInt::from(qj_u);

            // Shamir poly over Z_qj, degree t-1, with c0 ≡ a_i (mod q_j)
            let sss = ShamirSecretSharing::new(t - 1, n_parties, qj.clone());
            f[i][j] = sample_f_polynomial(&sss, a_i);
            let c0 = f[i][j][0].clone();

            // a_i - c0 = d_{i,j} * q_j
            let (d_ij, rem) = div_rem_euclid(&(a_i - &c0), &qj);
            debug_assert!(rem.is_zero());
            d[i][j] = d_ij;

            // shares: f(x_k) = r*q_j + y, with 0 ≤ y < q_j
            for (k_idx, xk) in x_coords.iter().enumerate() {
                let mut acc = BigInt::zero();
                for coeff in f[i][j].iter().rev() {
                    acc = xk * &acc + coeff;
                }
                let (rk, yk) = div_rem_euclid(&acc, &qj);
                r[i][j][k_idx] = rk;
                y[i][j][k_idx] = yk;
            }

            // commitment randomness in symmetric range
            let bj = BigInt::from((qj_u - 1) / 2);
            let rand_ij = rng.gen_bigint_range(&-bj.clone(), &(&bj + 1)); // upper bound exclusive
            f_randomness[i][j] = rand_ij;
        }
    }

    Ok(SssInputs {
        sk,
        n_parties,
        t,
        moduli,
        k_dim,
        degree,
        f,
        y,
        r,
        d,
        f_randomness,
        x_coords,
    })
}

pub fn generate_sss_toml(
    inputs: &SssInputs,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct CryptoToml {
        qis: Vec<String>,
    }

    #[derive(Serialize)]
    struct BoundsToml {
        sk_bound: String,
        r_lower_bound: String,
        r_upper_bound: String,
        randomness_bound: String,
    }

    #[derive(Serialize)]
    struct CircuitToml {
        n: String,
        n_parties: String,
        t: String,
    }

    #[derive(Serialize)]
    struct ParamsToml {
        crypto: CryptoToml,
        bounds: BoundsToml,
        circuit: CircuitToml,
    }

    #[derive(Serialize)]
    struct PolyToml {
        coefficients: Vec<String>,
    } // highest-first for f; flat for sk

    #[derive(Serialize)]
    struct ProverToml {
        // Witness payloads (all strings)
        f: Vec<Vec<PolyToml>>,          // [N][L] of { coefficients = [..] }
        y: Vec<Vec<Vec<String>>>,       // [N][L][P]
        r: Vec<Vec<Vec<String>>>,       // [N][L][P]
        d: Vec<Vec<String>>,            // [N][L]
        f_randomness: Vec<Vec<String>>, // [N][L]
        x_coords: Vec<String>,          // [P]

        // Params
        params: ParamsToml,

        // Top-level [sk] table
        sk: PolyToml,
    }

    let p = bn254_modulus();

    // field encoders
    let enc = |x: &BigInt| to_fp_str(&p, x);
    let enc_usize = |q: usize| enc(&BigInt::from(q as u64));

    // ----- witnesses -----

    // sk → [sk] coefficients = [..]
    let sk_ser = PolyToml {
        coefficients: inputs.sk.iter().map(&enc).collect(),
    };

    // f: constant-first → highest-first, then wrap into inline table per (i,j)
    let f_ser: Vec<Vec<PolyToml>> = inputs
        .f
        .iter()
        .map(|row| {
            row.iter()
                .map(|poly_const_first| {
                    let mut tmp = poly_const_first.clone();
                    tmp.reverse();
                    PolyToml {
                        coefficients: tmp.iter().map(&enc).collect::<Vec<String>>(),
                    }
                })
                .collect::<Vec<PolyToml>>()
        })
        .collect();

    // y, r
    let y_ser: Vec<Vec<Vec<String>>> = inputs
        .y
        .iter()
        .map(|row| {
            row.iter()
                .map(|col| col.iter().map(&enc).collect())
                .collect()
        })
        .collect();

    let r_ser: Vec<Vec<Vec<String>>> = inputs
        .r
        .iter()
        .map(|row| {
            row.iter()
                .map(|col| col.iter().map(&enc).collect())
                .collect()
        })
        .collect();

    // d
    let d_ser: Vec<Vec<String>> = inputs
        .d
        .iter()
        .map(|row| row.iter().map(&enc).collect())
        .collect();

    // f_randomness
    let f_randomness_ser: Vec<Vec<String>> = inputs
        .f_randomness
        .iter()
        .map(|row| row.iter().map(&enc).collect())
        .collect();

    // x_coords
    let x_coords_ser: Vec<String> = inputs.x_coords.iter().map(&enc).collect();

    // ----- params -----

    // crypto.qis (as field strings)
    let qis_ser: Vec<String> = inputs
        .moduli
        .iter()
        .copied()
        .map(|q: u64| enc(&BigInt::from(q)))
        .collect();

    // r-bounds from n_parties, t
    let (r_lower_bound_i64, r_upper_bound_u64) = derive_sss_r_bounds(inputs.n_parties, inputs.t);

    // sk_bound from actual sk
    let sk_bound_u64 = derive_sk_bound_from_sk(&inputs.sk);

    // randomness_bound = max_j floor((q_j-1)/2)
    let randomness_bound_u64: u64 = inputs
        .moduli
        .iter()
        .copied()
        .map(|q| (q - 1) / 2)
        .max()
        .unwrap_or(0);

    let params = ParamsToml {
        crypto: CryptoToml { qis: qis_ser },
        bounds: BoundsToml {
            sk_bound: enc(&BigInt::from(sk_bound_u64)),
            r_lower_bound: enc(&BigInt::from(r_lower_bound_i64)),
            r_upper_bound: enc(&BigInt::from(r_upper_bound_u64)),
            randomness_bound: enc(&BigInt::from(randomness_bound_u64)),
        },
        circuit: CircuitToml {
            n: enc_usize(inputs.degree),
            n_parties: enc_usize(inputs.n_parties),
            t: enc_usize(inputs.t),
        },
    };

    // ----- write -----

    let obj = ProverToml {
        f: f_ser,
        y: y_ser,
        r: r_ser,
        d: d_ser,
        f_randomness: f_randomness_ser,
        x_coords: x_coords_ser,
        params,
        sk: sk_ser,
    };

    let path = output_dir.join("Prover.toml");
    let mut f = File::create(&path)?;
    f.write_all(toml::to_string(&obj)?.as_bytes())?;
    Ok(path)
}

// Build polynomial over Z_q with f(0) = secret mod q (constant-first).
fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
    // c0 in [0, q)
    let mut c0 = secret % &sss.prime;
    if c0.sign() == Sign::Minus {
        c0 += &sss.prime;
    }

    // random coeffs in [0, q)
    let low = BigInt::from(0);
    let high = sss.prime.clone();
    let random_coefficients: Vec<BigInt> = (0..sss.threshold)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            rng.gen_bigint_range(&low, &high)
        })
        .collect();

    let mut coefficients = Vec::with_capacity(1 + sss.threshold);
    coefficients.push(c0);
    coefficients.extend(random_coefficients);
    coefficients
}
