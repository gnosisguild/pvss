//! PVSS Shamir-Share Generator & Prover I/O (PolyTable serialization)
//!
//! This module prepares witness values and parameters for a PVSS circuit that
//! verifies Shamir secret sharing of a TRBFV secret key across an RNS basis,
//! and serializes them to `Prover.toml`
//!
//!
//! ## Determinism
//! Sampling is non-deterministic (uses `ThreadRng` and Rayon). Replace the RNG
//! and/or remove parallelism if you need reproducibility.

use fhe::trbfv::ShamirSecretSharing;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt};
use num_traits::Zero;
use pvw::{params::PvwParameters, PvwParametersBuilder};
use rand::rngs::ThreadRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use crate::InputValidationBounds;

/// Witness bundle passed to the prover.
///
/// Shapes with `N = degree`, `L = moduli.len()`, `P = n_parties`:
/// - `sk`: `[N]`
/// - `f`: `[N][L][t]` (constant-first, degree `t-1`)
/// - `y`, `r`: `[N][L][P]`
/// - `d`: `[N][L]`
/// - `f_randomness`: `[N][L]`
/// - `x_coords`: `[P]`
#[derive(Clone, Debug)]
pub struct SssInputs {
    pub n_parties: usize,
    pub t: usize,         // shares needed; Shamir degree = t - 1
    pub moduli: Vec<u64>, // RNS moduli (length L)
    pub k_dim: usize,
    pub degree: usize, // number of coefficients (N)

    // Witness payloads
    pub sk: Vec<BigInt>,                // [N] constant-first
    pub f: Vec<Vec<Vec<BigInt>>>,       // [N][L][t] constant-first
    pub y: Vec<Vec<Vec<BigInt>>>,       // [N][L][P]
    pub r: Vec<Vec<Vec<BigInt>>>,       // [N][L][P]
    pub d: Vec<Vec<BigInt>>,            // [N][L]
    pub f_randomness: Vec<Vec<BigInt>>, // [N][L]
    pub x_coords: Vec<BigInt>,          // [P]
}

/// Integer Euclidean division: returns `(q, r)` s.t. `a = q*n + r` and `0 ≤ r < n`.
fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}

/// Generate all witnesses for the SK-sharing circuit.
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

    // Sample a secret polynomial via PVW parameters (used here for convenience).
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

    // Public evaluation points x_k = 1..=n_parties.
    let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

    // Secret polynomial (constant-first).
    let sk_bn: Vec<BigUint> = Vec::from(&pvw_params.sample_secret_polynomial(&mut rng)?);
    let mut sk: Vec<BigInt> = sk_bn.iter().map(|x| x.to_bigint().unwrap()).collect();
    assert!(
        sk.len() >= degree,
        "PVW secret returned fewer than N coefficients"
    );
    sk.truncate(degree);

    // Allocate.
    let mut f = vec![vec![vec![BigInt::zero(); t]; l]; degree];
    let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
    let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
    let mut d = vec![vec![BigInt::zero(); l]; degree];
    let mut f_randomness = vec![vec![BigInt::zero(); l]; degree];

    // Build Shamir polynomials, shares, and quotients.
    for i in 0..degree {
        let a_i = &sk[i];

        for (j, &qj_u) in moduli.iter().enumerate() {
            let qj = BigInt::from(qj_u);

            // f_{i,j} over Z_{q_j}, degree t-1, with c0 ≡ a_i (mod q_j).
            let sss = ShamirSecretSharing::new(t - 1, n_parties, qj.clone());
            f[i][j] = sample_f_polynomial(&sss, a_i);
            let c0 = f[i][j][0].clone();

            // a_i - c0 = d_{i,j} * q_j
            let (d_ij, rem) = div_rem_euclid(&(a_i - &c0), &qj);
            debug_assert!(rem.is_zero());
            d[i][j] = d_ij;

            // Shares: evaluate f_{i,j}(x_k) and split as r*q_j + y (0 ≤ y < q_j).
            for (k_idx, xk) in x_coords.iter().enumerate() {
                let mut acc = BigInt::zero();
                for coeff in f[i][j].iter().rev() {
                    acc = xk * &acc + coeff;
                }
                let (rk, yk) = div_rem_euclid(&acc, &qj);
                r[i][j][k_idx] = rk;
                y[i][j][k_idx] = yk;
            }

            // Commitment randomness in symmetric range: [-⌊(q_j-1)/2⌋, +⌊(q_j-1)/2⌋].
            let bj = BigInt::from((qj_u - 1) / 2);
            let low = -&bj;
            let high = &bj + 1; // exclusive
            let rand_ij = rng.gen_bigint_range(&low, &high);
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

/// Serialize witnesses and params to `Prover.toml` using PolyTable wrappers.
pub fn generate_sss_toml(
    inputs: &SssInputs,
    bounds: InputValidationBounds,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    /// A generic vector of Field elements.
    #[derive(Serialize)]
    struct PolyTable {
        coefficients: Vec<String>,
    }

    /// `params.crypto`
    #[derive(Serialize)]
    struct ParamsCrypto {
        qis: PolyTable,
    }

    /// `params.bounds` (scalar bounds, as required by the circuit)
    #[derive(Serialize)]
    struct ParamsBounds {
        sk_bound: u64,
        r_lower_bound: i64,
        r_upper_bound: u64,
        randomness_bound: u64,
    }

    /// `params.circuit`
    #[derive(Serialize)]
    struct ParamsCircuit {
        n: u32,
        n_parties: u32,
        t: u32,
    }

    /// Nested `params` block
    #[derive(Serialize)]
    struct ParamsToml {
        crypto: ParamsCrypto,
        bounds: ParamsBounds,
        circuit: ParamsCircuit,
    }

    /// Top-level TOML object
    #[derive(Serialize)]
    struct ProverToml {
        // Witness payloads
        sk: PolyTable,
        f: Vec<Vec<PolyTable>>,
        y: Vec<Vec<PolyTable>>,
        r: Vec<Vec<PolyTable>>,
        d: Vec<Vec<PolyTable>>,
        f_randomness: Vec<Vec<PolyTable>>,
        x_coords: PolyTable,

        // Circuit params
        params: ParamsToml,
    }

    // --- Field canonicalization ------------------------------------------------

    fn bn254() -> BigInt {
        BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }
    let p = bn254();

    let to_fp_str = |x: &BigInt| {
        let mut r = x % &p;
        if r.sign() == Sign::Minus {
            r += &p;
        }
        r.to_string()
    };

    // Helpers to pack slices into PolyTable
    let to_polytable = |slice: &[BigInt]| PolyTable {
        coefficients: slice.iter().map(&to_fp_str).collect(),
    };
    let to_polytable_from_u64s = |slice: &[u64]| PolyTable {
        coefficients: slice.iter().map(|&q| to_fp_str(&BigInt::from(q))).collect(),
    };

    // --- Witness serialization -------------------------------------------------

    // sk: constant-first
    let sk_ser = to_polytable(&inputs.sk);

    // f: [N][L][t]
    let f_ser: Vec<Vec<PolyTable>> = inputs
        .f
        .iter()
        .map(|row| {
            row.iter()
                .map(|poly_const_first| {
                    let mut tmp = poly_const_first.clone();
                    tmp.reverse(); // highest-first for Noir
                    to_polytable(&tmp)
                })
                .collect()
        })
        .collect();

    // y: [N][L][P]
    let y_ser: Vec<Vec<PolyTable>> = inputs
        .y
        .iter()
        .map(|row| {
            row.iter()
                .map(|shares_over_parties| to_polytable(shares_over_parties))
                .collect()
        })
        .collect();

    // r: [N][L][P]
    let r_ser: Vec<Vec<PolyTable>> = inputs
        .r
        .iter()
        .map(|row| {
            row.iter()
                .map(|quotients_over_parties| to_polytable(quotients_over_parties))
                .collect()
        })
        .collect();

    // d: [N][L]
    let d_ser: Vec<Vec<PolyTable>> = inputs
        .d
        .iter()
        .map(|row| {
            row.iter()
                .map(|val| to_polytable(std::slice::from_ref(val)))
                .collect()
        })
        .collect();

    // f_randomness: [N][L]
    let f_randomness_ser: Vec<Vec<PolyTable>> = inputs
        .f_randomness
        .iter()
        .map(|row| {
            row.iter()
                .map(|val| to_polytable(std::slice::from_ref(val)))
                .collect()
        })
        .collect();

    // x_coords: [P]
    let x_coords_ser = to_polytable(&inputs.x_coords);

    // --- Build [params] --------------------------------------------------------

    // crypto.qis
    let qis_poly = to_polytable_from_u64s(&inputs.moduli);

    // scalar bounds expected by the circuit
    let r_lower_bound_scalar: i64 = *bounds.r1_low_bounds.iter().min().unwrap_or(&0i64);
    let r_upper_bound_scalar: u64 = *bounds.r1_up_bounds.iter().max().unwrap_or(&0u64);

    // randomness_bound = max_j floor((q_j - 1) / 2)
    let randomness_bound: u64 = inputs
        .moduli
        .iter()
        .copied()
        .map(|q| (q - 1) / 2)
        .max()
        .unwrap_or(0);

    let params = ParamsToml {
        crypto: ParamsCrypto { qis: qis_poly },
        bounds: ParamsBounds {
            sk_bound: bounds.sk_bound,
            r_lower_bound: r_lower_bound_scalar,
            r_upper_bound: r_upper_bound_scalar,
            randomness_bound,
        },
        circuit: ParamsCircuit {
            n: inputs.degree as u32,
            n_parties: inputs.n_parties as u32,
            t: inputs.t as u32,
        },
    };

    let obj = ProverToml {
        sk: sk_ser,
        f: f_ser,
        y: y_ser,
        r: r_ser,
        d: d_ser,
        f_randomness: f_randomness_ser,
        x_coords: x_coords_ser,
        params,
    };

    // --- Write TOML ------------------------------------------------------------

    let path = output_dir.join("Prover.toml");
    let mut f = File::create(&path)?;
    f.write_all(toml::to_string(&obj)?.as_bytes())?;
    Ok(path)
}

/// Sample a Shamir polynomial `f(x)` over `Z_q` with `f(0) ≡ secret (mod q)`.
///
/// - Degree = `sss.threshold` (`t-1`); number of coeffs = `t`.
/// - Layout: **constant-first** → `[c0, c1, ..., c_{t-1}]`.
/// - `c0` is the reduction of `secret` into `[0, q)`.
/// - Remaining coeffs are uniform in `[0, q)`.
fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
    // c0 in [0, q)
    let mut c0 = secret % &sss.prime;
    if c0.sign() == Sign::Minus {
        c0 += &sss.prime;
    }

    // Random remaining coefficients
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
