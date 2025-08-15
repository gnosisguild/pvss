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

#[derive(Clone, Debug)]
pub struct SssInputs {
    pub n_parties: usize,
    pub t: usize,         // threshold (poly degree = T-1)
    pub moduli: Vec<u64>, // QIS (length L)
    pub k_dim: usize,
    pub degree: usize, // number of coefficients minus 1 (N)
    // Witness payloads
    pub sk: Vec<BigInt>,          // [N+1] secret polynomial coefficients
    pub f: Vec<Vec<Vec<BigInt>>>, // [N+1][L] each polynomial has T coeffs over Z_{q_j}
    pub y: Vec<Vec<Vec<BigInt>>>, // [N+1][L][N_PARTIES]
    pub r: Vec<Vec<Vec<BigInt>>>, // [N+1][L][N_PARTIES]
    pub d: Vec<Vec<BigInt>>,      // [N+1][L]
    pub x_coords: Vec<BigInt>,    // [N_PARTIES]
}

pub fn compute_sss_inputs(
    n_parties: usize,
    k_dim: usize,
    degree: usize, // N (sk has N+1 coeffs)
    moduli: &[u64],
    t: usize, // threshold (poly degree = T-1)
    mut rng: ThreadRng,
) -> Result<SssInputs, Box<dyn std::error::Error>> {
    assert!(t >= 1, "T must be ≥ 1");
    assert!(t <= n_parties, "threshold T must be ≤ number of parties");

    // Build PVW params only to sample a secret polynomial conveniently
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

    // Standard Shamir x-locations: 1..n
    let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

    // Sample a secret polynomial (length N+1)
    let sk_bn: Vec<BigUint> = Vec::from(&pvw_params.sample_secret_polynomial(&mut rng)?);
    let sk: Vec<BigInt> = sk_bn.iter().map(|x| x.to_bigint().unwrap()).collect();

    // Allocate outputs
    let mut f = vec![vec![vec![BigInt::zero(); t]; l]; degree + 1];
    let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree + 1];
    let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree + 1];
    let mut d = vec![vec![BigInt::zero(); l]; degree + 1];

    // For each coefficient a_i and each limb q_j:
    for i in 0..degree {
        let a_i = &sk[i]; // integer coefficient (may be negative)
        for (j, &qj_u) in moduli.iter().enumerate() {
            let qj = BigInt::from(qj_u);

            // Make degree-(t-1) Shamir polynomial over Z_{qj} with f(0) = a_i mod qj
            let sss = ShamirSecretSharing::new(t - 1, n_parties, qj.clone());
            f[i][j] = sample_f_polynomial(&sss, a_i);

            // Euclidean quotient for a_i / qj so that a_i = qj * d + (a_i mod qj)
            let (q_ij, _) = div_rem_euclid(a_i, &qj);
            d[i][j] = q_ij;

            // Shares: evaluate as integers, then Euclidean div/rem by qj
            for (k_idx, xk) in x_coords.iter().enumerate() {
                let mut acc = BigInt::zero();
                for c in f[i][j].iter().rev() {
                    acc = xk * &acc + c;
                }
                let (rk, yk) = div_rem_euclid(&acc, &qj);
                y[i][j][k_idx] = yk;
                r[i][j][k_idx] = rk;
            }
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
        x_coords,
    })
}

// ---------------- TOML writer ----------------
pub fn generate_sss_toml(
    inputs: &SssInputs,
    output_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[derive(Serialize)]
    struct PolyTable {
        coefficients: Vec<String>,
    }

    #[derive(Serialize)]
    struct ProverToml {
        sk: PolyTable,
        f: Vec<Vec<PolyTable>>,
        y: Vec<Vec<PolyTable>>,
        r: Vec<Vec<PolyTable>>,
        d: Vec<Vec<String>>,
        x_coords: PolyTable,
    }

    fn bn254() -> BigInt {
        BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }
    let p = bn254();

    // Normalize into [0,p) and to string
    let to_fp_str = |x: &BigInt| {
        let mut r = x % &p;
        if r.sign() == Sign::Minus {
            r += &p;
        }
        r.to_string()
    };

    // Vec<BigInt> -> PolyTable (each entry reduced mod p)
    let to_poly = |v: &Vec<BigInt>| -> PolyTable {
        PolyTable {
            coefficients: v.iter().map(&to_fp_str).collect(),
        }
    };

    // f: Vec<Vec<Polynomial>> -> Vec<Vec<PolyTable>>
    let f_ser: Vec<Vec<PolyTable>> = inputs
        .f
        .iter()
        .map(|row| row.iter().map(to_poly).collect())
        .collect();

    // y, r: Vec<Vec<Vec<BigInt>>> -> Vec<Vec<PolyTable>>
    let y_ser: Vec<Vec<PolyTable>> = inputs
        .y
        .iter()
        .map(|row| row.iter().map(to_poly).collect())
        .collect();

    let r_ser: Vec<Vec<PolyTable>> = inputs
        .r
        .iter()
        .map(|row| row.iter().map(to_poly).collect())
        .collect();

    // d: Vec<Vec<BigInt>> -> Vec<Vec<String>> (nested arrays, compact)
    let d_ser: Vec<Vec<String>> = inputs
        .d
        .iter()
        .map(|row| row.iter().map(&to_fp_str).collect())
        .collect();

    // x_coords
    let x_coords_ser = to_poly(&inputs.x_coords);

    let obj = ProverToml {
        sk: to_poly(&inputs.sk),
        f: f_ser,
        y: y_ser,
        r: r_ser,
        d: d_ser,
        x_coords: x_coords_ser,
    };

    let path = output_dir.join("Prover.toml");
    let mut f = File::create(&path)?;
    f.write_all(toml::to_string(&obj)?.as_bytes())?;
    Ok(path)
}

// Build degree-(t-1) polynomial over Z_{prime} with f(0) = secret mod prime
fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
    // constant term = a_i mod qj in [0, qj)
    let mut c0 = secret % &sss.prime;
    if c0.sign() == Sign::Minus {
        c0 += &sss.prime;
    }

    // random coeffs uniform in [0, qj)
    let low = BigInt::from(0);
    let high = sss.prime.clone(); // half-open: [0, prime)
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

// Euclidean division: a = q*n + r with 0 <= r < n (assumes n > 0)
fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}
