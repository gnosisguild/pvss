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
    pub sk: Vec<BigInt>, // [N+1] secret polynomial coefficients (constant-first)
    pub f: Vec<Vec<Vec<BigInt>>>, // [N][L] each polynomial has T coeffs over Z_{q_j} (constant-first)
    pub y: Vec<Vec<Vec<BigInt>>>, // [N][L][N_PARTIES]
    pub r: Vec<Vec<Vec<BigInt>>>, // [N][L][N_PARTIES]
    pub d: Vec<Vec<BigInt>>,      // [N][L]
    pub x_coords: Vec<BigInt>,    // [N_PARTIES]
}

// Euclidean division: a = q*n + r with 0 <= r < n
fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}

pub fn compute_sss_inputs(
    n_parties: usize,
    k_dim: usize,
    degree: usize, // N (sk has N+1 coeffs; we output i=0..N-1 to match Noir loop 0..N)
    moduli: &[u64],
    t: usize, // threshold (poly degree = T-1)
    mut rng: ThreadRng,
) -> Result<SssInputs, Box<dyn std::error::Error>> {
    assert!(t >= 1, "T must be ≥ 1");
    assert!(t <= n_parties, "threshold T must be ≤ number of parties");

    // use PVW just to sample a secret polynomial
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

    // x = 1..n
    let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

    // secret poly (length N+1), constant-first
    let sk_bn: Vec<BigUint> = Vec::from(&pvw_params.sample_secret_polynomial(&mut rng)?);
    let sk: Vec<BigInt> = sk_bn.iter().map(|x| x.to_bigint().unwrap()).collect();

    // Allocate outputs
    let mut f = vec![vec![vec![BigInt::zero(); t]; l]; degree + 1];
    let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree + 1];
    let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree + 1];
    let mut d = vec![vec![BigInt::zero(); l]; degree + 1];

    for i in 0..degree {
        let a_i = &sk[i];
        for (j, &qj_u) in moduli.iter().enumerate() {
            let qj = BigInt::from(qj_u);

            // degree-(t-1) Shamir poly over Z_qj with c0 = a_i (mod qj) in [0,qj)
            let sss = ShamirSecretSharing::new(t - 1, n_parties, qj.clone());
            f[i][j] = sample_f_polynomial(&sss, a_i); // constant-first: [c0, c1, ..., c_{t-1}]
            let c0 = f[i][j][0].clone();

            // d_{i,j} from a_i - c0 = d * qj
            let (d_ij, rem) = div_rem_euclid(&(a_i - &c0), &qj);
            debug_assert!(rem.is_zero());
            d[i][j] = d_ij;

            // shares via integer Horner (constant-first -> iterate rev)
            for (k_idx, xk) in x_coords.iter().enumerate() {
                let mut acc = BigInt::zero();
                for coeff in f[i][j].iter().rev() {
                    acc = xk * &acc + coeff;
                }
                let (rk, yk) = div_rem_euclid(&acc, &qj); // acc = rk * qj + yk
                r[i][j][k_idx] = rk;
                y[i][j][k_idx] = yk;
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
        y: Vec<Vec<Vec<String>>>,
        r: Vec<Vec<Vec<String>>>,
        d: Vec<Vec<String>>,
        x_coords: Vec<String>,
    }

    fn bn254() -> BigInt {
        BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }
    let p = bn254();

    // canonical field rep in [0,p)
    let to_fp_str = |x: &BigInt| {
        let mut r = x % &p;
        if r.sign() == Sign::Minus {
            r += &p;
        }
        r.to_string()
    };

    // sk stays constant-first (so sk.coefficients[i] == a_i in Noir)
    let to_poly_const_first = |v: &Vec<BigInt>| PolyTable {
        coefficients: v.iter().map(&to_fp_str).collect(),
    };

    // f must be highest-first to match Noir's eval (coeff[0] is highest degree)
    let to_poly_highest_first = |v: &Vec<BigInt>| PolyTable {
        coefficients: v.iter().rev().map(&to_fp_str).collect(),
    };

    let f_ser: Vec<Vec<PolyTable>> = inputs
        .f
        .iter()
        .map(|row| row.iter().map(to_poly_highest_first).collect())
        .collect();

    let y_ser: Vec<Vec<Vec<String>>> = inputs
        .y
        .iter()
        .map(|row| {
            row.iter()
                .map(|col| col.iter().map(&to_fp_str).collect())
                .collect()
        })
        .collect();

    let r_ser: Vec<Vec<Vec<String>>> = inputs
        .r
        .iter()
        .map(|row| {
            row.iter()
                .map(|col| col.iter().map(&to_fp_str).collect())
                .collect()
        })
        .collect();

    let d_ser: Vec<Vec<String>> = inputs
        .d
        .iter()
        .map(|row| row.iter().map(&to_fp_str).collect())
        .collect();

    let x_coords_ser: Vec<String> = inputs.x_coords.iter().map(&to_fp_str).collect();

    let obj = ProverToml {
        sk: to_poly_const_first(&inputs.sk),
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

// Build degree-(t-1) polynomial over Z_q with f(0) = secret mod q
fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
    // c0 = a_i mod q in [0,q)
    let mut c0 = secret % &sss.prime;
    if c0.sign() == Sign::Minus {
        c0 += &sss.prime;
    }
    // random coeffs in [0,q)
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
    coefficients.push(c0); // constant-first
    coefficients.extend(random_coefficients);
    coefficients
}
