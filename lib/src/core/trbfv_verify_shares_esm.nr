use crate::math::modular_fns::reduce_mod;
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;
use dep::bignum::BigNum;
use dep::bignum::bignum::to_field;
use dep::bignum::Enclave_TrBfv_100;

/// Cryptographic parameters for SK shares circuit.
pub struct CryptographicParams<let L: u32> {
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking.
pub struct BoundParams {
    pub sk_bound: Field,
}

impl BoundParams {
    pub fn new(sk_bound: Field) -> Self {
        BoundParams { sk_bound }
    }
}

/// Complete parameters for SK shares circuit.
pub struct Params<let L: u32> {
    pub crypto: CryptographicParams<L>,
    pub bounds: BoundParams,
}

impl<let L: u32> Params<L> {
    pub fn new(qis: [Field; L], sk_bound: Field) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(sk_bound);
        Params { crypto, bounds }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    pub fn bound_params(self) -> BoundParams {
        self.bounds
    }
}

/// PVSS Circuit for TRBFV Secret Key Shamir Secret Shares
///
/// Computes shares using precomputed power vectors and commits to them.
///
/// # Generic Parameters
/// * `N` - Number of TRBFV secret key coefficients
/// * `L` - Number of CRT moduli
/// * `N_PARTIES` - Number of parties
/// * `T` - Threshold degree (polynomials have degree T)
/// * `BIT_SK` - Bit width for secret key bounds
pub struct SecretKeySharesCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_F: u32> {
    params: Params<L>,
    /// Precomputed power vectors for each party and each modulus
    /// x_powers[mod_idx][party_idx] = [1, x_k, x_k^2, ..., x_k^T] mod q_j
    x_powers: [[[Field; T + 1]; N_PARTIES]; L],
    /// Secret key polynomial
    sk: Polynomial<N>,
    /// Sharing polynomials f[coeff_idx][mod_idx]
    f: [[Polynomial<T + 1>; L]; N],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_F: u32> SecretKeySharesCircuit<N, L, N_PARTIES, T, BIT_SK, BIT_F> {
    pub fn new(
        params: Params<L>,
        x_powers: [[[Field; T + 1]; N_PARTIES]; L],
        sk: Polynomial<N>,
        f: [[Polynomial<T + 1>; L]; N],
    ) -> Self {
        SecretKeySharesCircuit { params, x_powers, sk, f }
    }

    /// Main verification and computation function
    pub fn verify(self) -> Field {
        // Step 1: Range checks (includes degree check)
        self.check_range_bounds();

        // Step 2: Verify secret consistency
        self.verify_secret_consistency();

        // Step 3: Compute shares
        let y = self.compute_shares();

        // Step 4: Commit to shares
        Self::commit_to_shares(y)
    }

    /// Performs range checks
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();
        let crypto_params = self.params.crypto_params();

        // Check sharing polynomial coefficients
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                let poly = self.f[coeff_idx][mod_idx];
                poly.range_check_2bounds::<BIT_F>(q_j, 0);
            }
        }
    }

    /// Verifies f[i][j](0) = sk[i] for all i, j
    fn verify_secret_consistency(self) {
        for coeff_idx in 0..N {
            let sk_coeff = self.sk.coefficients[coeff_idx];

            for mod_idx in 0..L {
                // Constant term is at index T (polynomial is [a_T, ..., a_1, a_0])
                let constant_term = self.f[coeff_idx][mod_idx].coefficients[T];
                assert_eq(constant_term, sk_coeff);
            }
        }
    }
    /// Computes shares using dot product with x_powers, then reduce_mod at the end
    fn compute_shares(self) -> [[[Field; N_PARTIES]; L]; N] {
        let crypto_params = self.params.crypto_params();
        let mut y: [[[Field; N_PARTIES]; L]; N] = [[[0; N_PARTIES]; L]; N];

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                //let q_j = crypto_params.qis[mod_idx];
                let q_j_bn = Enclave_TrBfv_100::from(crypto_params.qis[mod_idx]);
                let f_poly = self.f[coeff_idx][mod_idx];

                for party_idx in 0..N_PARTIES {
                    // f(x_k) = a_0 + a_1*x_k + a_2*x_k^2 + ... + a_T*x_k^T
                    // coefficients[T-deg] is the coefficient of x^deg
                    let mut sum: Field = 0;
                    //let mut sum = Enclave_TrBfv_100::from(0);

                    for deg in 0..(T + 1) {
                        // let f_poly_coeff_bn = Enclave_TrBfv_100::from(f_poly.coefficients[T - deg]);
                        // let x_power_bn =
                        //     Enclave_TrBfv_100::from(self.x_powers[mod_idx][party_idx][deg]);
                        // sum = sum + f_poly_coeff_bn * x_power_bn;
                        sum = f_poly.coefficients[T - deg] * self.x_powers[mod_idx][party_idx][deg];
                    }

                    // Reduce mod q_j at the end
                    let sum_bn = Enclave_TrBfv_100::from(sum);
                    y[coeff_idx][mod_idx][party_idx] = to_field(sum_bn.umod(q_j_bn));
                }
            }
        }

        y
    }

    /// Flattens y into Vec<Field>
    fn payload(y: [[[Field; N_PARTIES]; L]; N]) -> Vec<Field> {
        let mut inputs = Vec::new();

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                for party_idx in 0..N_PARTIES {
                    inputs.push(y[coeff_idx][mod_idx][party_idx]);
                }
            }
        }

        inputs
    }

    /// Commits to shares using SafeSponge
    fn commit_to_shares(y: [[[Field; N_PARTIES]; L]; N]) -> Field {
        let inputs = Self::payload(y);

        // Domain separator - "PVSS_shares"
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let commitment = sponge.squeeze();
        sponge.finish();

        commitment.get(0)
    }
}
