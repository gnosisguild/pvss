use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

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
pub struct SecretKeySharesCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32> {
    params: Params<L>,
    x_coords: [Field; N_PARTIES],
    sk: Polynomial<N>,
    f: [[Polynomial<T + 1>; L]; N],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32> SecretKeySharesCircuit<N, L, N_PARTIES, T, BIT_SK> {
    pub fn new(
        params: Params<L>,
        x_coords: [Field; N_PARTIES],
        sk: Polynomial<N>,
        f: [[Polynomial<T + 1>; L]; N],
    ) -> Self {
        SecretKeySharesCircuit { params, x_coords, sk, f }
    }

    /// Main verification and computation function
    /// Returns commitment to computed shares
    pub fn verify(self) -> Field {
        // Step 1: Verify evaluation points
        self.verify_evaluation_points();

        // Step 2: Range checks (includes degree check)
        self.check_range_bounds();

        // Step 3: Verify secret consistency
        self.verify_secret_consistency();

        // Step 4: Compute shares
        let y = self.compute_shares();

        // Step 5: Commit to shares
        Self::commit_to_shares(y)
    }

    /// Verifies evaluation points are consecutive integers starting from 1
    fn verify_evaluation_points(self) {
        for party_idx in 0..N_PARTIES {
            let expected_id = (party_idx + 1) as Field;
            assert_eq(self.x_coords[party_idx], expected_id);
        }
    }

    /// Performs range checks on all private witness values
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();
        let crypto_params = self.params.crypto_params();

        // Check secret key coefficients are within bounds
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        // Check sharing polynomial coefficients
        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                let poly = self.f[coeff_idx][mod_idx];

                // Leading coefficient (index 0 = degree T): must be in [1, q_j)
                let leading_coeff = poly.coefficients[0];
                assert((leading_coeff - 1) as u64 < (q_j - 1) as u64);

                // Other coefficients (degrees 0 to T-1): in [0, q_j)
                for deg in 1..(T + 1) {
                    let coeff = poly.coefficients[deg];
                    assert(coeff as u64 < q_j as u64);
                }
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

    /// Computes shares y[i][j][k] = f[i][j](x_k) mod q_j
    fn compute_shares(self) -> [[[Field; N_PARTIES]; L]; N] {
        let crypto_params = self.params.crypto_params();
        let mut y: [[[Field; N_PARTIES]; L]; N] = [[[0; N_PARTIES]; L]; N];

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];
                let f_poly = self.f[coeff_idx][mod_idx];

                for party_idx in 0..N_PARTIES {
                    let x_k = self.x_coords[party_idx];
                    y[coeff_idx][mod_idx][party_idx] = f_poly.eval_mod(x_k, q_j);
                }
            }
        }

        y
    }

    /// Flattens y into a Vec<Field> for hashing
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

        // Domain separator - "PVSS_shares" in hex
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
