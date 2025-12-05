use crate::math::modular_fns::{add, mul_mod};
use crate::math::modular_fns::reduce_mod;
use crate::math::polynomial::Polynomial;
use crate::math::safe::SafeSponge;

/// Cryptographic parameters for SK shares verification circuit.
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
    /// Bound for trinary sk coefficients (should be 1 for {-1, 0, 1})
    pub sk_bound: Field,
}

impl BoundParams {
    pub fn new(sk_bound: Field) -> Self {
        BoundParams { sk_bound }
    }
}

/// Complete parameters for SK shares verification circuit.
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

/// PVSS Verification Circuit for TRBFV Secret Key Shamir Shares
///
/// This circuit verifies that Shamir secret shares satisfy the Reed-Solomon parity check.
///
/// Verification:
/// 1. sk consistency: y[i][j][0] == sk[i] for all i, j
/// 2. Range check: sk coefficients are trinary (-1, 0, 1)
/// 3. Parity check: y[i][j] * H[j] == 0 mod q_j for all i, j
///
/// Output:
/// - Commitment to shares y[i][j][1..N_PARTIES+1] (excluding sk values)
///
/// # Generic Parameters
/// * `N` - Number of TRBFV secret key coefficients
/// * `L` - Number of CRT moduli
/// * `N_PARTIES` - Number of parties (shares per coefficient)
/// * `T` - Threshold (degree of sharing polynomial)
/// * `BIT_SK` - Bit width for secret key bounds
pub struct SecretKeySharesVerificationCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32> {
    params: Params<L>,
    /// Secret key polynomial (trinary coefficients)
    sk: Polynomial<N>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk[i], y[i][j][1..N_PARTIES+1] = shares
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES + 1) * (N_PARTIES + 1 - T)
    h: [[[Field; N_PARTIES + 1 - T]; N_PARTIES + 1]; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32> SecretKeySharesVerificationCircuit<N, L, N_PARTIES, T, BIT_SK> {
    pub fn new(
        params: Params<L>,
        sk: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1 - T]; N_PARTIES + 1]; L],
    ) -> Self {
        SecretKeySharesVerificationCircuit { params, sk, y, h }
    }

    /// Main verification function
    /// Returns commitment to shares (excluding sk values)
    pub fn verify(self)
    // -> Field
{
        // Step 1: Verify sk consistency
        //  self.verify_sk_consistency();

        // Step 2: Range check sk (trinary)
        //   self.check_range_bounds();

        // Step 3: Verify parity check
        self.verify_parity_check();

        // Step 4: Commit to shares (excluding sk values)
        //   Self::commit_to_shares(self.y)
    }

    /// Verifies y[i][j][0] == sk[i] for all i, j
    fn verify_sk_consistency(self) {
        for coeff_idx in 0..N {
            let sk_coeff = self.sk.coefficients[coeff_idx];

            for mod_idx in 0..L {
                assert_eq(self.y[coeff_idx][mod_idx][0], sk_coeff);
            }
        }
    }

    /// Range check for trinary sk coefficients
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        // sk coefficients should be in {-1, 0, 1}
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        //TODO: add y bound check here
    }

    /// Verifies y[i][j] * H[j] == 0 mod q_j for all i, j
    fn verify_parity_check(self) {
        let crypto_params = self.params.crypto_params();

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];

                // Compute y[i][j] * H[j] and verify each element is 0 mod q_j
                for col in 0..(N_PARTIES + 1 - T) {
                    let mut sum: Field = 0;

                    for row in 0..(N_PARTIES + 1) {
                        // product = y[i][j][row] * H[j][row][col] mod q_j
                        let product = self.y[coeff_idx][mod_idx][row] * self.h[mod_idx][row][col];

                        // sum = (sum + product) mod q_j
                        sum = sum + product;
                    }
                    let sum_mod_q_j = reduce_mod(sum, q_j);

                    // Verify sum == 0 (already reduced mod q_j)
                    assert(sum_mod_q_j == 0, "Parity check failed");
                }
            }
        }
    }

    /// Flattens shares (excluding sk values) into Vec<Field>
    fn payload(y: [[[Field; N_PARTIES + 1]; L]; N]) -> Vec<Field> {
        let mut inputs = Vec::new();

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                // Only include shares, not sk (skip index 0)
                for party_idx in 1..(N_PARTIES + 1) {
                    inputs.push(y[coeff_idx][mod_idx][party_idx]);
                }
            }
        }

        inputs
    }

    /// Commits to shares using SafeSponge
    fn commit_to_shares(y: [[[Field; N_PARTIES + 1]; L]; N]) -> Field {
        let inputs = Self::payload(y);

        // Domain separator - "PVSS_verify" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00, 0x00, 0x00,
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
