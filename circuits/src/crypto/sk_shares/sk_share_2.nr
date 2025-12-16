use crate::math::modular_fns::reduce_mod;
use crate::math::polynomial::{flatten, Polynomial};
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
/// Verification:
/// 1. sk commitment: verify sk hashes to expected_sk_commitment
/// 2. sk consistency: y[i][j][0] == sk[i] for all i, j
/// 3. Range check: sk coefficients are trinary (-1, 0, 1)
/// 4. Range check: shares are in [0, q_j)
/// 5. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
///
/// Output:
/// - L * N_PARTIES commitments: [[Field; L]; N_PARTIES]
///   commitments[party_idx][mod_idx] = commitment to shares for that party and modulus
pub struct SecretKeySharesVerificationCircuit<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_SHARE: u32> {
    params: Params<L>,
    /// Expected commitment to sk (from BFV public key circuit)
    expected_sk_commitment: Field,
    /// Secret key polynomial (trinary coefficients)
    sk: Polynomial<N>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk[i] = f(0), y[i][j][k] = f(k) for k = 1..N_PARTIES
    y: [[[Field; N_PARTIES + 1]; L]; N],
    /// Parity check matrices: H[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) * (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
}

impl<let N: u32, let L: u32, let N_PARTIES: u32, let T: u32, let BIT_SK: u32, let BIT_SHARE: u32> SecretKeySharesVerificationCircuit<N, L, N_PARTIES, T, BIT_SK, BIT_SHARE> {
    pub fn new(
        params: Params<L>,
        expected_sk_commitment: Field,
        sk: Polynomial<N>,
        y: [[[Field; N_PARTIES + 1]; L]; N],
        h: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L],
    ) -> Self {
        SecretKeySharesVerificationCircuit { params, expected_sk_commitment, sk, y, h }
    }

    /// Main verification function
    /// Returns L * N_PARTIES commitments: [[Field; L]; N_PARTIES]
    pub fn verify(self) -> [[Field; L]; N_PARTIES] {
        // Step 1: Verify sk commitment matches expected
        self.verify_sk_commitment();

        // Step 2: Verify sk consistency
        self.verify_sk_consistency();

        // Step 3: Range checks
        self.check_range_bounds();

        // Step 4: Verify parity check
        self.verify_parity_check();

        // Step 5: Commit to shares for each party and modulus
        self.commit_to_party_shares()
    }

    /// Computes commitment to sk (must match BFV circuit's commit_to_sk)
    fn compute_sk_commitment(sk: Polynomial<N>) -> Field {
        let sk_payload = flatten::<_, _, BIT_SK>(Vec::new(), [sk]);

        // Domain separator - "PVSS_sk_comm" (must match BFV circuit)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = sk_payload.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(sk_payload);
        let commitment = sponge.squeeze();
        sponge.finish();

        commitment.get(0)
    }

    /// Verifies that sk hashes to expected_sk_commitment
    fn verify_sk_commitment(self) {
        let computed_commitment = Self::compute_sk_commitment(self.sk);
        assert_eq(computed_commitment, self.expected_sk_commitment, "SK commitment mismatch");
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

    /// Range checks for sk and shares
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();
        let crypto_params = self.params.crypto_params();

        // sk coefficients should be in {-1, 0, 1}
        self.sk.range_check_2bounds::<BIT_SK>(bound_params.sk_bound, bound_params.sk_bound);

        // Shares y[i][j][k] for k >= 1 should be in [0, q_j)
        for mod_idx in 0..L {
            let q_j = crypto_params.qis[mod_idx];

            for coeff_idx in 0..N {
                for party_idx in 1..(N_PARTIES + 1) {
                    range_check_field::<BIT_SHARE>(self.y[coeff_idx][mod_idx][party_idx], q_j);
                }
            }
        }
    }

    /// Verifies H[j] * y[i][j]^T == 0 mod q_j for all i, j
    fn verify_parity_check(self) {
        let crypto_params = self.params.crypto_params();

        for coeff_idx in 0..N {
            for mod_idx in 0..L {
                let q_j = crypto_params.qis[mod_idx];

                for row in 0..(N_PARTIES - T) {
                    let mut sum: Field = 0;

                    for col in 0..(N_PARTIES + 1) {
                        sum = sum + self.h[mod_idx][row][col] * self.y[coeff_idx][mod_idx][col];
                    }

                    let result = reduce_mod(sum, q_j);
                    assert(result == 0, "Parity check failed");
                }
            }
        }
    }

    /// Flattens shares for a specific party and modulus into Vec<Field>
    /// Returns N field elements: y[0][mod_idx][party_idx+1], ..., y[N-1][mod_idx][party_idx+1]
    fn party_modulus_payload(self, party_idx: u32, mod_idx: u32) -> Vec<Field> {
        let mut inputs = Vec::new();

        for coeff_idx in 0..N {
            inputs.push(self.y[coeff_idx][mod_idx][party_idx + 1]);
        }

        inputs
    }

    /// Commits to shares for a single party and modulus
    fn commit_to_single_party_modulus(self, party_idx: u32, mod_idx: u32) -> Field {
        let inputs = self.party_modulus_payload(party_idx, mod_idx);

        // Domain separator - "PVSS_sh_pm" (shares party-modulus)
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Include party_idx and mod_idx in the hash
        let mut inputs_with_indices = inputs;
        inputs_with_indices.push(party_idx as Field);
        inputs_with_indices.push(mod_idx as Field);

        let input_size = inputs_with_indices.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs_with_indices);
        let commitment = sponge.squeeze();
        sponge.finish();

        commitment.get(0)
    }

    /// Commits to shares for each party and modulus
    /// Returns [[Field; L]; N_PARTIES] where commitments[party_idx][mod_idx]
    fn commit_to_party_shares(self) -> [[Field; L]; N_PARTIES] {
        let mut commitments: [[Field; L]; N_PARTIES] = [[0; L]; N_PARTIES];

        for party_idx in 0..N_PARTIES {
            for mod_idx in 0..L {
                commitments[party_idx][mod_idx] =
                    self.commit_to_single_party_modulus(party_idx, mod_idx);
            }
        }

        commitments
    }
}

/// Range check for [0, upper_bound) on a single Field
fn range_check_field<let BIT: u32>(value: Field, upper_bound: Field) {
    value.assert_max_bit_size::<BIT>();
    (upper_bound - 1 - value).assert_max_bit_size::<BIT>();
}
