use crate::math::polynomial::Polynomial;
use safe::safe::SafeSponge;

/// Cryptographic parameters for decryption share correctness circuit.
/// Contains the core mathematical constants used in the threshold scheme.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Scaling factors for each basis: [k0_0, k0_1, ..., k0_{L-1}]
    pub k0is: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    /// Creates new cryptographic parameters
    pub fn new(qis: [Field; L], k0is: [Field; L]) -> Self {
        CryptographicParams { qis, k0is }
    }
}

/// Bound parameters for range checking in decryption share circuit.
/// Contains all the bounds used to validate polynomial coefficients.
pub struct BoundParams<let H: u32, let L: u32> {
    /// Bound for smudging noise shares e_i
    pub noise_bound: u64,
    /// Bounds for valid shares y_i for each honest party
    pub share_bounds: [u64; H],
    /// Bound for aggregated shares sum s
    pub s_bound: u64,
    /// Bound for aggregated noise sum e
    pub e_bound: u64,
    /// Bound for computed decryption share d
    pub decryption_share_bound: u64,
    /// Lower bounds for r_1 polynomials (modulus quotients, can be negative)
    pub r1_low_bounds: [i64; L],
    /// Upper bounds for r_1 polynomials (modulus quotients)
    pub r1_up_bounds: [u64; L],
    /// Bounds for r_2 polynomials (cyclotomic quotients)
    pub r2_bounds: [u64; L],
}

impl<let H: u32, let L: u32> BoundParams<H, L> {
    /// Creates new bound parameters
    pub fn new(
        noise_bound: u64,
        share_bounds: [u64; H],
        s_bound: u64,
        e_bound: u64,
        decryption_share_bound: u64,
        r1_low_bounds: [i64; L],
        r1_up_bounds: [u64; L],
        r2_bounds: [u64; L],
    ) -> Self {
        BoundParams { 
            noise_bound, 
            share_bounds, 
            s_bound,
            e_bound,
            decryption_share_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
        }
    }
}

/// Complete parameters for decryption share correctness circuit.
/// Combines cryptographic parameters and bounds.
pub struct Params<let N: u32, let H: u32, let L: u32> {
    /// Cryptographic parameters (moduli, scaling factors)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams<H, L>,
    /// Ring dimension (number of polynomial coefficients)
    pub n: u32,
    /// Number of CRT bases
    pub l: u32,
    /// Number of honest/valid parties (determines how many y_i and e_i shares we have)
    pub honest_parties: u32,
}

impl<let N: u32, let H: u32, let L: u32> Params<N, H, L> {
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        k0is: [Field; L],
        noise_bound: u64,
        share_bounds: [u64; H],
        s_bound: u64,
        e_bound: u64,
        decryption_share_bound: u64,
        r1_low_bounds: [i64; L],
        r1_up_bounds: [u64; L],
        r2_bounds: [u64; L],
        n: u32,
        l: u32,
        honest_parties: u32,
    ) -> Self {
        let crypto = CryptographicParams::new(qis, k0is);
        let bounds = BoundParams::new(
            noise_bound, 
            share_bounds, 
            s_bound,
            e_bound,
            decryption_share_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
        );

        Params { crypto, bounds, n, l, honest_parties }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    /// Convenience method to access bound parameters
    pub fn bound_params(self) -> BoundParams<H, L> {
        self.bounds
    }
}

/// Decryption Share Correctness Circuit
///
/// This circuit verifies that each party correctly computes their decryption share
/// according to the formula in ring R_q: d = c_0 + c_1 * s + e
///
/// Where:
/// - s = ∑ y_i (sum of valid shares from honest parties)
/// - e = ∑ e_i (sum of smudging noise shares)
/// - d is the party's computed decryption share
///
/// Since Noir works over a large field Z (254-bit), we lift the ring equation:
/// For each modulus q_i: d_i = c_0i + c_1i * s + e_i + r_2_i * (X^N + 1) + r_1_i * q_i (mod Z)
///
/// The circuit enforces:
/// 1. Range checks on all shares, noise terms, and quotients
/// 2. Correct computation of the lifted decryption share formula
/// 3. Small coefficient bounds on s (since it's sum of small shares)
///
/// # Generic Parameters
/// * `N` - The number of coefficients in ring polynomials (polynomials have degree N-1)
/// * `H` - The number of honest/valid parties
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
pub struct DecryptionShareCorrectness<let N: u32, let H: u32, let L: u32> {
    /// Circuit parameters including bounds and cryptographic constants
    params: Params<N, H, L>,
    
    /// Ciphertext components (public inputs)
    /// c_0 components for each CRT basis (degree N-1 polynomials with N coefficients)
    c_0: [Polynomial<N>; L],
    /// c_1 components for each CRT basis (degree N-1 polynomials with N coefficients)
    c_1: [Polynomial<N>; L],
    
    /// Valid shares collected by this party (secret witnesses)
    /// collected_shares[coefficient][basis][share_idx] - field element shares collected from H parties
    /// Each party collects H shares for each coefficient from different parties and sums them
    /// This represents the shares this party has collected from the H honest parties
    collected_shares: [[[Field; H]; L]; N],
    
    /// Noise shares collected by this party (secret witnesses)
    /// collected_noise[coefficient][basis][share_idx] - field element noise collected from H parties
    /// Each party collects H noise values for each coefficient from different parties and sums them
    /// This represents the noise shares this party has collected from the H honest parties
    collected_noise: [[[Field; H]; L]; N],
    
    /// Aggregated sum of shares s = ∑ y_i (secret witness)
    /// s[basis] - sum of valid shares for each CRT basis (degree N-1 with N coefficients)
    /// This has small coefficients since it's sum of small shares
    s: [Polynomial<N>; L],
    
    /// Aggregated sum of noise e = ∑ e_i (secret witness)
    /// e[basis] - sum of noise shares for each CRT basis (degree N-1 with N coefficients)
    e: [Polynomial<N>; L],
    
    /// Quotient polynomials for lifting to Z (secret witnesses)
    /// r_1[basis] - quotients from modulus q_i (degree 2N-2 with 2N-1 coefficients, can be negative)
    r_1: [Polynomial<2 * N - 1>; L],
    /// r_2[basis] - quotients from cyclotomic polynomial X^N + 1 (degree N-2 with N-1 coefficients)
    r_2: [Polynomial<N - 1>; L],
    
    /// Party's computed decryption share (public output)
    /// d[basis] - decryption share computed by this party for each CRT basis (degree N-1 with N coefficients)
    /// This is what the party claims to have computed using the lifted formula
    /// These shares are public so they can be aggregated by other parties
    d: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32> DecryptionShareCorrectness<N, H, L> {
    /// Creates a new decryption share correctness circuit instance
    ///
    /// # Arguments
    /// * `params` - Circuit parameters including bounds and crypto constants
    /// * `c_0` - First ciphertext components for each CRT basis
    /// * `c_1` - Second ciphertext components for each CRT basis
    /// * `collected_shares` - Valid shares collected by this party [coefficient][basis][share_idx] - field elements
    /// * `collected_noise` - Noise shares collected by this party [coefficient][basis][share_idx] - field elements
    /// * `s` - Aggregated sum of valid shares ∑ y_i for each CRT basis
    /// * `e` - Aggregated sum of noise shares ∑ e_i for each CRT basis
    /// * `r_1` - Quotient polynomials for modulus q_i lifting (degree 2N-2 with 2N-1 coefficients each)
    /// * `r_2` - Quotient polynomials for cyclotomic polynomial lifting (degree N-2 with N-1 coefficients each)
    /// * `d` - Party's computed decryption share (public output to be shared with others)
    ///
    /// # Returns
    /// A new DecryptionShareCorrectness instance ready for verification
    pub fn new(
        params: Params<N, H, L>,
        c_0: [Polynomial<N>; L],
        c_1: [Polynomial<N>; L],
        collected_shares: [[[Field; H]; L]; N],
        collected_noise: [[[Field; H]; L]; N],
        s: [Polynomial<N>; L],
        e: [Polynomial<N>; L],
        r_1: [Polynomial<2 * N - 1>; L],
        r_2: [Polynomial<N - 1>; L],
        d: [Polynomial<N>; L],
    ) -> Self {
        DecryptionShareCorrectness {
            params,
            c_0,
            c_1,
            collected_shares,
            collected_noise,
            s,
            e,
            r_1,
            r_2,
            d,
        }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    ///
    /// This creates a commitment to all the secret and public values used in the protocol.
    /// The ordering is deterministic to ensure reproducible challenge generation.
    ///
    /// # Generic Parameters
    /// * `SIZE` - The total size of the flattened array
    ///
    /// # Returns
    /// An array containing all witness data in flattened form
    fn payload<let SIZE: u32>(self) -> [Field; SIZE] {
        let mut inputs = [0; SIZE];
        let mut offset = 0;

        // Flatten ciphertext components (public inputs)
        let (inputs, offset) = flatten(inputs, self.c_0, offset);
        let (inputs, offset) = flatten(inputs, self.c_1, offset);

        // Flatten collected shares (secret witnesses)
        // Note: This flattens the 3D array [N][L][H] into 1D
        for coeff_idx in 0..N {
            for basis_idx in 0..L {
                for share_idx in 0..H {
                    inputs[offset] = self.collected_shares[coeff_idx][basis_idx][share_idx];
                    offset += 1;
                }
            }
        }

        // Flatten collected noise (secret witnesses)
        for coeff_idx in 0..N {
            for basis_idx in 0..L {
                for share_idx in 0..H {
                    inputs[offset] = self.collected_noise[coeff_idx][basis_idx][share_idx];
                    offset += 1;
                }
            }
        }

        // Flatten aggregated sums (secret witnesses)
        let (inputs, offset) = flatten(inputs, self.s, offset);
        let (inputs, offset) = flatten(inputs, self.e, offset);

        // Flatten quotient polynomials (secret witnesses)
        let (inputs, offset) = flatten(inputs, self.r_1, offset);
        let (inputs, offset) = flatten(inputs, self.r_2, offset);

        // Flatten decryption shares (public outputs - to be shared with other parties)
        let (inputs, _) = flatten(inputs, self.d, offset);

        inputs
    }

    /// Main verification function for decryption share correctness
    ///
    /// This function implements the complete zero-knowledge proof by:
    /// 1. Performing range checks on all secret values
    /// 2. Generating Fiat-Shamir challenges
    /// 3. Verifying the share aggregation (s = ∑ y_i, e = ∑ e_i)
    /// 4. Verifying the decryption share computation formula at random points
    pub fn verify_decryption_share_correctness(self) {
        // Step 1: Perform range checks on all secret witness values
        self.check_range_bounds();

        // Step 2: Generate Fiat-Shamir challenges from the transcript
        let gammas = self.generate_challenge();

        // Step 3: Verify share aggregation (s = ∑ y_i, e = ∑ e_i)
        self.verify_share_aggregation();

        // Step 4: Verify decryption share computation for each CRT basis
        for i in 0..L {
            let gamma = gammas.get(i);
            self.verify_decryption_share_computation(i, gamma);
        }
    }

    /// Performs comprehensive range checks on all secret witness values
    ///
    /// Ensures that shares, noise terms, aggregated sums, and quotients are within cryptographically safe bounds.
    /// This prevents attacks where values are outside the expected distribution.
    fn check_range_bounds(self) {
        let bound_params = self.params.bound_params();

        // Check collected shares are within bounds
        for coeff_idx in 0..N {
            for basis_idx in 0..L {
                for share_idx in 0..H {
                    let share_value = self.collected_shares[coeff_idx][basis_idx][share_idx];
                    // Range check each collected share value
                    assert(share_value <= bound_params.share_bounds[share_idx] as Field);
                    assert(share_value >= -(bound_params.share_bounds[share_idx] as Field));
                }
            }
        }

        // Check collected noise shares are within bounds
        for coeff_idx in 0..N {
            for basis_idx in 0..L {
                for share_idx in 0..H {
                    let noise_value = self.collected_noise[coeff_idx][basis_idx][share_idx];
                    assert(noise_value <= bound_params.noise_bound as Field);
                    assert(noise_value >= -(bound_params.noise_bound as Field));
                }
            }
        }

        // Check aggregated sums are within bounds
        for basis_idx in 0..L {
            self.s[basis_idx].range_check_1bound(bound_params.s_bound);
            self.e[basis_idx].range_check_1bound(bound_params.e_bound);
        }

        // Check quotient polynomials are within bounds
        for basis_idx in 0..L {
            // r_1 quotients can be negative (modulus quotients)
            self.r_1[basis_idx].range_check_2bounds(
                bound_params.r1_up_bounds[basis_idx],
                bound_params.r1_low_bounds[basis_idx],
            );
            // r_2 quotients (cyclotomic quotients)
            self.r_2[basis_idx].range_check_1bound(bound_params.r2_bounds[basis_idx]);
        }
    }

    /// Generates Fiat-Shamir challenge values using a cryptographic sponge
    ///
    /// The sponge absorbs all witness values and squeezes out deterministic random field elements
    /// that will be used to evaluate polynomials for the Schwartz-Zippel lemma.
    ///
    /// # Returns
    /// Vector of challenge values [gamma_0, gamma_1, ..., gamma_{L-1}]
    fn generate_challenge(self) -> Vec<Field> {
        // Domain separator for decryption share circuit - "DecShare" in hex
        let domain_separator = [
            0x44, 0x65, 0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Calculate input size: 2*L*N (ciphertexts) + H*L*N (collected shares) + H*L*N (collected noise) + 2*L*N (s,e) + L*(2*N-1) (r_1) + L*(N-1) (r_2) + L*N (d)
        let input_size = (2 + 2 + 1) * L * N + H * L * N + H * L * N + L * (2 * N - 1) + L * (N - 1);
        let io_pattern = [0x80000000 | input_size, 0x00000000 | L];

        let inputs = self.payload::<(2 + 2 + 1) * L * N + H * L * N + H * L * N + L * (2 * N - 1) + L * (N - 1)>();

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }

    /// Verifies that the aggregated sums are correctly computed
    ///
    /// Checks that:
    /// - s[basis] = ∑ collected_shares for each CRT basis (sum over all H collected shares)
    /// - e[basis] = ∑ collected_noise for each CRT basis (sum over all H collected noise values)
    fn verify_share_aggregation(self) {
        // For each CRT basis, verify the aggregation
        for basis_idx in 0..L {
            // Verify s = ∑ collected_shares for this basis
            for coeff_idx in 0..N {
                let mut expected_s_coeff = 0 as Field;
                for share_idx in 0..H {
                    expected_s_coeff += self.collected_shares[coeff_idx][basis_idx][share_idx];
                }
                assert_eq(self.s[basis_idx].coefficients[coeff_idx], expected_s_coeff);
            }

            // Verify e = ∑ collected_noise for this basis
            for coeff_idx in 0..N {
                let mut expected_e_coeff = 0 as Field;
                for share_idx in 0..H {
                    expected_e_coeff += self.collected_noise[coeff_idx][basis_idx][share_idx];
                }
                assert_eq(self.e[basis_idx].coefficients[coeff_idx], expected_e_coeff);
            }
        }
    }

    /// Verifies the lifted decryption share computation formula for a specific CRT basis
    ///
    /// Checks the lifted equation: d_i(gamma) = c_0i(gamma) + c_1i(gamma) * s(gamma) + e_i(gamma) + r_2_i(gamma) * (gamma^N + 1) + r_1_i(gamma) * q_i
    /// This verifies the equation holds in Z (integers) rather than just R_{q_i}.
    ///
    /// # Arguments
    /// * `basis_idx` - CRT basis index
    /// * `gamma` - Challenge value for polynomial evaluation
    fn verify_decryption_share_computation(self, basis_idx: u32, gamma: Field) {
        let crypto_params = self.params.crypto_params();

        // Evaluate ciphertext components at gamma
        let c_0_at_gamma = self.c_0[basis_idx].eval(gamma);
        let c_1_at_gamma = self.c_1[basis_idx].eval(gamma);

        // Evaluate aggregated sums at gamma
        let s_at_gamma = self.s[basis_idx].eval(gamma);
        let e_at_gamma = self.e[basis_idx].eval(gamma);

        // Evaluate quotient polynomials at gamma
        let r_1_at_gamma = self.r_1[basis_idx].eval(gamma);
        let r_2_at_gamma = self.r_2[basis_idx].eval(gamma);

        // Evaluate cyclotomic polynomial X^N + 1 at gamma
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Compute expected decryption share using the lifted formula:
        // d_i = c_0i + c_1i * s + e_i + r_2_i * (X^N + 1) + r_1_i * q_i
        let expected_decryption_share = c_0_at_gamma 
            + c_1_at_gamma * s_at_gamma 
            + e_at_gamma
            + r_2_at_gamma * cyclo_at_gamma
            + r_1_at_gamma * crypto_params.qis[basis_idx];

        // Evaluate the party's claimed decryption share at gamma
        let computed_decryption_share = self.d[basis_idx].eval(gamma);

        // Enforce equality: computed decryption share must match expected value
        assert_eq(computed_decryption_share, expected_decryption_share);
    }
}

/// Helper function to flatten an array of polynomials into a 1D array
///
/// This function serializes polynomial coefficients for challenge generation
/// in the Fiat-Shamir transform. It maintains deterministic ordering.
///
/// # Generic Parameters
/// * `A` - The degree of each polynomial in the array
/// * `L` - The number of polynomials in the array
/// * `SIZE` - The total size of the target array
///
/// # Arguments
/// * `inputs` - The target array to store flattened coefficients
/// * `poly` - Array of polynomials to flatten
/// * `offset` - Starting position in the inputs array
///
/// # Returns
/// A tuple containing the updated inputs array and new offset
fn flatten<let A: u32, let L: u32, let SIZE: u32>(
    mut inputs: [Field; SIZE],
    poly: [Polynomial<A>; L],
    mut offset: u32,
) -> ([Field; SIZE], u32) {
    for j in 0..L {
        for i in 0..A {
            inputs[i + offset] = poly[j].coefficients[i];
        }
        offset += A;
    }

    (inputs, offset)
}