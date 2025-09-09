/// PVW Single Decryption Proof Circuit
///
/// Proves that a party correctly decrypted ONE ciphertext using their secret key.
/// Both the secret key and decrypted plaintext remain private witnesses.
///
/// Core verification: <secret_key, c1> - c2[party_index] = plaintext + small_noise

use crate::math::polynomial::{flatten_matrix, Matrix, Polynomial};
use safe::safe::SafeSponge;

/// Cryptographic parameters for PVW decryption circuit.
/// Contains the core mathematical constants used in the PVW decryption scheme.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    /// Creates new cryptographic parameters
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Bound parameters for range checking in PVW decryption circuit.
/// Contains all the bounds used to validate polynomial coefficients during decryption.
pub struct BoundParams<let L: u32> {
    /// Bound for secret key polynomials
    pub sk_bound: u64,
    /// Bound for decryption noise polynomials
    pub noise_bound: u64,
    /// Message space bound (maximum plaintext value)
    pub message_bound: u64,
}

impl<let L: u32> BoundParams<L> {
    /// Creates new bound parameters for decryption
    pub fn new(sk_bound: u64, noise_bound: u64, message_bound: u64) -> Self {
        BoundParams { sk_bound, noise_bound, message_bound }
    }
}

/// Circuit-specific parameters for PVW decryption circuit.
/// Contains dimensions and other circuit-specific constants.
pub struct CircuitParams {
    /// The degree of polynomials (ring dimension)
    pub n: u32,
    /// Security dimension in PVW decryption
    pub k: u32,
    /// Number of parties
    pub n_parties: u32,
}

impl CircuitParams {
    /// Creates new circuit parameters
    pub fn new(n: u32, k: u32, n_parties: u32) -> Self {
        CircuitParams { n, k, n_parties }
    }
}

/// Complete parameters for PVW decryption circuit.
/// Combines cryptographic parameters, bounds, and circuit-specific parameters.
pub struct Params<let N: u32, let L: u32> {
    /// Cryptographic parameters (moduli)
    pub crypto: CryptographicParams<L>,
    /// Bound parameters for range checking
    pub bounds: BoundParams<L>,
    /// Circuit-specific parameters
    pub circuit: CircuitParams,
}

impl<let N: u32, let L: u32> Params<N, L> {
    /// Creates new complete decryption parameters
    pub fn new(
        qis: [Field; L],
        sk_bound: u64,
        noise_bound: u64,
        message_bound: u64,
        n: u32,
        k: u32,
        n_parties: u32,
    ) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(sk_bound, noise_bound, message_bound);
        let circuit = CircuitParams::new(n, k, n_parties);

        Params { crypto, bounds, circuit }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }

    /// Convenience method to access bound parameters
    pub fn bound_params(self) -> BoundParams<L> {
        self.bounds
    }

    /// Convenience method to access circuit parameters
    pub fn circuit_params(self) -> CircuitParams {
        self.circuit
    }
}

/// PVW Single Decryption Verification Circuit
///
/// Verifies that a party correctly decrypted a ciphertext using their secret key.
/// The circuit enforces that party i can only decrypt the ciphertext component intended for party i.
/// For a party with index party_index and modulus l, the decryption equation is:
/// <sk, c1_l> - c2_l[party_index] = plaintext + noise
///
/// Where:
/// - sk is the party's secret key (K-dimensional vector of polynomials)
/// - c1_l is the first ciphertext component for modulus l (K-dimensional vector)
/// - c2_l[party_index] is extracted from the full c2 matrix for the specified party
/// - plaintext is the decrypted message (kept secret)
/// - noise is small decryption error (must be bounded)
/// - L is the number of moduli in the RNS representation
/// - K is the security dimension
///
/// The circuit includes the complete c2 matrix and cryptographically enforces that
/// the party can only prove decryption of their designated component.
pub struct PvwDecryptionCircuit<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32> {
    // Parameters for the circuit
    params: Params<N, L>,

    // Public inputs - ciphertext components
    /// First ciphertext component for each modulus l (K-dimensional vectors)
    c1: [Matrix<1, K, N>; L],
    /// Complete second ciphertext component matrix for all parties and moduli
    /// c2[l][party][0] contains party's component for modulus l
    c2: [Matrix<N_PARTIES, 1, N>; L],
    /// Party index proving correct decryption
    party_index: Field,

    // Secret witness values
    /// Secret key of the proving party (K-dimensional vector of polynomials)
    sk: Matrix<1, K, N>,
    /// The decrypted plaintext value (kept secret)
    decrypted_plaintext: Field,
    /// Decryption noise for each modulus (small polynomials)
    decryption_noise: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32> PvwDecryptionCircuit<N, L, K, N_PARTIES> {
    /// Creates a new PVW decryption verification circuit
    pub fn new(
        params: Params<N, L>,
        c1: [Matrix<1, K, N>; L],
        c2: [Matrix<N_PARTIES, 1, N>; L],
        party_index: Field,
        sk: Matrix<1, K, N>,
        decrypted_plaintext: Field,
        decryption_noise: [Polynomial<N>; L],
    ) -> Self {
        PvwDecryptionCircuit {
            params,
            c1,
            c2,
            party_index,
            sk,
            decrypted_plaintext,
            decryption_noise,
        }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    /// This creates a commitment to all the secret and public values used in the decryption
    pub fn payload<let SIZE: u32>(self) -> [Field; SIZE] {
        let mut inputs = [0; SIZE];
        let mut offset = 0;

        // Flatten public ciphertext components for all moduli
        for l in 0..L {
            // Flatten c1 matrices (L matrices of 1 x K polynomials of degree N)
            let (inputs, offset) = flatten_matrix(inputs, self.c1[l], offset);

            // Flatten c2 matrices (L matrices of N_PARTIES x 1 polynomials of degree N)
            let (inputs, offset) = flatten_matrix(inputs, self.c2[l], offset);
        }

        // Flatten party index (single field element)
        inputs[offset] = self.party_index;
        offset += 1;

        // Flatten secret witness values
        // Secret key matrix (1 x K polynomials of degree N)
        let (inputs, offset) = flatten_matrix(inputs, self.sk, offset);

        // Decrypted plaintext (single field element)
        inputs[offset] = self.decrypted_plaintext;
        offset += 1;

        // Decryption noise polynomials (L polynomials of degree N)
        for l in 0..L {
            for i in 0..N {
                inputs[offset + i] = self.decryption_noise[l].coefficients[i];
            }
            offset += N;
        }

        inputs
    }

    /// Main verification function for PVW decryption correctness
    /// Uses the Fiat-Shamir heuristic to generate random challenges and verifies
    /// the decryption equations at those challenge points
    pub fn verify_correct_pvw_decryption(self) {
        // Step 1: Perform range checks on all secret witness values
        perform_range_checks(self);

        // Step 2: Generate Fiat-Shamir challenges from the transcript
        let gammas = self.generate_challenge();

        // Step 3: Verify decryption equations for each modulus
        // For each modulus q_l, we evaluate all polynomials at a random challenge gamma
        // and verify the decryption relation holds
        for l in 0..L {
            let gamma = gammas.get(l);
            verify_decryption_for_modulus(self, l, gamma);
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
        // Domain separator for PVSS_dec_pvw circuit - "PVSS_dec_pvw" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x64, 0x65, 0x63, 0x5f, 0x70, 0x76, 0x77, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(SIZE), SQUEEZE(L)
        // Calculate size based on circuit parameters
        let inputs = self.payload::<50000>(); // Adjust based on actual circuit size
        let input_size = 50000;
        let io_pattern = [0x80000000 | input_size, 0x00000000 | L];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }
}

/// Performs comprehensive range checks on all secret witness values
/// Ensures that secret keys, plaintext, and noise are within cryptographically safe bounds
fn perform_range_checks<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32>(
    circuit: PvwDecryptionCircuit<N, L, K, N_PARTIES>,
) {
    // Check that secret key has correct distribution (small coefficients from CBD)
    for j in 0..K {
        circuit.sk[0][j].range_check_1bound(circuit.params.bounds.sk_bound);
    }

    // Check that decryption noise is small for all moduli
    // Small noise proves the decryption was computed correctly
    for l in 0..L {
        circuit.decryption_noise[l].range_check_1bound(circuit.params.bounds.noise_bound);
    }

    // Check plaintext is in valid message space
    assert(circuit.decrypted_plaintext <= circuit.params.bounds.message_bound as Field);

    // Ensure party index is valid
    assert(circuit.party_index < circuit.params.circuit.n_parties as Field);
}

/// Verifies the decryption equation for a specific modulus
/// This is where the core PVW decryption verification happens
fn verify_decryption_for_modulus<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32>(
    circuit: PvwDecryptionCircuit<N, L, K, N_PARTIES>,
    l: u32,
    gamma: Field,
) {
    // Evaluate all polynomials at the random challenge point gamma
    // This reduces polynomial equations to field element equations

    // Evaluate ciphertext components at gamma
    let c1_at_gamma = circuit.c1[l][0].map(|poly| poly.eval(gamma)); // K-dimensional vector

    // Extract and evaluate the specific party's polynomial from c2
    let party_idx = circuit.party_index as u32;
    let c2_at_gamma = circuit.c2[l][party_idx][0].eval(gamma); // Single field element for this party

    // Evaluate secret key at gamma
    let sk_at_gamma = circuit.sk[0].map(|poly| poly.eval(gamma)); // K-dimensional vector

    // Evaluate decryption noise at gamma
    let noise_at_gamma = circuit.decryption_noise[l].eval(gamma); // Single field element

    // Step 1: Compute inner product <sk, c1> for this modulus
    // This is the core lattice operation: compute dot product of K-vectors
    let mut inner_product = 0;
    for j in 0..K {
        inner_product += sk_at_gamma[j] * c1_at_gamma[j];
    }

    // Step 2: Verify the core PVW decryption equation
    // The equation is: <sk, c1_l> - c2_l[party_index] = plaintext + noise
    let left_side = inner_product - c2_at_gamma;
    let right_side = circuit.decrypted_plaintext + noise_at_gamma;

    // Assert that the decryption equation holds
    // This is the core verification: if this passes with small noise, decryption is correct
    assert_eq(left_side, right_side);
}

/// Estimates circuit performance metrics
pub fn estimate_circuit_metrics<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32>(
    circuit: PvwDecryptionCircuit<N, L, K, N_PARTIES>,
) -> (u32, u32) {
    // Estimate constraint count
    let range_checks = K * N * 15 + L * N * 15; // SK + noise range checks
    let inner_products = L * K * 2; // Multiplication + addition per modulus
    let equation_checks = L; // One equality per modulus
    let challenge_generation = 100; // Fiat-Shamir overhead
    let total_constraints = range_checks + inner_products + equation_checks + challenge_generation;

    // Estimate proof size in field elements
    let public_inputs = L * (K + N_PARTIES) * N + 1; // Ciphertext + party index
    let witness_commitments = K * N + 1 + L * N; // SK + plaintext + noise
    let challenge_responses = L; // One per modulus
    let total_proof_size = public_inputs + witness_commitments + challenge_responses;

    (total_constraints, total_proof_size)
}
