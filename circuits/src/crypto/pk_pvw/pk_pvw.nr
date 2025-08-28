use crate::crypto::pk_pvw::constants::{
    E_BOUND, K, L, N, N_PARTIES, QIS, R1_LOW_BOUNDS, R1_UP_BOUNDS, R2_BOUNDS, SK_BOUND,
};
use crate::math::polynomial::{flatten_matrix, Matrix};
use safe::safe::SafeSponge;

/// PVW Public Key Verification Circuit
///
/// Verifies that a PVW public key was correctly generated according to the protocol.
/// For each party i and modulus l, the public key generation equation is:
/// b_{l,i} = -a_l * s_i + e_i + r2_{l,i} * (X^N + 1) + r1_{l,i} * q_l
///
/// Where:
/// - a_l is the l-th KxK CRS matrix (same for all parties)
/// - s_i is party i's secret key (K-dimensional vector of polynomials)
/// - e_i is party i's error vector (K-dimensional, small coefficients)
/// - b_{l,i} is party i's public key for modulus l (K-dimensional vector)
/// - r1_{l,i}, r2_{l,i} are quotients from modulus switching and cyclotomic reduction
/// - L is the number of moduli, must equal the length of QIS array
/// - q_l = QIS[l] is the l-th modulus in the RNS representation
pub struct PvwPublicKeyCircuit {
    // Common Reference String (CRS) matrices
    // One KxK matrix per modulus l
    a: [Matrix<K, K, N>; L],

    // Party error vectors (secret witness)
    // Each party i has an error vector e[i] of K polynomials with small coefficients
    e: Matrix<N_PARTIES, K, N>,

    // Party secret keys (secret witness)
    // Each party i has a secret key sk[i] of K polynomials from CBD distribution
    sk: Matrix<N_PARTIES, K, N>,

    // Party public keys (public output)
    // b[l][i] is party i's public key vector for modulus l
    b: [Matrix<N_PARTIES, K, N>; L],

    // Quotients from modulus switching and cyclotomic reduction (secret witness)
    // r1[l][i] are quotients from modulus switching for party i, modulus l (can be negative)
    r1: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
    // r2[l][i] are quotients from cyclotomic reduction for party i, modulus l (typically positive)
    r2: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
}

impl PvwPublicKeyCircuit {
    /// Creates a new PVW public key verification circuit
    pub fn new(
        a: [Matrix<K, K, N>; L],
        e: Matrix<N_PARTIES, K, N>,
        sk: Matrix<N_PARTIES, K, N>,
        b: [Matrix<N_PARTIES, K, N>; L],
        r1: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
        r2: [Matrix<N_PARTIES, K, 2 * N - 1>; L],
    ) -> Self {
        PvwPublicKeyCircuit { a, e, sk, b, r1, r2 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    /// This creates a commitment to all the secret and public values used in the protocol
    pub fn payload<let SIZE: u32>(self) -> [Field; SIZE] {
        let mut inputs = [0; SIZE];
        let mut offset = 0;

        for l in 0..L {
            // Flatten CRS matrices a (L matrices of KxK polynomials of degree N)
            // These are public but included for completeness in the transcript
            let (inputs, offset) = flatten_matrix(inputs, self.a[l], offset);

            // Flatten public key matrices b (L matrices of N_PARTIES x K polynomials of degree N)
            // These are public outputs but included in transcript for binding
            let (inputs, offset) = flatten_matrix(inputs, self.b[l], offset);

            // Flatten r1 quotient matrices (L matrices of N_PARTIES x K polynomials of degree 2*N-1)
            // Quotients from modulus switching (degree 2*N-1 to handle polynomial products)
            let (inputs, offset) = flatten_matrix(inputs, self.r1[l], offset);

            // Flatten r2 quotient matrices (L matrices of N_PARTIES x K polynomials of degree 2*N-1)
            // Quotients from cyclotomic reduction modulo (X^N + 1)
            let (_, _) = flatten_matrix(inputs, self.r2[l], offset);
        }

        // Flatten error matrix e (N_PARTIES x K polynomials of degree N)
        // These are secret witnesses that must remain hidden
        let (inputs, offset) = flatten_matrix(inputs, self.e, offset);

        // Flatten secret key matrix sk (N_PARTIES x K polynomials of degree N)
        // These are the most sensitive secret values
        let (inputs, _) = flatten_matrix(inputs, self.sk, offset);

        inputs
    }

    /// Main verification function for PVW public key correctness
    /// Uses the Fiat-Shamir heuristic to generate random challenges and verifies
    /// the public key equations at those challenge points
    pub fn verify_correct_pvw_public_key(self) {
        // Step 1: Perform range checks on all secret witness values
        perform_range_checks(self);

        // Step 2: Generate Fiat-Shamir challenges from the transcript
        let gammas = self.generate_challenge();
        // Step 3: Verify public key equations for each modulus
        // For each modulus q_l, we evaluate all polynomials at a random challenge gamma
        // and verify the linear algebra relation holds
        for l in 0..L {
            let gamma = gammas.get(l);
            verify_public_key_for_modulus(self, l, gamma);
        }
    }

    /// Generates Fiat-Shamir challenge values using a cryptographic sponge
    ///
    /// The sponge absorbs all witness values and squeezes out deterministic random field elements
    /// that will be used to evaluate polynomials for the Schwartz-Zippel lemma.
    ///
    /// # Returns
    /// Vector of challenge values [gamma_0, gamma_1, ..., gamma_{2L-1}]
    fn generate_challenge(self) -> Vec<Field> {
        // Domain separator for PVSS_pk_pvw circuit - "PVSS_pk_pvw" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x70, 0x76, 0x77, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(SIZE), SQUEEZE(2 * L)
        // TODO: double check pattern and size value.
        let inputs = self.payload::<28668>();
        let input_size = 28668;
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }
}

/// Performs comprehensive range checks on all secret witness values
/// Ensures that secret keys, errors, and quotients are within cryptographically safe bounds
fn perform_range_checks(circuit: PvwPublicKeyCircuit) {
    // Check that all party error vectors have small coefficients
    // Small errors are crucial for both security and correctness
    for i in 0..N_PARTIES {
        for j in 0..K {
            // Error coefficients must be bounded to maintain security
            circuit.e[i][j].range_check_1bound(E_BOUND);
            // Secret key coefficients must be small (from CBD distribution)
            circuit.sk[i][j].range_check_1bound(SK_BOUND);
        }
    }

    // Check quotient terms are within expected bounds (per modulus and per party)
    for l in 0..L {
        for j in 0..N_PARTIES {
            for k in 0..K {
                // r1 quotients can be negative (modulus switching can produce negative quotients)
                // Use asymmetric bounds [R1_LOW_BOUNDS[l], R1_UP_BOUNDS[l]] for modulus l
                circuit.r1[l][j][k].range_check_2bounds(R1_UP_BOUNDS[l], R1_LOW_BOUNDS[l]);

                // r2 quotients are typically positive (cyclotomic reduction quotients)
                // Use symmetric bounds [-R2_BOUNDS[l], R2_BOUNDS[l]] for modulus l
                circuit.r2[l][j][k].range_check_1bound(R2_BOUNDS[l]);
            }
        }
    }
}

/// Verifies the public key generation equation for a specific modulus
/// This is where the core PVW linear algebra verification happens
fn verify_public_key_for_modulus(circuit: PvwPublicKeyCircuit, l: u32, gamma: Field) {
    // Evaluate all polynomials at the random challenge point gamma
    // This reduces polynomial equations to field element equations

    // Evaluate CRS matrix A_l at gamma (KxK matrix of field elements)
    let a_at_gamma = circuit.a[l].map(|row| row.map(|poly| poly.eval(gamma)));

    // Evaluate all parties' data at gamma
    let e_at_gamma = circuit.e.map(|row| row.map(|poly| poly.eval(gamma)));
    let sk_at_gamma = circuit.sk.map(|row| row.map(|poly| poly.eval(gamma)));
    let b_at_gamma = circuit.b[l].map(|row| row.map(|poly| poly.eval(gamma)));

    // Evaluate quotient polynomials at gamma
    let r1_at_gamma = circuit.r1[l].map(|row| row.map(|poly| poly.eval(gamma)));
    let r2_at_gamma = circuit.r2[l].map(|row| row.map(|poly| poly.eval(gamma)));

    // Evaluate the cyclotomic polynomial X^N + 1 at gamma
    let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

    // Verify the public key equation for each party
    // The equation is: b_{l,i} = a_l * s_i + e_i + r2_{l,i}*(X^N+1) + r1_{l,i}*q_l
    for i in 0..N_PARTIES {
        // Step 1: Compute matrix-vector product a_l * s_i
        // This is the core lattice operation: multiply KxK matrix by K-vector
        let mut a_times_s = [0; K];
        for row in 0..K {
            for col in 0..K {
                // Accumulate the dot product of row 'row' with secret key s_i
                a_times_s[row] += a_at_gamma[row][col] * sk_at_gamma[i][col];
            }
        }

        // Step 2: Verify each component of the K-dimensional equation
        for k in 0..K {
            // Compute the right-hand side of the public key equation
            let rhs = a_times_s[k] // a_l * s_i (matrix-vector product)
                + e_at_gamma[i][k] // + e_i[k] (error term)
                + r2_at_gamma[i][k] * cyclo_at_gamma // + r2_{l,i}[k] * (X^N + 1)
                + r1_at_gamma[i][k] * QIS[l]; // + r1_{l,i}[k] * q_l

            // Assert that the computed public key matches the expected value
            // This is the core verification: b_{l,i}[k] = RHS
            assert_eq(b_at_gamma[i][k], rhs);
        }
    }
}
