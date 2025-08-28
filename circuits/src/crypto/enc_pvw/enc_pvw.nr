use crate::math::polynomial::{flatten_matrix, flatten_vector, Matrix, Vector};
use safe::safe::SafeSponge;

/// Cryptographic parameters for PVW encryption circuit.
/// Contains the core mathematical constants used in the PVW encryption scheme.
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

/// Bound parameters for range checking in PVW encryption circuit.
/// Contains all the bounds used to validate polynomial coefficients.
pub struct BoundParams<let L: u32> {
    /// Bound for error polynomials e1 (c1 components)
    pub e1_bound: u64,
    /// Bound for error polynomials e2 (c2 components)
    pub e2_bound: u64,
    /// Bound for secret key polynomials (same as encryption vector u)
    pub sk_bound: u64,
    /// Lower bounds for r1 polynomials (modulus switching quotients for c1)
    pub r1_low_bounds: [i64; L],
    /// Upper bounds for r1 polynomials (modulus switching quotients for c1)
    pub r1_up_bounds: [u64; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients for c1)
    pub r2_bounds: [u64; L],
    /// Lower bounds for s1 polynomials (modulus switching quotients for c2)
    pub s1_low_bounds: [i64; L],
    /// Upper bounds for s1 polynomials (modulus switching quotients for c2)
    pub s1_up_bounds: [u64; L],
    /// Bounds for s2 polynomials (cyclotomic reduction quotients for c2)
    pub s2_bounds: [u64; L],
}

impl<let L: u32> BoundParams<L> {
    /// Creates new bound parameters
    pub fn new(
        e1_bound: u64,
        e2_bound: u64,
        sk_bound: u64,
        r1_low_bounds: [i64; L],
        r1_up_bounds: [u64; L],
        r2_bounds: [u64; L],
        s1_low_bounds: [i64; L],
        s1_up_bounds: [u64; L],
        s2_bounds: [u64; L],
    ) -> Self {
        BoundParams {
            e1_bound,
            e2_bound,
            sk_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            s1_low_bounds,
            s1_up_bounds,
            s2_bounds,
        }
    }
}

/// Circuit-specific parameters for PVW encryption circuit.
/// Contains dimensions and other circuit-specific constants.
pub struct CircuitParams {
    /// The degree of polynomials (ring dimension)
    pub n: u32,
    /// Security dimension in PVW encryption
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

/// Complete parameters for PVW encryption circuit.
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
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        e1_bound: u64,
        e2_bound: u64,
        sk_bound: u64,
        r1_low_bounds: [i64; L],
        r1_up_bounds: [u64; L],
        r2_bounds: [u64; L],
        s1_low_bounds: [i64; L],
        s1_up_bounds: [u64; L],
        s2_bounds: [u64; L],
        n: u32,
        k: u32,
        n_parties: u32,
    ) -> Self {
        let crypto = CryptographicParams::new(qis);
        let bounds = BoundParams::new(
            e1_bound,
            e2_bound,
            sk_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            s1_low_bounds,
            s1_up_bounds,
            s2_bounds,
        );
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

/// PVW Encryption Verification Circuit
///
/// Verifies that a ciphertext was correctly generated according to the PVW encryption algorithm.
/// For each party i and modulus l, the encryption equation is:
/// c1_{l,j} = a_{l,j} * u + e1_{j} + r2_{l,j} * (X^N + 1) + r1_{l,j} * q_l
/// c2_{l,i} = b_{l,i} * u + m_i + e2_{i} + s2_{l,i} * (X^N + 1) + s1_{l,i} * q_l
///
/// Where:
/// - u is the random encryption vector (K polynomials: u_0, u_1, ..., u_{K-1})
/// - a_{l,j} is the j-th row of matrix A_l, so a_{l,j} * u = sum_{k=0}^{K-1} a_{l,j,k} * u_k
/// - b_{l,i} is the i-th row of matrix B_l, so b_{l,i} * u = sum_{k=0}^{K-1} b_{l,i,k} * u_k
/// - encoded_messages are the result of message_i * gadget_polynomial (already computed)
/// - e1, e2 are error terms
/// - r1, r2, s1, s2 are quotients from modulus switching and cyclotomic reduction
/// - L is the number of moduli, must equal the length of QIS array
/// - q_l = QIS[l] is the l-th modulus in the RNS representation
pub struct PvwEncryptionCircuit<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    params: Params<N, L>,

    // Public inputs (from public key)
    // Public matrix A for each modulus
    a: [Matrix<K, K, N>; L],
    // Public matrix B for each modulus
    b: [Matrix<N_PARTIES, K, N>; L],

    // Public ciphertext components
    // First ciphertext component for each modulus
    c1: [Vector<K, N>; L],
    // Second ciphertext component (per party, per modulus)
    c2: [Matrix<N_PARTIES, 1, N>; L],

    // Secret witness values
    // Random encryption vector (K polynomials, same distribution as secret key)
    u: Vector<K, N>,
    // Already-encoded messages for each party (result of message_i * gadget_polynomial)
    encoded_messages: Vector<N_PARTIES, N>,

    // Error terms
    // Error for c1 components
    e1: Vector<K, N>,
    // Error for c2 components
    e2: Vector<N_PARTIES, N>,

    // Quotients from modulus switching and cyclotomic reduction
    // Quotient from c1 modulus switching
    r1: [Vector<K, 2 * N - 1>; L],
    // Quotient from c1 cyclotomic reduction
    r2: [Vector<K, N - 1>; L],
    // Quotient from c2 modulus switching
    s1: [Matrix<N_PARTIES, 1, 2 * N - 1>; L],
    // Quotient from c2 cyclotomic reduction
    s2: [Matrix<N_PARTIES, 1, N - 1>; L],
}

impl<let N: u32, let L: u32, let K: u32, let N_PARTIES: u32> PvwEncryptionCircuit<N, L, K, N_PARTIES> {
    pub fn new(
        params: Params<N, L>,
        a: [Matrix<K, K, N>; L],
        b: [Matrix<N_PARTIES, K, N>; L],
        c1: [Vector<K, N>; L],
        c2: [Matrix<N_PARTIES, 1, N>; L],
        u: Vector<K, N>,
        encoded_messages: Vector<N_PARTIES, N>,
        e1: Vector<K, N>,
        e2: Vector<N_PARTIES, N>,
        r1: [Vector<K, 2 * N - 1>; L],
        r2: [Vector<K, N - 1>; L],
        s1: [Matrix<N_PARTIES, 1, 2 * N - 1>; L],
        s2: [Matrix<N_PARTIES, 1, N - 1>; L],
    ) -> Self {
        PvwEncryptionCircuit { params, a, b, c1, c2, u, encoded_messages, e1, e2, r1, r2, s1, s2 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir
    pub fn payload<let SIZE: u32>(self) -> [Field; SIZE] {
        let mut inputs = [0; SIZE];
        let mut offset = 0;

        for l in 0..L {
            // Flatten public matrices a and b (already known, but included for completeness)
            let (inputs, offset) = flatten_matrix(inputs, self.a[l], offset);
            let (inputs, offset) = flatten_matrix(inputs, self.b[l], offset);

            // Flatten ciphertext components (public)
            let (inputs, offset) = flatten_vector(inputs, self.c1[l], offset);
            let (inputs, offset) = flatten_matrix(inputs, self.c2[l], offset);

            // Flatten modulus switching terms
            let (inputs, offset) = flatten_vector(inputs, self.r1[l], offset);
            let (inputs, offset) = flatten_vector(inputs, self.r2[l], offset);
            let (inputs, offset) = flatten_matrix(inputs, self.s1[l], offset);
            let (_, _) = flatten_matrix(inputs, self.s2[l], offset);
        }

        // Flatten witness values (secret)
        let (inputs, offset) = flatten_vector(inputs, self.u, offset);
        let (inputs, offset) = flatten_vector(inputs, self.encoded_messages, offset);

        // Flatten error terms
        let (inputs, offset) = flatten_vector(inputs, self.e1, offset);
        let (inputs, _) = flatten_vector(inputs, self.e2, offset);

        inputs
    }

    /// Verifies that the ciphertext was correctly generated
    pub fn verify_correct_encryption(self) {
        // 1. Range checks on all secret values
        self.perform_range_checks();

        // 2. Generate Fiat-Shamir challenges
        let gammas = self.generate_challenge();

        // 3. Verify encryption equations for each modulus
        for l in 0..L {
            self.verify_encryption_for_modulus(l, gammas.get(l));
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
        // Domain separator for PVSS_enc_pvw circuit - "PVSS_enc_pvw" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x65, 0x6e, 0x63, 0x5f, 0x70, 0x76, 0x77, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(SIZE), SQUEEZE(L)
        // TODO: double check pattern and size value.
        let inputs = self.payload::<28668>();
        let input_size = 28668;
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();
        sponge.finish();
        gammas
    }

    /// Performs range checks on all secret witness values
    fn perform_range_checks(circuit: PvwEncryptionCircuit<N, L, K, N_PARTIES>) {
        // Check encryption vector u has same bounds as secret key (CBD distribution)
        for j in 0..K {
            // Same bound as secret key
            circuit.u[j].range_check_1bound(circuit.params.bounds.sk_bound);
        }

        // Check error terms have appropriate bounds
        for j in 0..K {
            // Error bound for c1 components
            circuit.e1[j].range_check_1bound(circuit.params.bounds.e1_bound);
        }

        for i in 0..N_PARTIES {
            // Error bound for c2 components
            circuit.e2[i].range_check_1bound(circuit.params.bounds.e2_bound);
        }

        // Check quotient terms are within expected bounds (per modulus)
        for l in 0..L {
            for j in 0..K {
                // r1 can be negative (modulus switching quotients for c1)
                circuit.r1[l][j].range_check_2bounds(
                    circuit.params.bounds.r1_up_bounds[l],
                    circuit.params.bounds.r1_low_bounds[l],
                );
                // r2 bound check (cyclotomic reduction quotients for c1)
                circuit.r2[l][j].range_check_1bound(circuit.params.bounds.r2_bounds[l]);
            }

            for i in 0..N_PARTIES {
                // s1 can be negative (modulus switching quotients for c2)
                circuit.s1[l][i][0].range_check_2bounds(
                    circuit.params.bounds.s1_up_bounds[l],
                    circuit.params.bounds.s1_low_bounds[l],
                );
                // s2 range check (cyclotomic reduction quotients for c2)
                circuit.s2[l][i][0].range_check_1bound(circuit.params.bounds.s2_bounds[l]);
            }
        }

        // The circuit assumes encoded_messages = [message_0 * g, message_1 * g, ..., message_{N_PARTIES-1} * g]
    }

    /// Verifies encryption equations for a specific modulus
    fn verify_encryption_for_modulus(
        circuit: PvwEncryptionCircuit<N, L, K, N_PARTIES>,
        l: u32,
        gamma: Field,
    ) {
        // Evaluate all polynomials at the challenge point gamma
        let a_at_gamma = circuit.a[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let b_at_gamma = circuit.b[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let c1_at_gamma = circuit.c1[l].map(|poly| poly.eval(gamma));
        let c2_at_gamma = circuit.c2[l].map(|row| row.map(|poly| poly.eval(gamma)));

        let u_at_gamma = circuit.u.map(|poly| poly.eval(gamma));
        let messages_at_gamma = circuit.encoded_messages.map(|poly| poly.eval(gamma));
        let e1_at_gamma = circuit.e1.map(|poly| poly.eval(gamma));
        let e2_at_gamma = circuit.e2.map(|poly| poly.eval(gamma));

        let r1_at_gamma = circuit.r1[l].map(|poly| poly.eval(gamma));
        let r2_at_gamma = circuit.r2[l].map(|poly| poly.eval(gamma));
        let s1_at_gamma = circuit.s1[l].map(|row| row.map(|poly| poly.eval(gamma)));
        let s2_at_gamma = circuit.s2[l].map(|row| row.map(|poly| poly.eval(gamma)));

        // Cyclotomic polynomial evaluation: X^N + 1
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Verify c1 components: c1_{l,j} = sum_{k=0}^{K-1} a_{l,j,k} * u_k + e1_{j} + r2_{l,j} * (X^N + 1) + r1_{l,j} * q_l
        for j in 0..K {
            // Compute a_{l,j} * u = sum_{k=0}^{K-1} a_{l,j,k} * u_k (dot product of j-th row of A with vector u)
            let mut a_u_product = 0;
            for col in 0..K {
                // a_{l,j,k} * u_k
                a_u_product += a_at_gamma[j][col] * u_at_gamma[col];
            }

            // Compute expected c1 value
            let expected_c1 = a_u_product
                + e1_at_gamma[j]
                + r2_at_gamma[j] * cyclo_at_gamma
                + r1_at_gamma[j] * circuit.params.crypto.qis[l];

            // Verify c1 matches
            assert_eq(c1_at_gamma[j], expected_c1);
        }

        // Verify c2 components: c2_{l,i} = sum_{k=0}^{K-1} b_{l,i,k} * u_k + m_i + e2_{i} + s2_{l,i} * (X^N + 1) + s1_{l,i} * q_l
        for i in 0..N_PARTIES {
            // Compute b_{l,i} * u = sum_{k=0}^{K-1} b_{l,i,k} * u_k (dot product of i-th row of B with vector u)
            let mut b_u_product = 0;
            for j in 0..K {
                // b_{l,i,k} * u_k
                b_u_product += b_at_gamma[i][j] * u_at_gamma[j];
            }

            // Compute expected c2 value
            let expected_c2 = b_u_product
                + messages_at_gamma[i]
                + e2_at_gamma[i]
                + s2_at_gamma[i][0] * cyclo_at_gamma
                + s1_at_gamma[i][0] * circuit.params.crypto.qis[l];

            // Verify c2 matches
            assert_eq(c2_at_gamma[i][0], expected_c2);
        }
    }

    /// Verify that the encryption uses fresh randomness
    /// (prevents replay attacks and ensures semantic security)
    pub fn verify_fresh_randomness(
        circuit: PvwEncryptionCircuit<N, L, K, N_PARTIES>,
        mut previous_u: Vector<K, N>,
    ) {
        // Ensure u is different from any previously used randomness
        let mut is_different = false;
        for j in 0..K {
            for k in 0..N {
                if circuit.u[j].coefficients[k] != previous_u[j].coefficients[k] {
                    is_different = true;
                }
            }
        }
        assert(is_different);
    }
}
