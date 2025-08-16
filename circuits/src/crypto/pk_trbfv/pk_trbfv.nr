use crate::crypto::pk_trbfv::constants::{
    EEK_BOUND, L, N, QIS, R1_LOW_BOUNDS, R1_UP_BOUNDS, R2_BOUNDS, SIZE, SK_BOUND, TAG,
};
use crate::math::polynomial::Polynomial;
use safe::safe::SafeSponge;

/// BFV Public Key Verification Circuit
///
/// Verifies that a BFV public key was correctly generated according to the protocol.
/// The BFV public key generation equation is:
/// pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
/// pk1_i = a_i
///
/// Where:
/// - a_i is the i-th polynomial in the CRS (one per modulus)
/// - sk is the secret key polynomial (same for all moduli)
/// - eek is the error polynomial (small coefficients)
/// - pk0_i, pk1_i form the public key pair for modulus i
/// - r1_i, r2_i are quotients from modulus switching and cyclotomic reduction
/// - L is the number of moduli, must equal the length of QIS array
/// - q_i = QIS[i] is the i-th modulus in the RNS representation
///
/// Note: This uses RNS (Residue Number System) representation for efficiency
pub struct BfvPublicKeyCircuit {
    // Common Reference String polynomials (public)
    // One polynomial per modulus i
    a: [Polynomial<N>; L],

    // Error polynomial (secret witness)
    // Small coefficients sampled from error distribution
    eek: Polynomial<N>,

    // Secret key polynomial (secret witness)
    // Small coefficients sampled from CBD (Centered Binomial Distribution)
    sk: Polynomial<N>,

    // Quotients from polynomial operations (secret witness)
    // r1[i] are quotients from modulus switching for modulus i (can be negative, degree 2*N-1)
    r1: [Polynomial<2 * N - 1>; L],
    // r2[i] are quotients from cyclotomic reduction for modulus i (typically positive, degree N-1)
    r2: [Polynomial<N - 1>; L],

    // BFV public key components (public output)
    // pk0[i] is the first component of the public key for modulus i
    pk0: [Polynomial<N>; L],
    // pk1[i] is the second component of the public key for modulus i (should equal a[i])
    pk1: [Polynomial<N>; L],
}

impl BfvPublicKeyCircuit {
    /// Creates a new BFV public key verification circuit
    pub fn new(
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: [Polynomial<2 * N - 1>; L],
        r2: [Polynomial<N - 1>; L],
        pk0: [Polynomial<N>; L],
        pk1: [Polynomial<N>; L],
    ) -> Self {
        BfvPublicKeyCircuit { a, eek, sk, r1, r2, pk0, pk1 }
    }

    /// Flattens all witness data into a single array for Fiat-Shamir challenge generation
    /// This creates a commitment to all the secret and public values used in the protocol
    fn payload(self) -> [Field; SIZE] {
        let mut inputs = [0; SIZE];
        let mut offset = 0;

        // Flatten CRS polynomials a (L polynomials of degree N)
        // These are public but included for completeness in the transcript
        let (inputs, offset) = flatten(inputs, self.a, offset);

        // Flatten error polynomial eek (1 polynomial of degree N)
        // This is a secret witness that must remain hidden
        let (inputs, offset) = flatten(inputs, [self.eek], offset);

        // Flatten secret key polynomial sk (1 polynomial of degree N)
        // This is the most sensitive secret value
        let (inputs, offset) = flatten(inputs, [self.sk], offset);

        // Flatten quotient polynomials (L polynomials each)
        // r1: quotients from modulus switching (degree 2*N-1)
        let (inputs, offset) = flatten(inputs, self.r1, offset);
        // r2: quotients from cyclotomic reduction (degree N-1)
        let (inputs, _) = flatten(inputs, self.r2, offset);

        inputs
    }

    /// Main verification function for BFV public key correctness
    /// Uses the Fiat-Shamir heuristic to generate random challenges and verifies
    /// the public key equations at those challenge points
    pub fn verify_correct_bfv_public_key(self) {
        // Step 1: Perform range checks on all secret witness values
        perform_range_checks(self);

        // Step 2: Generate Fiat-Shamir challenges from the transcript
        let inputs = self.payload();
        let mut safe = SafeSponge::<_, _, TAG>::start([SIZE, 2 * L]);
        safe = safe.absorb(inputs);
        let gammas = safe.squeeze();

        // Step 3: Verify public key equations for each modulus
        // For each modulus q_i, we evaluate all polynomials at a random challenge gamma
        // and verify the BFV public key generation relation holds
        for i in 0..L {
            let gamma = gammas.get(i);
            verify_public_key_for_modulus(self, i, gamma);
        }

        safe.finish();
    }
}

/// Performs comprehensive range checks on all secret witness values
/// Ensures that secret keys, errors, and quotients are within cryptographically safe bounds
fn perform_range_checks(circuit: BfvPublicKeyCircuit) {
    // Check that error polynomial has small coefficients
    // Small errors are crucial for both security and correctness in BFV
    circuit.eek.range_check_1bound(EEK_BOUND);

    // Check that secret key polynomial has small coefficients
    // Secret key must be small (from CBD distribution) for security
    circuit.sk.range_check_1bound(SK_BOUND);

    // Check quotient terms are within expected bounds (per modulus)
    for i in 0..L {
        // r1 quotients can be negative (modulus switching can produce negative quotients)
        // Use asymmetric bounds [R1_LOW_BOUNDS[i], R1_UP_BOUNDS[i]] for modulus i
        circuit.r1[i].range_check_2bounds(R1_UP_BOUNDS[i], R1_LOW_BOUNDS[i]);

        // r2 quotients are typically positive (cyclotomic reduction quotients)
        // Use symmetric bounds [-R2_BOUNDS[i], R2_BOUNDS[i]] for modulus i
        circuit.r2[i].range_check_1bound(R2_BOUNDS[i]);
    }
}

/// Verifies the BFV public key generation equation for a specific modulus
/// This is where the core BFV verification happens
fn verify_public_key_for_modulus(circuit: BfvPublicKeyCircuit, i: u32, gamma: Field) {
    // Evaluate all polynomials at the random challenge point gamma
    // This reduces polynomial equations to field element equations

    // Evaluate CRS polynomials at gamma
    let a_at_gamma = circuit.a.map(|a_poly| a_poly.eval(gamma));

    // Evaluate secret values at gamma
    let eek_at_gamma = circuit.eek.eval(gamma);
    let sk_at_gamma = circuit.sk.eval(gamma);

    // Evaluate quotient polynomials at gamma
    let r1_at_gamma = circuit.r1.map(|r1_poly| r1_poly.eval(gamma));
    let r2_at_gamma = circuit.r2.map(|r2_poly| r2_poly.eval(gamma));

    // Evaluate public key polynomials at gamma
    let pk0_at_gamma = circuit.pk0.map(|pk0_poly| pk0_poly.eval(gamma));
    let pk1_at_gamma = circuit.pk1.map(|pk1_poly| pk1_poly.eval(gamma));

    // Evaluate the cyclotomic polynomial X^N + 1 at gamma
    let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

    // Verify the BFV public key generation equations

    // Equation 1: pk0_i = -a_i * sk + eek + r2_i * (X^N + 1) + r1_i * q_i
    // This is the main BFV public key equation
    let expected_pk0 = -a_at_gamma[i] * sk_at_gamma // -a_i * sk
        + eek_at_gamma // + eek (error term)
        + r2_at_gamma[i] * cyclo_at_gamma // + r2_i * (X^N + 1)
        + r1_at_gamma[i] * QIS[i]; // + r1_i * q_i

    assert_eq(pk0_at_gamma[i], expected_pk0);

    // Equation 2: pk1_i = a_i
    // The second component of BFV public key is just the CRS polynomial
    assert_eq(pk1_at_gamma[i], a_at_gamma[i]);
}

/// Helper function to flatten polynomial arrays into the Fiat-Shamir transcript
/// Converts arrays of polynomials into a flat array of field elements
fn flatten<let A: u32, let L: u32>(
    mut inputs: [Field; SIZE],
    poly_array: [Polynomial<A>; L],
    mut offset: u32,
) -> ([Field; SIZE], u32) {
    // For each polynomial in the array
    for j in 0..L {
        // For each coefficient in the polynomial
        for k in 0..A {
            // Copy coefficient into the flat inputs array
            inputs[k + offset] = poly_array[j].coefficients[k];
        }
        // Move offset by the polynomial degree
        offset += A;
    }

    (inputs, offset)
}
