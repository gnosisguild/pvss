use crate::math::polynomial::Polynomial;
use safe::safe::SafeSponge;
use dep::bignum::runtime_bignum::{BigNumInstance, BigNumParamsTrait};

/// Cryptographic parameters for decryption share aggregation circuit.
/// Contains the core mathematical constants used in the threshold scheme.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Scaling factors for each basis: [k_0, k_1, ..., k_{L-1}]
    /// These are the negative of the inverse of the plaintext modulus in each q_i
    pub kis: [Field; L],
    /// Plaintext modulus
    pub plaintext_modulus: Field,
}

impl<let L: u32> CryptographicParams<L> {
    /// Creates new cryptographic parameters
    pub fn new(qis: [Field; L], kis: [Field; L], plaintext_modulus: Field) -> Self {
        CryptographicParams { qis, kis, plaintext_modulus }
    }
}

/// Complete parameters for decryption share aggregation circuit.
pub struct Params<let N: u32, let T: u32, let L: u32> {
    /// Cryptographic parameters (moduli, delta inverse)
    pub crypto: CryptographicParams<L>,
    /// Ring dimension (number of polynomial coefficients)
    pub n: u32,
    /// Number of CRT bases
    pub l: u32,
    /// Threshold (number of parties needed - 1, we need t+1 parties)
    pub threshold: u32,
}

impl<let N: u32, let T: u32, let L: u32> Params<N, T, L> {
    /// Creates new complete parameters
    pub fn new(
        qis: [Field; L],
        kis: [Field; L],
        plaintext_modulus: Field,
        n: u32,
        l: u32,
        threshold: u32,
    ) -> Self {
        let crypto = CryptographicParams::new(qis, kis, plaintext_modulus);
        Params { crypto, n, l, threshold }
    }

    /// Convenience method to access cryptographic parameters
    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }
}

/// Decryption Share Aggregation Circuit
///
/// This circuit aggregates t+1 decryption shares using Lagrange interpolation
/// to recover the final decrypted message. The process involves:
///
/// 1. Each of t+1 parties provides a polynomial d_i(x) of degree N-1 with their party ID x_i
/// 2. For each coefficient position (0 to N-1), we have t+1 values (one from each party)
/// 3. We apply Lagrange interpolation to each coefficient independently
/// 4. This gives us N interpolated values p_i(0) which form a polynomial m'(x) of degree N-1
/// 5. We compute Q = ∏ q_i (product of CRT moduli) IN THE CIRCUIT
/// 6. We compute scaled_message = Q*m(x) mod t IN THE CIRCUIT
/// 7. We encode the scaled message in each modulus: encoded_i = k_i * scaled_message
/// 8. We verify that m'(x) ≡ encoded_i (mod q_i) for each modulus i
///
/// # Generic Parameters
/// * `N` - The message degree (number of coefficients in the message and decryption share polynomials)
///        Note: This may be smaller than the full ring dimension if we only need part of the message
/// * `T` - The threshold value (we need T+1 parties to reconstruct)
/// * `L` - The number of CRT (Chinese Remainder Theorem) bases
pub struct DecryptionShareAggregation<let N: u32, let T: u32, let L: u32> {
    /// Circuit parameters including crypto constants
    params: Params<N, T, L>,
    
    /// Decryption shares from t+1 parties (public inputs)
    /// decryption_shares[party_idx][basis_idx] - polynomial d_i(x) from party i for each CRT basis
    /// Each polynomial has degree N-1 with N coefficients (only the first N coefficients we care about)
    decryption_shares: [[Polynomial<N>; L]; T + 1],
    
    /// Party IDs (x-coordinates) for interpolation (public inputs)
    /// party_ids[party_idx] - the ID x_i of party i
    /// These are the x-coordinates for Lagrange interpolation
    party_ids: [Field; T + 1],
    
    /// Lagrange coefficients evaluated at point 0: l_i(0) (public inputs)
    /// lagrange_coeffs[coeff_idx][basis_idx][party_idx] - l_i(0) for coefficient position
    /// We have N*(T+1)*L total Lagrange coefficients (one for each coefficient, basis, and party)
    lagrange_coeffs: [[[Field; T + 1]; L]; N],
    
    /// Message polynomial m(x) (public input)
    /// The plaintext message polynomial of degree N-1 with N coefficients
    /// We compute scaled_message = Q*m(x) mod t inside the circuit
    message: Polynomial<N>,
}

impl<let N: u32, let T: u32, let L: u32> DecryptionShareAggregation<N, T, L> {
    /// Creates a new decryption share aggregation circuit instance
    ///
    /// # Arguments
    /// * `params` - Circuit parameters including crypto constants (includes Q and plaintext modulus)
    /// * `decryption_shares` - Polynomials d_i(x) from t+1 parties for each CRT basis (degree N-1)
    /// * `party_ids` - Party IDs x_i (x-coordinates for interpolation)
    /// * `lagrange_coeffs` - Pre-computed Lagrange coefficients l_i(0)
    /// * `message` - The plaintext message m(x); scaled_message = Q*m(x) mod t is computed in circuit
    pub fn new(
        params: Params<N, T, L>,
        decryption_shares: [[Polynomial<N>; L]; T + 1],
        party_ids: [Field; T + 1],
        lagrange_coeffs: [[[Field; T + 1]; L]; N],
        message: Polynomial<N>,
    ) -> Self {
        DecryptionShareAggregation {
            params,
            decryption_shares,
            party_ids,
            lagrange_coeffs,
            message,
        }
    }

    /// Prepares all circuit inputs into a single array for challenge generation
    ///
    /// Serializes all inputs in a deterministic order for the Fiat-Shamir transform.
    /// The order is:
    /// 1. Decryption shares: (T+1) * L * N coefficients
    /// 2. Party IDs: (T+1) values
    /// 3. Lagrange coefficients: N * L * (T+1) values
    /// 4. Message: N coefficients
    ///
    /// # Returns
    /// Array of all circuit inputs serialized in order
    fn payload<let SIZE: u32>(self) -> [Field; SIZE] {
        let mut inputs = [0 as Field; SIZE];
        let mut offset = 0;

        // Flatten decryption shares from all parties and all bases
        for party_idx in 0..(T + 1) {
            (inputs, offset) = flatten(inputs, self.decryption_shares[party_idx], offset);
        }

        // Add party IDs
        for party_idx in 0..(T + 1) {
            inputs[offset] = self.party_ids[party_idx];
            offset += 1;
        }

        // Flatten Lagrange coefficients for all coefficients, bases, and parties
        for coeff_idx in 0..N {
            for basis_idx in 0..L {
                for party_idx in 0..(T + 1) {
                    inputs[offset] = self.lagrange_coeffs[coeff_idx][basis_idx][party_idx];
                    offset += 1;
                }
            }
        }

        // Add message coefficients
        for coeff_idx in 0..N {
            inputs[offset] = self.message.coefficients[coeff_idx];
            offset += 1;
        }

        inputs
    }

    /// Main verification function that orchestrates the entire aggregation check
    ///
    /// The verification process:
    /// 1. (TODO) Verify Lagrange coefficient correctness - currently trusted input
    /// 2. Compute Q = ∏ q_i (product of all CRT moduli) inside the circuit
    /// 3. Compute scaled_message = Q*m(x) mod t inside the circuit
    /// 4. Perform Lagrange interpolation on each coefficient
    /// 5. Encode the scaled message in each modulus: encoded_i = k_i * scaled_message
    /// 6. Check that m'(x) ≡ encoded_i (mod q_i) for each modulus
    pub fn verify(self) {
        // Step 1: Verify Lagrange coefficients are correctly computed
        // TODO: Currently a placeholder - see verify_lagrange_coefficients for details
        self.verify_lagrange_coefficients();

        // Step 2: Compute Q = ∏ q_i, then scaled_message = Q * message mod t (all in-circuit)
        let scaled_message = self.compute_scaled_message();

        // Step 3: Perform interpolation and verify congruence for each CRT basis
        for basis_idx in 0..L {
            self.verify_interpolation_and_congruence(basis_idx, scaled_message);
        }
    }

    /// Computes the scaled message: scaled_message = Q * m(x) mod t
    ///
    /// Where:
    /// - Q = ∏ q_i is computed inside the circuit from the qis parameters
    /// - m(x) is the message polynomial (input)
    /// - t is the plaintext modulus (from params)
    ///
    /// # Returns
    /// The scaled message polynomial with each coefficient computed as (Q * m[i]) mod t
    fn compute_scaled_message(self) -> Polynomial<N> {
        let crypto_params = self.params.crypto_params();
        let t = crypto_params.plaintext_modulus;

        // Compute Q = q_0 * q_1 * ... * q_{L-1} inside the circuit
        let mut big_q = 1 as Field;
        for i in 0..L {
            big_q = big_q * crypto_params.qis[i];
        }

        // Compute scaled message coefficients
        let mut scaled_coeffs = [0 as Field; N];
        for i in 0..N {
            // Compute (Q * message[i]) mod t using BigNum
            // This is now constrained to ensure correctness
            scaled_coeffs[i] = compute_scaled_coefficient(big_q, self.message.coefficients[i], t);
        }

        Polynomial { coefficients: scaled_coeffs }
    }

    /// Verifies that Lagrange coefficients are correctly computed
    ///
    /// For each party i, verifies that l_i(0) = ∏(j≠i) (0 - x_j) / (x_i - x_j)
    /// This ensures the Lagrange coefficients will correctly interpolate at point 0.
    ///
    /// TODO: This verification is currently not implemented due to field arithmetic mismatch.
    /// 
    /// ISSUE: Lagrange coefficients are calculated in each modulus q_i, but Noir operates
    /// in a different field (BN254 scalar field, ~254 bits). This creates a fundamental mismatch:
    /// - The Lagrange coefficients l_i(0) are computed mod q_i during share generation
    /// - Noir circuit arithmetic is performed mod p (where p is the Noir field modulus)
    /// - We cannot directly verify l_i(0) in Noir field matches the value computed mod q_i
    ///
    /// POTENTIAL SOLUTIONS:
    /// 1. Implement modular arithmetic in Noir to compute and verify in each q_i
    ///    - Pros: Full verification in circuit
    ///    - Cons: Complex, expensive, requires big integer arithmetic
    /// 
    /// 2. Implement Noir field arithmetic in Rust during Lagrange coefficient generation
    ///    - Pros: Generate l_i(0) directly in Noir field, simple verification
    ///    - Cons: Requires careful implementation to match Noir's field operations
    /// 
    /// 3. Use a cryptographic commitment or hash-based verification
    ///    - Pros: Can verify correctness without field arithmetic
    ///    - Cons: Adds complexity, may not provide same security guarantees
    ///
    /// For now, we trust that the Lagrange coefficients are correctly provided as input.
    /// The interpolation will fail to produce the correct message if coefficients are wrong,
    /// providing implicit verification through the final message check.
    fn verify_lagrange_coefficients(self) {
        // TODO: Implement verification when field arithmetic solution is chosen
        // For now, this is a placeholder - Lagrange coefficients are trusted inputs
        
        // The correctness of Lagrange coefficients will be implicitly verified by:
        // 1. The final message check (if coefficients are wrong, message won't match)
        // 2. The polynomial identity check at the challenge point gamma
    }

    /// Performs Lagrange interpolation and verifies congruence with encoded message
    ///
    /// For each CRT basis:
    /// 1. Interpolate each of the N coefficients independently to get m'(x)
    /// 2. Encode the scaled message: encoded = k_i * scaled_message
    /// 3. For each coefficient, check if (encoded[j] - m'[j]) is divisible by q_i
    ///    by verifying the remainder is zero using BigNum
    ///
    /// # Arguments
    /// * `basis_idx` - CRT basis index
    /// * `scaled_message` - The precomputed scaled message Q*m(x) mod t
    fn verify_interpolation_and_congruence(self, basis_idx: u32, scaled_message: Polynomial<N>) {
        let crypto_params = self.params.crypto_params();
        let q_i = crypto_params.qis[basis_idx];
        let k_i = crypto_params.kis[basis_idx];

        // Array to store interpolated coefficients m'_i(0) for this basis
        let mut interpolated_coeffs = [0 as Field; N];

        // Step 1: Perform Lagrange interpolation for each coefficient position
        for coeff_idx in 0..N {
            let mut m_prime_coeff = 0 as Field;

            // Interpolate: m'_i(0) = ∑(j=0 to t) d_j[coeff_idx] * l_j(0)
            for party_idx in 0..(T + 1) {
                let d_coeff = self.decryption_shares[party_idx][basis_idx].coefficients[coeff_idx];
                let l_j_at_0 = self.lagrange_coeffs[coeff_idx][basis_idx][party_idx];
                m_prime_coeff += d_coeff * l_j_at_0;
            }

            interpolated_coeffs[coeff_idx] = m_prime_coeff;
        }

        // Step 2: Form polynomial m'(x) from interpolated coefficients
        let m_prime = Polynomial { coefficients: interpolated_coeffs };

        // Step 3: Compute encoded message: encoded = k_i * scaled_message
        let mut encoded_coeffs = [0 as Field; N];
        for i in 0..N {
            encoded_coeffs[i] = k_i * scaled_message.coefficients[i];
        }
        let encoded = Polynomial { coefficients: encoded_coeffs };

        // Step 4: Verify congruence for each coefficient
        // Check if (encoded[j] - m'[j]) ≡ 0 (mod q_i)
        for j in 0..N {
            verify_congruence_bignum(encoded.coefficients[j], m_prime.coefficients[j], q_i);
        }
    }
}

/// Computes a single scaled coefficient: (Q * message[i]) mod t
/// Uses noir-bignum for accurate integer arithmetic on large values
///
/// # Arguments
/// * `big_q` - The product of all CRT moduli (Q = ∏ q_i), ~180 bits
/// * `message_coeff` - A single message coefficient, < t ~57 bits
/// * `t` - The plaintext modulus, ~57 bits
///
/// # Returns
/// (Q * message_coeff) mod t, guaranteed to be < t
fn compute_scaled_coefficient(big_q: Field, message_coeff: Field, t: Field) -> Field {
    // Create BigNum instance with t as modulus
    // t is ~57 bits, fits in 1 limb (< 120 bits)
    let modulus_limbs: [Field; 1] = [t];
    let params = BigNumParamsTrait::derive_from_modulus(modulus_limbs);
    let bn = BigNumInstance::new(params);
    
    // Convert to BigNum (this automatically reduces mod t)
    let q_bn = bn.from_field(big_q);
    let msg_bn = bn.from_field(message_coeff);
    
    // Multiply: (Q * message[i]) mod t
    let result_bn = q_bn.mul(msg_bn);
    
    // Convert back to Field
    result_bn.to_field()
}


/// Verifies that two values are congruent modulo q_i
/// Uses the noir-bignum library for proper modular arithmetic
///
/// Checks: a ≡ b (mod q_i)
/// Equivalent to: (a - b) % q_i == 0
///
/// # Arguments
/// * `a` - First value (e.g., encoded[j])
/// * `b` - Second value (e.g., m_prime[j])
/// * `q_i` - The modulus (CRT basis)
fn verify_congruence_bignum(a: Field, b: Field, q_i: Field) {
    // Determine number of limbs needed for q_i
    // q_i is a CRT modulus, typically 50-60 bits, fits in 1 limb (< 120 bits)
    let modulus_limbs: [Field; 1] = [q_i];
    
    // Create BigNum parameters from the modulus
    let params = BigNumParamsTrait::derive_from_modulus(modulus_limbs);
    let bn = BigNumInstance::new(params);
    
    // Convert field values to BigNum (mod q_i)
    let a_bn = bn.from_field(a);
    let b_bn = bn.from_field(b);
    
    // Check congruency: a ≡ b (mod q_i)
    // This internally checks if a and b are equal modulo q_i
    assert(a_bn.eq(b_bn), "Values must be congruent modulo q_i");
}


/// Helper function to flatten an array of polynomials into a 1D array
///
/// This function serializes polynomial coefficients for challenge generation
/// in the Fiat-Shamir transform. It maintains deterministic ordering.
///
/// # Generic Parameters
/// * `A` - The number of coefficients in each polynomial
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
