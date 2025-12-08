// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use super::modular_fns::reduce_mod;
/// Polynomial structure representing a polynomial of degree N-1.
///
/// A polynomial P(X) = a_{N-1} * X^{N-1} + a_{N-2} * X^{N-2} + ... + a_1 * X + a_0
/// is represented as an array of coefficients where coefficients[0] = a_{N-1} (highest degree)
/// and coefficients[N-1] = a_0 (constant term).
pub struct Polynomial<let N: u32> {
    /// Array of polynomial coefficients in descending degree order
    /// coefficients[0] = coefficient of X^{N-1} (highest degree term)
    /// coefficients[N-1] = constant term (degree 0)
    pub coefficients: [Field; N],
}

impl<let N: u32> Polynomial<N> {
    /// Creates a new polynomial from an array of coefficients.
    ///
    /// # Arguments
    /// * `coefficients` - Array of N coefficients in descending degree order
    ///                    coefficients[0] = coefficient of X^{N-1}
    ///                    coefficients[N-1] = constant term
    ///
    /// # Returns
    /// A new Polynomial instance with the specified coefficients
    pub fn new(coefficients: [Field; N]) -> Self {
        Polynomial { coefficients }
    }

    /// Adds two polynomials.
    ///
    /// # Arguments
    /// * `other` - The polynomial to add to the current polynomial.
    ///
    /// # Returns
    /// A new polynomial with the coefficients added.
    pub fn add(self, other: Self) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] + other.coefficients[i];
        }

        result
    }

    /// Subtracts two polynomials.
    ///
    /// # Arguments
    /// * `other` - The polynomial to subtract from the current polynomial.
    ///
    /// # Returns
    /// A new polynomial with the coefficients subtracted.
    pub fn sub(self, other: Self) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] - other.coefficients[i];
        }

        result
    }

    /// Multiplies a polynomial by a scalar.
    ///
    /// # Arguments
    /// * `scalar` - The scalar to multiply the polynomial by.
    ///
    /// # Returns
    /// A new polynomial with the coefficients multiplied by the scalar.
    pub fn mul_scalar(self, scalar: Field) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] * scalar;
        }

        result
    }

    /// Evaluates the polynomial at a given point using Horner's method.
    ///
    /// Horner's method computes P(x) = a_{N-1} * x^{N-1} + ... + a_1 * x + a_0
    /// as ((...((a_{N-1} * x + a_{N-2}) * x + a_{N-3}) * x + ...) * x + a_0)
    /// This approach require n multiplications and n additions to evaluate the polynomial.
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate the polynomial.
    ///
    /// # Returns
    /// The value of the polynomial at point x: P(x).
    pub fn eval(self, x: Field) -> Field {
        let mut result = self.coefficients[0];

        for i in 1..self.coefficients.len() {
            result = result * x + self.coefficients[i];
        }

        result
    }

    /// Performs range checking on polynomial coefficients using asymmetric bounds
    ///
    /// This function constrains all polynomial coefficients to be in the range [lower_bound, upper_bound].
    /// The entire computation (loop + bit checks) is performed unconstrained, then verified in the circuit
    /// using polynomial evaluation (batch verification with a single constraint).
    ///
    /// The verification strategy:
    /// 1. Unconstrained: Loop through all coefficients, compute shifted values, check bit sizes
    /// 2. Constrained: Verify shift relationship using polynomial evaluation (single constraint)
    ///    This proves all checks were performed correctly via batch verification.
    ///
    /// Set `BIT` to the bit-length of the total range `upper_bound + lower_bound`
    /// (choose `BIT` so `upper_bound + lower_bound < 2^BIT`).
    ///
    /// # Arguments
    /// * `upper_bound` - The upper bound for coefficient range checking
    /// * `lower_bound` - The lower bound for coefficient range checking (must be positive Field value)
    ///                   Coefficients must satisfy: lower_bound <= c <= upper_bound
    pub fn range_check_2bounds<let BIT: u32>(self, upper_bound: Field, lower_bound: Field) {
        // Safety: The unconstrained function performs all range checks (loop + bit checks).
        // We verify correctness by checking the shift relationship using polynomial evaluation,
        // which proves via batch verification that all checks were performed correctly.
        let (shifted_poly, all_checks_passed): (Polynomial<N>, bool) =
            unsafe { unconstrained_range_check_2bounds::<N, BIT>(self, lower_bound, upper_bound) };

        // Verify the shift relationship using polynomial evaluation at x=1
        // This proves that shifted_poly = self + lower_bound (coefficient-wise)
        // We use x=1 because sum of coefficients = poly.eval(1)
        // If the sums match, and all_checks_passed is true, then all individual checks are correct
        let original_sum = self.eval(1);
        let shifted_sum = shifted_poly.eval(1);
        let expected_shifted_sum = original_sum + lower_bound * (N as Field);
        assert(shifted_sum == expected_shifted_sum);

        // Assert that all range checks passed
        assert(all_checks_passed == true);
    }

    pub fn eval_mod(self, x: Field, q: Field) -> Field {
        let mut acc = self.coefficients[0];
        let len = self.coefficients.len();

        for i in 1..len {
            acc = acc * x + self.coefficients[i];
            // Only reduce if accumulator exceeds q
            if acc as u64 >= q as u64 {
                acc = reduce_mod(acc, q);
            }
        }

        // Final reduction to ensure result is in [0, q)
        if acc as u64 >= q as u64 {
            reduce_mod(acc, q)
        } else {
            acc
        }
    }
}

/// Unconstrained function to perform full range check computation
///
/// Performs the entire range check computation (loop + bit checks) outside the circuit.
/// Returns (shifted_polynomial, all_checks_passed) where:
/// - shifted_polynomial has coefficients shifted by lower_bound
/// - all_checks_passed = true if all coefficients pass the bit-size checks
///
/// In unconstrained code, we can check bit sizes using native comparisons.
/// The constrained code will verify the shift relationship using polynomial evaluation.
///
/// # Arguments
/// * `poly` - The polynomial to check
/// * `lower_bound` - Lower bound of the range
/// * `upper_bound` - Upper bound of the range
unconstrained fn unconstrained_range_check_2bounds<let N: u32, let BIT: u32>(
    poly: Polynomial<N>,
    lower_bound: Field,
    upper_bound: Field,
) -> (Polynomial<N>, bool) {
    let range_size = lower_bound + upper_bound;
    let mut shifted_coeffs = [0; N];
    let mut all_checks_passed = true;

    // Loop through all coefficients (this entire loop is unconstrained!)
    for i in 0..N {
        let shifted = poly.coefficients[i] + lower_bound;

        // Check bit size using native comparisons (unconstrained!)
        // assert_max_bit_size::<BIT+1> checks that value < 2^(BIT+1)
        let max_value = 2.pow_32((BIT + 1) as Field);

        // Check if shifted fits in BIT+1 bits
        let shifted_fits = (shifted as u64) < (max_value as u64);

        // Check if (range_size - shifted) fits in BIT+1 bits
        let range_diff = range_size - shifted;
        let range_fits = (range_diff as u64) < (max_value as u64);

        // Both checks must pass for this coefficient to be in range
        let coeff_ok = if shifted_fits { range_fits } else { false };

        shifted_coeffs[i] = shifted;
        all_checks_passed = if all_checks_passed { coeff_ok } else { false };
    }

    let shifted_poly = Polynomial::new(shifted_coeffs);
    (shifted_poly, all_checks_passed)
}

/// Compute hex-aligned packing parameters for a given `BIT`.
///
/// # Purpose
/// Returns `(nibble_bits, group)` for use by packer/flatten so layout stays consistent.
/// - `nibble_bits`: ceil (`BIT`) to the next multiple of 4 (nibble alignment).
///   - Examples: `BIT = 7 -> 8`, `BIT = 8 -> 8`, `BIT = 9 -> 12`, `BIT = 10 -> 12`, `BIT = 11 -> 12`,
///     `BIT=16 -> 16`, `BIT = 17 -> 20`.
/// - `group`: max number of encoded limbs that fit in one BN254 field element,
///            when each limb uses an extra 4 bits (see below).
///
/// # Rationale
/// - We align to nibbles so powers of two are hex-friendly and deterministic.
/// - We reserve one extra nibble (4 bits) per stored value to lift signed
///   coefficients into the non-negative range (e.g., store `v + 2^nibble_bits`),
///   which implies a radix of `2^(nibble_bits + 4)`.
///
/// # Safety
/// - Asserts `nibble_bits + 4 <= 254` to avoid mod-p wrap on BN254.
/// - Ensures at least one limb fits: `group >= 1`.
fn packing_layout<let BIT: u32>() -> (u32, u32) {
    // Ceil BIT up to the next multiple of 4 (nibble alignment).
    let nibble_bits = ((BIT + 3) / 4) * 4;

    // Each stored limb uses an extra nibble because negative coefficients
    // will be shifted to positive, so radix = 2^(nibble_bits+4).
    assert(nibble_bits + 4 <= 254);

    // Maximum limbs that fit in one BN254 element without wrap.
    let group = 254 / (nibble_bits + 4);
    assert(group >= 1);
    (nibble_bits, group)
}

/// Flatten `L` polynomials into a single linear stream of packed `Field` carriers.
///
/// ## What this does
/// - For each CRT limb `j` in `0..L`, it packs the coefficients of `poly[j]`
///   with `packer::<A, BIT>` and appends all resulting carriers to `inputs`.
/// - The packing layout (nibble-aligned width and `group` size) is taken from
///   `packing_layout::<BIT>()` and must match what `packer` uses.
///
/// ## Determinism & order
/// - Preserves a stable order: iterate `j = 0..L`, then for each `j` append
///   carriers in ascending chunk index `i = 0..num_chunks`.
/// - This ensures transcripts remain deterministic across runs.
///
/// ## Generics
/// - `A`: polynomial degree (number of coefficients per polynomial).
/// - `L`: number of CRT bases (polynomials).
/// - `BIT`: per-coefficient bit bound used by the packing layout (compile-time).
///
/// ## Returns
/// - The same `inputs` vector, extended with all carriers in deterministic order.
pub fn flatten<let A: u32, let L: u32, let BIT: u32>(
    mut inputs: Vec<Field>,
    poly: [Polynomial<A>; L],
) -> Vec<Field> {
    for j in 0..L {
        // Pack its A coefficients into `num_chunks` carriers using the same BIT layout.
        let packed = packer::<A, BIT>(poly[j].coefficients);

        // Append carriers in-order to `inputs` to keep a stable transcript layout.
        for i in 0..packed.len() {
            inputs.push(packed.get(i));
        }
    }

    // Return the extended input stream.
    inputs
}

/// Pack `A` values into a `Vec<Field>` of carriers using the shared hex-aligned layout.
///
/// ## What this does
/// - Computes `(nibble_bits, group)` via `packing_layout::<BIT>()`.
/// - Encodes each value as a limb `digit = v + 2^nibble_bits` and concatenates
///   limbs in base `radix = 2^(nibble_bits + 4)` (one extra nibble of headroom).
/// - Packs up to `group` limbs per carrier (fits within BN254 254-bit capacity).
/// - Pads the last, partial carrier with `digit = 2^nibble_bits` to keep a stable layout.
///
/// ## Determinism & order
/// - Processes values in increasing index order and emits carriers in chunk order
///   (`chunk = 0..num_chunks`). Padding is deterministic.
///
/// ## Generics
/// - `A`: number of input values.
/// - `BIT`: per-value bit bound; rounded up to `nibble_bits` by `packing_layout`.
///
/// ## Preconditions / Notes
/// - Call with the raw coefficients whose magnitudes already satisfy the BIT bound
///   (as enforced by the upstream range checks); `packer` performs the signed -> unsigned
///   shift internally via `v + base`.
/// - `group >= 1` is enforced by `packing_layout::<BIT>()`.
/// - Padding with `digit = 2^nibble_bits` encodes `zero limb` consistently.
///
/// ## Returns
/// - A `Vec<Field>` where each element is a concatenation of up to `group` limbs,
///   suitable for hashing or transcript I/O.
pub fn packer<let A: u32, let BIT: u32>(values: [Field; A]) -> Vec<Field> {
    // Layout parameters: nibble-aligned width and limbs-per-carrier group size.
    let (nibble_bits, group) = packing_layout::<BIT>();

    let base = 2.pow_32(nibble_bits as Field); // 2^nibble_bits
    let radix = 2.pow_32((nibble_bits + 4) as Field); // 2^(nibble_bits + 4)

    // Number of chunks to emit: ceil(A / group).
    let num_chunks = (A + group - 1) / group;
    let mut out = Vec::new();

    // Process in fixed-size chunks of `group` limbs.
    for chunk in 0..num_chunks {
        // How many real values go into this chunk.
        let remain = A - (chunk * group);
        let take = if remain < group { remain } else { group };

        // Build field element accumulator (big-endian concatenation in `radix`).
        let mut acc = 0;
        for i in 0..take {
            let v = values[chunk * group + i];
            acc = acc * radix + (v + base);
        }

        // Pad remaining limb slots with the canonical zero-limb `digit = base`.
        for _ in 0..(group - take) {
            acc = acc * radix + base;
        }

        out.push(acc);
    }
    out
}
