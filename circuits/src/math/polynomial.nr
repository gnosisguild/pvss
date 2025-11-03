/// Polynomial structure
pub struct Polynomial<let N: u32> {
    // Coefficients of the polynomial (Biggest degree at the first index)
    pub coefficients: [Field; N],
}

// Matrix type representing a 2D array of polynomials
// ROWS x COLS matrix where each entry is a polynomial of degree N
pub type Matrix<let ROWS: u32, let COLS: u32, let N: u32> = [[Polynomial<N>; COLS]; ROWS];

// Vector type representing a 1D array of polynomials
// SIZE vector where each entry is a polynomial of degree N
pub type Vector<let SIZE: u32, let N: u32> = [Polynomial<N>; SIZE];

impl<let N: u32> Polynomial<N> {
    /// Creates a new polynomial
    pub fn new(coefficients: [Field; N]) -> Self {
        Polynomial { coefficients }
    }

    /// Evaluate a polynomial at a point in the field.
    pub fn eval(self, x: Field) -> Field {
        let mut acc = self.coefficients[0];
        for i in 1..self.coefficients.len() {
            acc = acc * x + self.coefficients[i];
        }
        acc
    }
    pub fn eval_mod(self, x: Field, q: Field) -> Field {
        let mut acc = self.coefficients[0];
        let len = self.coefficients.len();

        let x_u64 = x as u64;

        // Adaptive reduction based on x value
        let reduction_interval = if x_u64 < 64 {
            20 // Safe for x < 64
        } else if x_u64 < 512 {
            15 // Safe for x < 512
        } else {
            12 // Safe for x up to 1000
        };

        for i in 1..len {
            acc = acc * x + self.coefficients[i];

            if i % reduction_interval == 0 {
                acc = mod_reduce(acc, q);
            }
        }

        mod_reduce(acc, q)
    }

    /// Performs range checking on polynomial coefficients using a symmetric bound.
    ///
    /// This function constrains all polynomial coefficients to be in the range [-upper_bound, upper_bound].
    /// The implementation uses a clever shifting technique to avoid negative numbers in the range check:
    /// 1. Shifts each coefficient by adding upper_bound: c' = c + upper_bound
    /// 2. Checks that shifted coefficients are in [0, 2*upper_bound]
    /// 3. This ensures original coefficients are in [-upper_bound, upper_bound]
    ///
    /// Set `BIT` to the bit-length of `upper_bound` (i.e., choose `BIT` so `upper_bound < 2^BIT`).
    /// Because all checked values lie in `[0, 2*upper_bound]`, they cannot exceed `BIT + 1` bits; hence the
    /// `assert_max_bit_size::<BIT + 1>()` checks.
    ///
    /// # Arguments
    /// * `upper_bound` - The symmetric bound for coefficient range checking
    ///                   Coefficients must satisfy: -upper_bound <= c <= upper_bound
    pub fn range_check_1bound<let BIT: u32>(self, upper_bound: u64) {
        let shifted_bound = (upper_bound as Field) + (upper_bound as Field);

        for i in 0..self.coefficients.len() {
            let shifted_coefficient = self.coefficients[i] + upper_bound as Field;

            shifted_coefficient.assert_max_bit_size::<BIT + 1>();
            (shifted_bound - shifted_coefficient).assert_max_bit_size::<BIT + 1>();
        }
    }

    /// Performs range checking on polynomial coefficients using asymmetric bounds
    ///
    /// This function constrains all polynomial coefficients to be in the range [lower_bound, upper_bound].
    /// Similar to range_check_1bound, it uses a shifting technique to avoid negative numbers:
    /// 1. Shifts each coefficient by adding -lower_bound: c' = c - lower_bound
    /// 2. Checks that shifted coefficients are in [0, upper_bound - lower_bound]
    /// 3. This ensures original coefficients are in [lower_bound, upper_bound]
    ///
    /// Set `BIT` to the bit-length of the total range `upper_bound - lower_bound`
    /// (choose `BIT` so `upper_bound - lower_bound < 2^BIT`). Since all checked values lie in
    /// `[0, upper_bound - lower_bound]`, they cannot exceed `BIT + 1` bits, which is
    /// why we use `assert_max_bit_size::<BIT + 1>()`.
    ///
    /// # Arguments
    /// * `upper_bound` - The upper bound for coefficient range checking
    /// * `lower_bound` - The lower bound for coefficient range checking (can be negative)
    ///                   Coefficients must satisfy: lower_bound <= c <= upper_bound
    pub fn range_check_2bounds<let BIT: u32>(self, upper_bound: u64, lower_bound: i64) {
        let shifted_amount = (lower_bound * -1) as u64 as Field;
        let range_size = shifted_amount + upper_bound as Field;

        for i in 0..self.coefficients.len() {
            let shifted_coefficient = self.coefficients[i] + shifted_amount;

            shifted_coefficient.assert_max_bit_size::<BIT + 1>();
            (range_size - shifted_coefficient).assert_max_bit_size::<BIT + 1>();
        }
    }
}

pub fn mod_reduce(value: Field, q: Field) -> Field {
    //Safety: compute_mod_reduction is safe to call here because we assert the properties of the output
    let (quotient, remainder) = unsafe { compute_mod_reduction(value, q) };
    assert(remainder as u64 < q as u64); // Ensure remainder is in [0, q)
    assert(value == quotient * q + remainder); // Verify the reduction is correct
    remainder
}

/// Compute quotient and remainder for value mod q (unconstrained)
pub unconstrained fn compute_mod_reduction(value: Field, q: Field) -> (Field, Field) {
    // Convert to u64 for proper integer division
    let value_u64 = value as u64;
    let q_u64 = q as u64;

    let quotient_u64 = value_u64 / q_u64;
    let remainder_u64 = value_u64 % q_u64;

    (quotient_u64 as Field, remainder_u64 as Field)
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
pub fn flatten_vector<let A: u32, let L: u32, let BIT: u32>(
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

pub fn flatten_matrix<let ROWS: u32, let COLS: u32, let N: u32, let BIT: u32>(
    mut inputs: Vec<Field>,
    matrix: Matrix<ROWS, COLS, N>,
) -> Vec<Field> {
    for j in 0..ROWS {
        for i in 0..COLS {
            let packed = packer::<N, BIT>(matrix[j][i].coefficients);
            for k in 0..packed.len() {
                inputs.push(packed.get(k));
            }
        }
    }

    inputs
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

#[test]
fn test_polynomial_eval() {
    let coeffs = [1, 2, 3]; // represents 1x^2 + 2x + 3
    let poly = Polynomial::new(coeffs);

    let x = 2; // evaluate at x = 2
    let result = poly.eval(x);
    // (1 * 2^2) + (2 * 2) + 3 = 4 + 4 + 3 = 11
    assert_eq(result, 11);
}

#[test]
fn test_polynomial_bounds() {
    let coeffs = [-16, 240, 242];
    let poly = Polynomial::new(coeffs);

    // Test single bound check
    poly.range_check_1bound::<9>(242);

    // Test double bounds check
    poly.range_check_2bounds::<9>(242, -16);
}

#[test]
fn test_polynomial_eval_zero() {
    let coeffs = [1, -2, 1]; // x^2 - 2x + 1 = (x-1)^2
    let poly = Polynomial::new(coeffs);

    let x = 1; // evaluate at x = 1, should be 0
    let result = poly.eval(x);
    assert_eq(result, 0);
}

#[test]
fn test_polynomial_eval_large() {
    let coeffs = [1000000, -500000, 250000]; // large coefficients
    let poly = Polynomial::new(coeffs);

    let x = 2;
    let result = poly.eval(x);
    // 1000000*2^2 - 500000*2 + 250000 = 4000000 - 1000000 + 250000 = 3250000
    assert_eq(result, 3250000);
}

#[test]

fn test_mod_reduce_small_values() {
    // Test mod_reduce with values already less than q
    let q = 7;

    // These should pass through unchanged
    assert(mod_reduce(0, q) == 0);
    assert(mod_reduce(1, q) == 1);
    assert(mod_reduce(6, q) == 6);

    // These need actual reduction
    assert(mod_reduce(7, q) == 0);
    assert(mod_reduce(8, q) == 1);
    assert(mod_reduce(13, q) == 6);
}

#[test]
fn test_eval_mod_step_by_step() {
    // p(x) = x + 1 at x=5, mod 7
    // Step by step: acc = 1, then acc = 1*5 + 1 = 6
    let poly = Polynomial::new([1, 1]);

    // Manually compute
    let mut acc = 1; // coefficients[0]
    acc = acc * 5 + 1; // = 6
    assert(acc == 6);

    // Now with mod_reduce
    let reduced = mod_reduce(acc, 7);
    assert(reduced == 6);

    // Now test the actual function
    let result = poly.eval_mod(5, 7);
    assert(result == 6);
}
#[test]
fn test_eval_mod_simple() {
    // Test without initial reduction - simple case
    // p(x) = x + 1 at x=5, mod 7
    // Expected: (5 + 1) mod 7 = 6
    let poly1 = Polynomial::new([1, 1]);
    let result1 = poly1.eval_mod(5, 7);
    assert(result1 == 6);

    // Test: p(x) = 2x + 3 at x=5, mod 7
    // Expected: (10 + 3) mod 7 = 13 mod 7 = 6
    let poly2 = Polynomial::new([2, 3]);
    let result2 = poly2.eval_mod(5, 7);
    assert(result2 == 6);
}

#[test]
fn test_eval_mod_degree_2() {
    // p(x) = x^2 + 2x + 3 at x=5, mod 7
    // Using Horner's method: ((1)*5 + 2)*5 + 3 = (5+2)*5 + 3 = 7*5 + 3 = 35 + 3 = 38
    // 38 mod 7 = 3 (since 38 = 5*7 + 3)
    let poly = Polynomial::new([1, 2, 3]);
    let result = poly.eval_mod(5, 7);
    assert(result == 3);
}

#[test]
fn test_mod_reduce_function() {
    // Test mod_reduce directly first
    assert(mod_reduce(38, 7) == 3);
    assert(mod_reduce(6, 7) == 6);
    assert(mod_reduce(7, 7) == 0);
    assert(mod_reduce(14, 7) == 0);
}

#[test]
fn test_eval_vs_eval_mod() {
    // Compare eval and eval_mod for small values where no reduction should occur
    let poly = Polynomial::new([1, 2, 3]);
    let x = 2;
    let q = 1000; // Large enough that no reduction happens

    let result_normal = poly.eval(x);
    let result_mod = poly.eval_mod(x, q);

    // They should be equal: (1)*2 + 2)*2 + 3 = (2+2)*2 + 3 = 4*2 + 3 = 11
    assert(result_normal == 11);
    assert(result_mod == 11);
}
#[test]
fn test_eval_mod() {
    // Test 1: Simple polynomial x^2 + 2x + 3 at x=5, mod 7
    // Expected: (25 + 10 + 3) mod 7 = 38 mod 7 = 3
    let poly1 = Polynomial::new([1, 2, 3]);
    let result1 = poly1.eval_mod(5, 7);
    assert(result1 == 3);

    // Test 2: Higher degree polynomial, mod small prime
    // p(x) = x^3 + x^2 + x + 1 at x=2, mod 11
    // Expected: (8 + 4 + 2 + 1) mod 11 = 15 mod 11 = 4
    let poly2 = Polynomial::new([1, 1, 1, 1]);
    let result2 = poly2.eval_mod(2, 11);
    assert(result2 == 4);

    // Test 3: Polynomial with larger coefficients
    // p(x) = 100x^2 + 50x + 25 at x=10, mod 73
    // Expected: (10000 + 500 + 25) mod 73 = 10525 mod 73 = 13
    let poly3 = Polynomial::new([100, 50, 25]);
    let result3 = poly3.eval_mod(10, 73);
    assert(result3 == 13);

    // Test 4: Result should be less than modulus
    let poly4 = Polynomial::new([5, 3, 7]);
    let q = 17;
    let result4 = poly4.eval_mod(4, q);
    assert(result4 as u64 < q as u64);

    // Test 5: Compare with regular eval for small values
    let poly5 = Polynomial::new([1, 2, 1]);
    let x = 3;
    let q = 1000;
    let result5 = poly5.eval_mod(x, q);
    let expected5 = poly5.eval(x);
    assert(result5 == expected5);

    // Test 6: Zero polynomial
    let poly6 = Polynomial::new([0, 0, 0]);
    let result6 = poly6.eval_mod(100, 13);
    assert(result6 == 0);
}
