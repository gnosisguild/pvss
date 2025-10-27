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

    ///  Adds `upper_bound` to the coefficients of the polynomial and constrains them to be in the range `[0, 2 * upper_bound]`.
    pub fn range_check_1bound(self, upper_bound: u64) {
        let comp_value = (2 * upper_bound) as Field;
        for i in 0..self.coefficients.len() {
            let shifted_coeff = self.coefficients[i] + upper_bound as Field;
            shifted_coeff.assert_max_bit_size::<66>();
            (comp_value - shifted_coeff).assert_max_bit_size::<66>();
        }
    }

    /// Adds `-lower_bound` to the coefficients of the polynomial and constrains them to be in the range `[0, upper_bound - lower_bound]`.
    pub fn range_check_2bounds(self, upper_bound: u64, lower_bound: i64) {
        let value_shift = (-1 * lower_bound) as u64 as Field;
        let comp_value = value_shift + upper_bound as Field;
        for i in 0..self.coefficients.len() {
            let shifted_coeff = self.coefficients[i] + value_shift;
            shifted_coeff.assert_max_bit_size::<66>();
            (comp_value - shifted_coeff).assert_max_bit_size::<66>();
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
/// Flattens an array of polynomials into a 1D array of Field elements.
///
/// This helper function serializes polynomial coefficients maintaining a deterministic
/// ordering of coefficients to ensure reproducible challenge values.
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
/// A tuple containing:
/// * The updated inputs array with flattened coefficients
/// * The new offset position after flattening
pub fn flatten_vector<let A: u32, let L: u32, let SIZE: u32>(
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

/// Flattens a matrix of polynomials into a 1D array of Field elements.
///
/// This helper function serializes polynomial coefficients from a matrix maintaining a deterministic
/// ordering of coefficients to ensure reproducible challenge values.
///
/// # Generic Parameters
/// * `ROWS` - The number of rows in the matrix
/// * `COLS` - The number of columns in the matrix
/// * `N` - The degree of each polynomial in the matrix
/// * `SIZE` - The total size of the target array
///
/// # Arguments
/// * `inputs` - The target array to store flattened coefficients
/// * `matrix` - Matrix of polynomials to flatten
/// * `offset` - Starting position in the inputs array
///
/// # Returns
/// A tuple containing:
/// * The updated inputs array with flattened coefficients
/// * The new offset position after flattening
pub fn flatten_matrix<let ROWS: u32, let COLS: u32, let N: u32, let SIZE: u32>(
    mut inputs: [Field; SIZE],
    matrix: Matrix<ROWS, COLS, N>,
    mut offset: u32,
) -> ([Field; SIZE], u32) {
    for j in 0..ROWS {
        for i in 0..COLS {
            for k in 0..N {
                inputs[k + offset] = matrix[j][i].coefficients[k];
            }
            offset += N;
        }
    }

    (inputs, offset)
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
    poly.range_check_1bound(242);

    // Test double bounds check
    poly.range_check_2bounds(242, -16);
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
