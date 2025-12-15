// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

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

    /// Performs range checking on polynomial coefficients using asymmetric bounds.
    ///
    /// This function constrains all polynomial coefficients to be in the range [lower_bound, upper_bound].
    /// It uses a shifting technique to handle negative numbers efficiently:
    /// 1. Shifts each coefficient by adding `lower_bound`: c' = c + lower_bound
    /// 2. Checks that shifted coefficients are in [0, upper_bound + lower_bound] using bit-size assertions
    /// 3. This ensures original coefficients are in [lower_bound, upper_bound]
    ///
    /// The function uses two bit-size checks per coefficient to ensure the value is within bounds:
    /// - `shifted_coefficient.assert_max_bit_size::<BIT + 1>()` ensures c' >= 0
    /// - `(range_size - shifted_coefficient).assert_max_bit_size::<BIT + 1>()` ensures c' <= range_size
    ///
    /// # Arguments
    /// * `upper_bound` - The upper bound for coefficient range checking
    /// * `lower_bound` - The lower bound for coefficient range checking
    ///                   Coefficients must satisfy: lower_bound <= c <= upper_bound
    ///
    /// # Generic Parameters
    /// * `BIT` - The bit-length of the total range `upper_bound - lower_bound`
    ///           (choose `BIT` so `upper_bound - lower_bound < 2^BIT`). Since all checked
    ///           values lie in `[0, upper_bound + lower_bound]`, they cannot exceed `BIT + 1` bits.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// the specified bounds.
    pub fn range_check_2bounds<let BIT: u32>(self, upper_bound: Field, lower_bound: Field) {
        let range_size = lower_bound + upper_bound;

        for i in 0..self.coefficients.len() {
            let shifted_coefficient = self.coefficients[i] + lower_bound;

            shifted_coefficient.assert_max_bit_size::<BIT + 1>();
            (range_size - shifted_coefficient).assert_max_bit_size::<BIT + 1>();
        }
    }
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
fn test_polynomial_eval_zero() {
    let coeffs = [1, -2, 1]; // x^2 - 2x + 1 = (x-1)^2
    let poly = Polynomial::new(coeffs);

    let x = 1; // evaluate at x = 1, should be 0
    let result = poly.eval(x);

    assert_eq(result, 0);
}

#[test]
fn test_polynomial_bounds() {
    let coeffs = [-16, 240, 242];
    let poly = Polynomial::new(coeffs);

    // Test double bounds check - constrains to [-240, 242]
    poly.range_check_2bounds::<8>(242, 240);
}

#[test(should_fail_with = "assert_max_bit_size")]
fn test_polynomial_out_of_bounds_coefficients() {
    let coeffs = [-100];
    let poly = Polynomial::new(coeffs);

    // Test double bounds check - constrains to [-98, 99]
    // Should fail because -100 is out of bounds.
    poly.range_check_2bounds::<7>(99, 98);
}
