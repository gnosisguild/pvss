use std::field::bn254::{assert_lt, assert_gt};

/// Polynomial structure
pub struct Polynomial<let N: u32> {
    // Coefficients of the polynomial (Biggest degree at the first index)
    pub coefficients: [Field; N],
}

impl<let N: u32> Polynomial<N> {
    /// Creates a new polynomial
    pub fn new(coefficients: [Field; N]) -> Self {
        Polynomial { coefficients }
    }

    /// Evaluate a polynomial at a point in the field.
    pub fn eval(self, x: Field) -> Field {
        {
            let mut acc = self.coefficients[0];
            for i in 1..self.coefficients.len() {
                acc = acc * x + self.coefficients[i];
            }
            acc
        }
    }


    ///  Adds `upper_bound` to the coefficients of the polynomial and constrains them to be in the range `[0, 2 * upper_bound]`.
    pub fn range_check_1bound(self, upper_bound: u64) {
        let two_b = upper_bound * 2;
        let upper_bound_field = upper_bound as Field;
        let two_b_field = two_b as Field + 1 ;
        
        for i in 0..self.coefficients.len() {
            let shifted_coeff = self.coefficients[i] + upper_bound_field;
            assert_lt(shifted_coeff, two_b_field);
        }
    }

    /// Adds `-lower_bound` to the coefficients of the polynomial and constrains them to be in the range `[0, upper_bound - lower_bound]`.
    pub fn range_check_2bounds(self, upper_bound: u64, lower_bound: i64) {
        let shift = (-lower_bound) as u64; 
        let range_size = (upper_bound as i64 - lower_bound + 1) as u64;
        let shift_field = shift as Field;
        let range_size_field = range_size as Field;

        for i in 0..self.coefficients.len() {
            let shifted = self.coefficients[i] + shift_field;
            assert_lt(shifted, range_size_field);
        }
    }
}

#[test]
// Tests single bound check and double bounds check with a small Polynomial
fn test_polynomial_bounds() {
    let mut coeffs = [-16, 240, 242];

    let mut poly = Polynomial::new(coeffs);
    poly.range_check_1bound(242);
    poly.range_check_2bounds(242, -16);
}

#[test]
// Tests polynomial evaluation on a random small number
fn test_polynomial_eval() {
    let mut coeffs = [1, 2, 3];
    let mut poly = Polynomial::new(coeffs);

    let eval = poly.eval(3);
    assert_eq(eval as u64, 18);
}