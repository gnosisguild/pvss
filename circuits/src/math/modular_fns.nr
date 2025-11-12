/// Modular arithmetic operations for u128 values

// ------------------------------ ARITHMETIC FUNCTIONS ------------------------------

/// Negates a value modulo m: returns (m - val) mod m
pub fn neg(val: Field, m: Field) -> Field {
    //Safety: __neg is safe because we verify val + result = 0 (mod m) below
    let result = unsafe { __neg(val, m) };

    // Verify: val + result = 0 (mod m)
    // Special case: if val = 0, result should be 0
    if val == 0 {
        assert(result == 0, "Negation of zero should be zero");
    } else {
        assert(val + result == m, "Negation verification failed");
    }

    result
}

/// Adds two values with modular reduction
pub fn add(lhs: Field, rhs: Field, m: Field) -> Field {
    reduce_mod(lhs + rhs, m)
}

/// Subtracts two values with modular reduction
pub fn sub(lhs: Field, rhs: Field, m: Field) -> Field {
    //Safety: __sub_with_underflow is safe because we verify the subtraction equation below
    let (result, underflow) = unsafe { __sub_with_underflow(lhs, rhs, m) };

    // Verify the subtraction
    if underflow {
        assert(lhs + m == rhs + result, "Subtraction with underflow verification failed");
    } else {
        assert(lhs == rhs + result, "Subtraction verification failed");
    }

    result
}

/// Multiplies two values with modular reduction
pub fn mul_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    reduce_mod(lhs * rhs, m)
}

/// Computes modular inverse using Fermat's Little Theorem
pub fn inv_mod(val: Field, m: Field) -> Field {
    //Safety: __inv_mod is safe because we verify val * result = 1 (mod m) below
    let result = unsafe { __inv_mod(val, m) };

    // Verify: val * result = 1 (mod m)
    assert(mul_mod(val, result, m) == 1, "Inverse verification failed");

    result
}

/// Computes: lhs * rhs^(-1) mod m
pub fn div_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    //Safety: __div_mod is safe because we verify result * rhs = lhs (mod m) below
    let result = unsafe { __div_mod(lhs, rhs, m) };

    // Verify: (result * rhs) mod m == lhs mod m
    assert(
        mul_mod(result, rhs, m) == reduce_mod(lhs, m),
        "Division verification failed: result * rhs ≠ lhs (mod m)",
    );

    result
}

/// Reduces a value modulo m
pub fn reduce_mod(value: Field, q: Field) -> Field {
    //Safety: __compute_mod_reduction is safe to call here because we assert the properties of the output
    let (quotient, remainder) = unsafe { __compute_mod_reduction(value, q) };
    assert(remainder as u128 < q as u128); // Ensure remainder is in [0, q)
    assert(value == quotient * q + remainder); // Verify the reduction is correct
    remainder
}

// ------------------------------ UNCONSTRAINED FUNCTIONS ------------------------------

/// Compute quotient and remainder for value mod q (unconstrained)
pub unconstrained fn __compute_mod_reduction(value: Field, q: Field) -> (Field, Field) {
    let value_u128 = value as u128;
    let q_u128 = q as u128;

    let quotient_u128 = value_u128 / q_u128;
    let remainder_u128 = value_u128 % q_u128;

    (quotient_u128 as Field, remainder_u128 as Field)
}

unconstrained fn __neg(val: Field, m: Field) -> Field {
    if val == 0 {
        0
    } else {
        m - val
    }
}

unconstrained fn __sub_with_underflow(lhs: Field, rhs: Field, m: Field) -> (Field, bool) {
    let lhs_u128 = lhs as u128;
    let rhs_u128 = rhs as u128;
    let m_u128 = m as u128;

    let underflow = lhs_u128 < rhs_u128;
    let result = if underflow {
        (lhs_u128 + m_u128 - rhs_u128) as Field
    } else {
        (lhs_u128 - rhs_u128) as Field
    };
    (result, underflow)
}

unconstrained fn __mul_with_quotient(lhs: Field, rhs: Field, m: Field) -> (Field, Field) {
    // For u128 values, product can overflow Field
    // But since our values are small (party IDs <= 100), this is safe
    let product = lhs * rhs;
    __compute_mod_reduction(product, m)
}

unconstrained fn __inv_mod(val: Field, m: Field) -> Field {
    // by Fermat's Little Theorem: val^(m-1)= 1 mod m
    __pow_mod(val, m - 2, m)
}

unconstrained fn __div_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    let rhs_inv = __inv_mod(rhs, m);
    __mul_mod(lhs, rhs_inv, m)
}

unconstrained fn __pow_mod(base: Field, exp: Field, m: Field) -> Field {
    let mut result = 1 as Field;
    let (_, base_mod) = __compute_mod_reduction(base, m);
    let mut current_base = base_mod;
    let mut e = exp as u128;

    while e > 0 {
        if (e % 2) == 1 {
            result = __mul_mod(result, current_base, m);
        }
        current_base = __mul_mod(current_base, current_base, m);
        e = e / 2;
    }

    result
}

unconstrained fn __mul_mod(lhs: Field, rhs: Field, m: Field) -> Field {
    let (_, r) = __mul_with_quotient(lhs, rhs, m);
    r
}
