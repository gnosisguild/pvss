use super::modular_fns::{add, div_mod, inv_mod, mul_mod, neg, reduce_mod, sub};
use super::polynomial::{flatten, Polynomial};

// ------------------------------ REDUCE_MOD TESTS ------------------------------

#[test]
fn test_reduce_mod_already_reduced() {
    let value = 42;
    let modulus = 100;
    let result = reduce_mod(value, modulus);
    assert(result == 42);
}

#[test]
fn test_reduce_mod_needs_reduction() {
    let value = 250;
    let modulus = 100;
    let result = reduce_mod(value, modulus);
    assert(result == 50);
}

#[test]
fn test_reduce_mod_exact_multiple() {
    let value = 300;
    let modulus = 100;
    let result = reduce_mod(value, modulus);
    assert(result == 0);
}

#[test]
fn test_reduce_mod_large_value() {
    let value = 123456789;
    let modulus = 1000;
    let result = reduce_mod(value, modulus);
    assert(result == 789);
}

// ------------------------------ ADD TESTS ------------------------------

#[test]
fn test_add_no_overflow() {
    let a = 30;
    let b = 40;
    let m = 100;
    let result = add(a, b, m);
    assert(result == 70);
}

#[test]
fn test_add_with_overflow() {
    let a = 60;
    let b = 50;
    let m = 100;
    let result = add(a, b, m);
    assert(result == 10); // (60 + 50) mod 100 = 10
}

#[test]
fn test_add_exact_modulus() {
    let a = 50;
    let b = 50;
    let m = 100;
    let result = add(a, b, m);
    assert(result == 0);
}

#[test]
fn test_add_with_zero() {
    let a = 42;
    let b = 0;
    let m = 100;
    let result = add(a, b, m);
    assert(result == 42);
}

// ------------------------------ SUB TESTS ------------------------------

#[test]
fn test_sub_no_underflow() {
    let a = 50;
    let b = 30;
    let m = 100;
    let result = sub(a, b, m);
    assert(result == 20);
}

#[test]
fn test_sub_with_underflow() {
    let a = 30;
    let b = 50;
    let m = 100;
    let result = sub(a, b, m);
    assert(result == 80); // (30 - 50 + 100) mod 100 = 80
}

#[test]
fn test_sub_equal_values() {
    let a = 42;
    let b = 42;
    let m = 100;
    let result = sub(a, b, m);
    assert(result == 0);
}

#[test]
fn test_sub_subtract_zero() {
    let a = 42;
    let b = 0;
    let m = 100;
    let result = sub(a, b, m);
    assert(result == 42);
}

// ------------------------------ MUL_MOD TESTS ------------------------------

#[test]
fn test_mul_mod_small_values() {
    let a = 6;
    let b = 7;
    let m = 100;
    let result = mul_mod(a, b, m);
    assert(result == 42);
}

#[test]
fn test_mul_mod_with_reduction() {
    let a = 12;
    let b = 15;
    let m = 100;
    let result = mul_mod(a, b, m);
    assert(result == 80); // 12 * 15 = 180, 180 mod 100 = 80
}

#[test]
fn test_mul_mod_result_zero() {
    let a = 5;
    let b = 20;
    let m = 100;
    let result = mul_mod(a, b, m);
    assert(result == 0); // 5 * 20 = 100, 100 mod 100 = 0
}

#[test]
fn test_mul_mod_with_zero() {
    let a = 42;
    let b = 0;
    let m = 100;
    let result = mul_mod(a, b, m);
    assert(result == 0);
}

#[test]
fn test_mul_mod_large_values() {
    let a = 123;
    let b = 456;
    let m = 1000;
    let result = mul_mod(a, b, m);
    assert(result == 88); // 123 * 456 = 56088, 56088 mod 1000 = 88
}

// ------------------------------ NEG TESTS ------------------------------

#[test]
fn test_neg_non_zero() {
    let val = 30;
    let m = 100;
    let result = neg(val, m);
    assert(result == 70); // 100 - 30 = 70
}

#[test]
fn test_neg_zero() {
    let val = 0;
    let m = 100;
    let result = neg(val, m);
    assert(result == 0); // Negation of 0 is 0, not m
}

#[test]
fn test_neg_large_modulus() {
    let val = 12345;
    let m = 1000000;
    let result = neg(val, m);
    assert(result == 987655); // 1000000 - 12345 = 987655
}

// ------------------------------ INV_MOD TESTS ------------------------------

#[test]
fn test_inv_mod_simple() {
    let val = 3;
    let m = 11;
    let result = inv_mod(val, m);
    // 3 * 4 = 12 = 1 (mod 11), so 3^(-1) = 4 (mod 11)
    assert(result == 4);
    // Verify: 3 * result = 1 (mod 11)
    assert(mul_mod(val, result, m) == 1);
}

#[test]
fn test_inv_mod_larger_prime() {
    let val = 7;
    let m = 13;
    let result = inv_mod(val, m);
    // Verify: 7 * result = 1 (mod 13)
    assert(mul_mod(val, result, m) == 1);
}

#[test]
fn test_inv_mod_with_result_verification() {
    let val = 5;
    let m = 17;
    let result = inv_mod(val, m);
    // Verify the inverse property
    let product = mul_mod(val, result, m);
    assert(product == 1);
}

#[test]
fn test_inv_mod_coprime_values() {
    let val = 9;
    let m = 23;
    let result = inv_mod(val, m);
    assert(mul_mod(val, result, m) == 1);
}

// ------------------------------ DIV_MOD TESTS ------------------------------

#[test]
fn test_div_mod_simple() {
    let a = 6;
    let b = 2;
    let m = 11;
    let result = div_mod(a, b, m);
    assert(result == 3); // 6 / 2 = 3
}

#[test]
fn test_div_mod_with_inverse() {
    let a = 7;
    let b = 3;
    let m = 11;
    let result = div_mod(a, b, m);
    // 3^(-1) mod 11 = 4 (since 3 * 4 = 12 = 1 mod 11)
    // 7 * 4 = 28 = 6 (mod 11)
    assert(result == 6);
    // Verify: result * b = a (mod m)
    assert(mul_mod(result, b, m) == a);
}

#[test]
fn test_div_mod_verification() {
    let a = 10;
    let b = 3;
    let m = 17;
    let result = div_mod(a, b, m);
    // Verify: result * b = a (mod m)
    assert(mul_mod(result, b, m) == reduce_mod(a, m));
}

#[test]
fn test_div_mod_larger_values() {
    let a = 250;
    let b = 7;
    let m = 97;
    let result = div_mod(a, b, m);
    // Verify: result * b = a (mod m)
    let a_reduced = reduce_mod(a, m); // 250 mod 100 = 50
    assert(mul_mod(result, b, m) == a_reduced);
}

// ------------------------------ INTEGRATION TESTS ------------------------------

#[test]
fn test_field_properties_additive_identity() {
    let a = 42;
    let m = 100;
    // a + 0 = a
    assert(add(a, 0, m) == a);
}

#[test]
fn test_field_properties_multiplicative_identity() {
    let a = 42;
    let m = 100;
    // a * 1 = a
    assert(mul_mod(a, 1, m) == a);
}

#[test]
fn test_field_properties_additive_inverse() {
    let a = 42;
    let m = 100;
    let neg_a = sub(0, a, m);
    // a + (-a) = 0
    assert(add(a, neg_a, m) == 0);
}

#[test]
fn test_field_properties_commutativity_add() {
    let a = 35;
    let b = 47;
    let m = 100;
    // a + b = b + a
    assert(add(a, b, m) == add(b, a, m));
}

#[test]
fn test_field_properties_commutativity_mul() {
    let a = 7;
    let b = 9;
    let m = 100;
    // a * b = b * a
    assert(mul_mod(a, b, m) == mul_mod(b, a, m));
}

#[test]
fn test_field_properties_associativity_add() {
    let a = 23;
    let b = 34;
    let c = 45;
    let m = 100;
    // (a + b) + c = a + (b + c)
    let left = add(add(a, b, m), c, m);
    let right = add(a, add(b, c, m), m);
    assert(left == right);
}

#[test]
fn test_field_properties_associativity_mul() {
    let a = 3;
    let b = 7;
    let c = 11;
    let m = 100;
    // (a * b) * c = a * (b * c)
    let left = mul_mod(mul_mod(a, b, m), c, m);
    let right = mul_mod(a, mul_mod(b, c, m), m);
    assert(left == right);
}

#[test]
fn test_field_properties_distributivity() {
    let a = 5;
    let b = 7;
    let c = 9;
    let m = 100;
    // a * (b + c) = (a * b) + (a * c)
    let left = mul_mod(a, add(b, c, m), m);
    let right = add(mul_mod(a, b, m), mul_mod(a, c, m), m);
    assert(left == right);
}
#[test]
fn test_division_multiplication_inverse() {
    let a = 35;
    let b = 7;
    let m = 97;
    let quotient = div_mod(a, b, m);
    let product = mul_mod(quotient, b, m);
    assert(product == reduce_mod(a, m));
}
#[test]
fn test_inverse_of_inverse() {
    let a = 7;
    let m = 11;
    // (a^(-1))^(-1) = a
    let inv_a = inv_mod(a, m);
    let inv_inv_a = inv_mod(inv_a, m);
    assert(inv_inv_a == a);
}

// ------------------------------ EDGE CASE TESTS ------------------------------

#[test]
fn test_operations_with_prime_modulus() {
    let m = 97; // Prime number
    let a = 42;
    let b = 13;

    // Test addition
    let sum = add(a, b, m);
    assert(sum == 55); // 42 + 13 = 55

    // Test subtraction
    let diff = sub(a, b, m);
    assert(diff == 29); // 42 - 13 = 29

    // Test multiplication
    let prod = mul_mod(a, b, m);
    assert(prod == 61); // (42 * 13) mod 97 = 546 mod 97 = 61

    // Test inverse: b * b^(-1) = 1 (mod m)
    let inv = inv_mod(b, m);
    assert(mul_mod(b, inv, m) == 1);

    // Test division: (a / b) * b = a (mod m)
    let quot = div_mod(a, b, m);
    assert(mul_mod(quot, b, m) == a);
}

#[test]
fn test_large_party_ids_scenario() {
    // Simulating party IDs in range [1, 100]
    let party_id_1 = 42;
    let party_id_2 = 73;
    let modulus = 288230376151711717; // ~58 bits

    // Operations that would be used in Lagrange coefficients
    let product = mul_mod(party_id_1, party_id_2, modulus);
    let diff = sub(party_id_2, party_id_1, modulus);

    assert(product == 3066);
    assert(diff == 31);
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

#[test]
fn test_flatten() {
    // Create test polynomials
    let poly1 = Polynomial::new([1, 2, 3]); // degree 2
    let poly2 = Polynomial::new([4, -16, 6]); // degree 2
    let poly3 = Polynomial::new([-7, 8, 9]); // degree 2

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = Vec::new();

    // Flatten the polynomials
    let result = flatten::<_, _, 4>(inputs, polynomials);

    // Verify the flattened coefficients are in the correct positions
    // Every value shifted 1 nibble incase of negative integers
    assert_eq(result.get(0), 0x11121310101010101010101010101010101010101010101010101010101010);
    assert_eq(result.get(1), 0x14001610101010101010101010101010101010101010101010101010101010); // -16 became 00 at  0x 14 00 16,
    assert_eq(result.get(2), 0x09181910101010101010101010101010101010101010101010101010101010); // -7 became 09 at 0x 09 18 19(16 - 7 = 9)
}

#[test]
fn test_flatten_big() {
    // Create test polynomials
    let poly1 = Polynomial::new([
        1791218451968394,
        21888242871839275222246405745257275088548364400416034343698198265248580087864,
        21888242871839275222246405745257275088548364400416034343698200542108324633466,
        5430119342984413,
        704811298945172,
        8901715723925099,
        21888242871839275222246405745257275088548364400416034343698203098124042812559,
        21888242871839275222246405745257275088548364400416034343698200215091693880034,
    ]);
    let poly2 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698200314078269634250,
        21888242871839275222246405745257275088548364400416034343698200967285641915872,
        2909990636858607,
        7896103832076587,
        2078397209533893,
        21888242871839275222246405745257275088548364400416034343698199792421452734531,
        614400389245817,
        8290314119277588,
    ]);
    let poly3 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698201373175279892906,
        21888242871839275222246405745257275088548364400416034343698201087241869723721,
        6768789983786188,
        635797784303388,
        7610153424227556,
        4633893206538324,
        2016269760615332,
        21888242871839275222246405745257275088548364400416034343698201007080554428142,
    ]);

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = Vec::new();

    // Flatten the polynomials
    let result = flatten::<_, _, 54>(inputs, polynomials);

    // Verify the flattened coefficients are in the correct positions
    // Every value shifted 1 nibble incase of negative integers

    // For the first index of result operation goes like this,

    // First four index of poly1
    // 1791218451968394,
    // 21888242871839275222246405745257275088548364400416034343698198265248580087864,
    // 21888242871839275222246405745257275088548364400416034343698200542108324633466,
    // 5430119342984413,

    // base + 1791218451968394 = 0x1065d1a8b8b718a
    // base - 5921327228407753 = 0xeaf69591f3b037 (negative coefficient shifted)
    // base - 3644467483862151 = 0xf30d604a3a9b79 (negative coefficient shifted)
    // base + 5430119342984413 = 0x1134aaa2e86ccdd
    assert_eq(result.get(0), 0x1065d1a8b8b718a0eaf69591f3b0370f30d604a3a9b791134aaa2e86ccdd);
    assert_eq(result.get(1), 0x1028105ab1b789411fa010339db66b0fc220f1326bc8e0f1e3f4cc1e02e1);
    assert_eq(result.get(2), 0x0f23dfbe7cd76c90f4901299312ddf10a569efe35acef11c0d76f005412b);
    assert_eq(result.get(3), 0x107624a8f605dc50f0638a368960421022ecb3cf36b7911d73ff2c27ec14);
    assert_eq(result.get(4), 0x0f6013a24e1b9a90f4fd2c158a08481180c2dba8af4cc10242413515171c);
    assert_eq(result.get(5), 0x11b0964eb898ce411076805680b85410729c962da53a40f4b44412d0f6ed);
}

#[test]
fn test_flatten_small() {
    // Create test polynomials
    let poly1 = Polynomial::new([712345, 104857, 999999, 500001, 123, 654321, 77]);
    let poly2 = Polynomial::new([1, 524287, 888888, 23456, 34567, 765432, 0]);
    let poly3 = Polynomial::new([444444, 333333, 222222, 111111, 987654, 246810, 13579]);

    let polynomials = [poly1, poly2, poly3];

    // Initialize target array with zeros
    let mut inputs = Vec::new();

    // Flatten the polynomials
    let result = flatten::<_, _, 20>(inputs, polynomials);

    assert_eq(result.get(0), 0x1ade991199991f423f17a12110007b19fbf110004d100000100000100000);
    assert_eq(result.get(1), 0x10000117ffff1d9038105ba01087071badf8100000100000100000100000);
    assert_eq(result.get(2), 0x16c81c15161513640e11b2071f120613c41a10350b100000100000100000);
}
#[test]

fn test_reduce_mod_small_values() {
    // Test reduce_mod with values already less than q
    let q = 7;

    // These should pass through unchanged
    assert(reduce_mod(0, q) == 0);
    assert(reduce_mod(1, q) == 1);
    assert(reduce_mod(6, q) == 6);

    // These need actual reduction
    assert(reduce_mod(7, q) == 0);
    assert(reduce_mod(8, q) == 1);
    assert(reduce_mod(13, q) == 6);
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

    // Now with reduce_mod
    let reduced = reduce_mod(acc, 7);
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
fn test_reduce_mod_function() {
    // Test reduce_mod directly first
    assert(reduce_mod(38, 7) == 3);
    assert(reduce_mod(6, 7) == 6);
    assert(reduce_mod(7, 7) == 0);
    assert(reduce_mod(14, 7) == 0);
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
