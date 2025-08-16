/// `N` is the degree of the cyclotomic polynomial defining the ring `Rq = Zq[X]/(X^N + 1)` (`l` in the pvw encryption )
pub global N: u32 = 8;
/// `L` is the number of moduli
pub global L: u32 = 2;
/// The coefficients of the polynomial `e` should exist in the interval `[-E_BOUND, E_BOUND]` where `E_BOUND` is the upper bound of the gaussian distribution with Sigma = 3.2.
pub global E1_BOUND: u64 = 100;
pub global E2_BOUND: u64 = 100;
pub global SK_BOUND: u64 = 9;
/// List of scalars `qis` such that `qis[i]` is the modulus of the i-th CRT basis of `q` (ciphertext space modulus).
pub global QIS: [Field; 2] = [4503599625535489, 4503599626321921];
/// The coefficients of the polynomials `r1is` should exist in the interval `[R1_LOW_BOUNDS[i], R1_UP_BOUNDS[i]]` where R1_LOW_BOUNDS is equal to $\frac{\frac{-(t - 1)}{2} \cdot |K_{0,i}| - (N \cdot B +2) \cdot \frac{q_i - 1}{2} + B}{q_i}` and `R1_UP_BOUNDS[i]` is equal to `$\frac{\frac{(t - 1)}{2} \cdot |K_{0,i}| + (N \cdot +2) \cdot \frac{q_i - 1}{2} + B}{q_i}` .
pub global R1_LOW_BOUNDS: [i64; 2] = [-9729, -9729];
pub global R1_UP_BOUNDS: [u64; 2] = [9729, 9729];
/// The coefficients of the polynomials `r2is` should exist in the interval `[-R2_BOUND[i], R2_BOUND[i]]` where `R2_BOUND[i]` is equal to `(qi-1)/2`.
pub global R2_BOUNDS: [u64; 2] = [2251799812767744, 2251799813160960];
// For c1 quotients
pub global ENCRYPTION_R1_LOW_BOUNDS: [i64; 2] = [-2251799812767744, -2251799813160960];
pub global ENCRYPTION_R1_UP_BOUNDS: [u64; 2] = [2251799812767744, 2251799813160960];
pub global ENCRYPTION_R2_BOUNDS: [u64; 2] = [2251799812767744, 2251799813160960];

// For c2 quotients (potentially different values)
pub global ENCRYPTION_S1_UP_BOUNDS = [9729, 9729];
pub global ENCRYPTION_S1_LOW_BOUNDS: [i64; 2] = [-9729, -9729];
pub global ENCRYPTION_S2_BOUNDS = [2251799812767744, 2251799813160960];
/// Security dimension in PVW encryption
pub global K: u32 = 2;
pub global N_PARTIES: u32 = 3;

/// Size of the payload.
pub global SIZE: u32 = 28668;
/// Constant value for the SAFE sponge algorithm.
pub global TAG: Field = 5380324561195082;
