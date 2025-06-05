/// `N` is the degree of the cyclotomic polynomial defining the ring `Rq = Zq[X]/(X^N + 1)`.
pub global N: u32 = 1024;
/// `L` is the dimension size of the polynomials.
pub global L: u32 = 2;
/// The coefficients of the polynomial `e` should exist in the interval `[-E_BOUND, E_BOUND]` where `E_BOUND` is the upper bound of the gaussian distribution with Sigma = 3.2.
pub global EEK_BOUND: u64 = 19;
pub global SK_BOUND: u64 = 9;
/// List of scalars `qis` such that `qis[i]` is the modulus of the i-th CRT basis of `q` (ciphertext space modulus).
pub global QIS: [Field; 2] = [4503599625535489, 4503599626321921];
