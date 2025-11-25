use circuits::{crypto::greco::greco::Greco, math::polynomial::Polynomial};
use constants::set_bfv_8192_100::{CONSTANTS, N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R1, BIT_R2, BIT_P1, BIT_P2};

fn main(
    commitment_pk_ct: pub Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
) {
    let greco: Greco<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R1, BIT_R2, BIT_P1, BIT_P2> = Greco::new(
        CONSTANTS,
        commitment_pk_ct,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
        e0is,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    let is_greco_valid = greco.verify();
    assert(is_greco_valid);
}
