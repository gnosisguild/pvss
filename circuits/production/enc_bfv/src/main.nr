use e3_lib::configs::production::bfv::{
    ENC_BFV_BIT_CT, ENC_BFV_BIT_E0, ENC_BFV_BIT_E1, ENC_BFV_BIT_K, ENC_BFV_BIT_P1, ENC_BFV_BIT_P2,
    ENC_BFV_BIT_PK, ENC_BFV_BIT_R1, ENC_BFV_BIT_R2, ENC_BFV_BIT_U, ENC_BFV_CONFIGS, L, N,
};
use e3_lib::core::greco::Greco;
use e3_lib::math::polynomial::Polynomial;

fn main(
    pk_commitment: pub Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
) {
    let greco: Greco<N, L, ENC_BFV_BIT_PK, ENC_BFV_BIT_CT, ENC_BFV_BIT_U, ENC_BFV_BIT_E0, ENC_BFV_BIT_E1, ENC_BFV_BIT_K, ENC_BFV_BIT_R1, ENC_BFV_BIT_R2, ENC_BFV_BIT_P1, ENC_BFV_BIT_P2> = Greco::new(
        ENC_BFV_CONFIGS,
        pk_commitment,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e0is,
        e0_quotients,
        e1,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    let is_greco_valid = greco.verify();
    assert(is_greco_valid);
}
