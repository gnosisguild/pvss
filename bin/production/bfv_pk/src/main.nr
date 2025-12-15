use lib::configs::production::bfv::{
    BFV_PK_BIT_EEK, BFV_PK_BIT_R1, BFV_PK_BIT_R2, BFV_PK_BIT_SK, BFV_PK_CONFIGS, L, N,
};
use lib::core::bfv_pk::BfvPublicKey;
use lib::math::polynomial::Polynomial;

fn main(
    a: [Polynomial<N>; 2],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; 2],
    r2is: [Polynomial<N - 1>; 2],
    pk0is: [Polynomial<N>; 2],
    pk1is: [Polynomial<N>; 2],
) {
    let bfv_pk: BfvPublicKey<N, L, BFV_PK_BIT_EEK, BFV_PK_BIT_SK, BFV_PK_BIT_R1, BFV_PK_BIT_R2> =
        BfvPublicKey::new(BFV_PK_CONFIGS, a, eek, sk, r1is, r2is, pk0is, pk1is);
    bfv_pk.verify();
}
