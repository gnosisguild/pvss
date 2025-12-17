use lib::configs::insecure::trbfv::{
    L, N, PK_TRBFV_BIT_EEK, PK_TRBFV_BIT_R1, PK_TRBFV_BIT_R2, PK_TRBFV_BIT_SK, PK_TRBFV_CONFIGS,
};
use lib::core::bfv_pk::BfvPublicKey;
use lib::math::polynomial::Polynomial;

fn main(
    a: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
) -> pub Field {
    let pk_trbfv: BfvPublicKey<N, L, PK_TRBFV_BIT_EEK, PK_TRBFV_BIT_SK, PK_TRBFV_BIT_R1, PK_TRBFV_BIT_R2> =
        BfvPublicKey::new(PK_TRBFV_CONFIGS, a, eek, sk, r1is, r2is, pk0is, pk1is);
    pk_trbfv.verify()
}
