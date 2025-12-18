use lib::configs::insecure::trbfv::{L, N, PK_AGG_TRBFV_CONFIGS};
use lib::core::trbfv_pk_agg::TrbfvPublicKeyAggregation;
use lib::math::polynomial::Polynomial;

/// Number of honest parties.
pub global H: u32 = 5;

fn main(
    pk0: [[Polynomial<N>; L]; H],
    pk1: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
    pk1_agg: [Polynomial<N>; L],
) {
    let pk_agg_trbfv: TrbfvPublicKeyAggregation<N, H, L> =
        TrbfvPublicKeyAggregation::new(PK_AGG_TRBFV_CONFIGS, pk0, pk1, pk0_agg, pk1_agg);

    pk_agg_trbfv.verify();
}
