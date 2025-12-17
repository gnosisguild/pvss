use lib::configs::production::trbfv::{L, N};
use lib::core::trbfv_pk_agg::TrbfvPublicKeyAggregation;
use lib::math::polynomial::Polynomial;

/// Honest parties.
pub global H: u32 = 5;

// TODO: missing configs!
fn main(
    pk0: [[Polynomial<N>; L]; H],
    pk1: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
    pk1_agg: [Polynomial<N>; L],
) {
    let pk_agg_trbfv: TrbfvPublicKeyAggregation<N, H, L> =
        TrbfvPublicKeyAggregation::new(pk0, pk1, pk0_agg, pk1_agg);
    pk_agg_trbfv.verify();
}
