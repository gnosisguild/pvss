use circuits::{
    crypto::pk_agg_trbfv::pk_agg_trbfv::{Params, TrbfvPublicKeyAggregation},
    math::polynomial::Polynomial,
};
fn main(
    params: Params<2>,
    pk0: [[Polynomial<512>; 2]; 5], // 5 honest parties
    pk1: [[Polynomial<512>; 2]; 5],
    pk0_agg: [Polynomial<512>; 2],
    pk1_agg: [Polynomial<512>; 2],
) {
    let circuit: TrbfvPublicKeyAggregation<512, 5, 2> =
        TrbfvPublicKeyAggregation::new(params, pk0, pk1, pk0_agg, pk1_agg);

    circuit.verify()
}
