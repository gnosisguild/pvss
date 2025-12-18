use lib::configs::production::bfv::{
    DEC_BFV_BIT_CT, DEC_BFV_BIT_MSG, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_S, DEC_BFV_BIT_U,
    DEC_BFV_CONFIGS, L_PRIME, L_TRBFV, N,
};
use lib::core::bfv_dec::BfvDec;
use lib::math::polynomial::Polynomial;

/// Number of honest parties.
pub global H: u32 = 3;

fn main(
    expected_sk_commitment: Field,
    honest_c0: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    honest_c1: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    s: Polynomial<N>,
    u_i: [[Polynomial<N>; L_PRIME]; L_TRBFV],
    r_1: [[Polynomial<(2 * N) - 1>; L_PRIME]; L_TRBFV],
    r_2: [[Polynomial<N - 1>; L_PRIME]; L_TRBFV],
    u_global: [Polynomial<N>; L_TRBFV],
    crt_quotients: [[Polynomial<N>; L_PRIME]; L_TRBFV],
    message: [Polynomial<N>; L_TRBFV],
) -> pub Field {
    let dec_bfv: BfvDec<N, H, L_TRBFV, L_PRIME, DEC_BFV_BIT_CT, DEC_BFV_BIT_S, DEC_BFV_BIT_U, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_MSG> = BfvDec::new(
        DEC_BFV_CONFIGS,
        expected_sk_commitment,
        honest_c0,
        honest_c1,
        s,
        u_i,
        r_1,
        r_2,
        u_global,
        crt_quotients,
        message,
    );

    dec_bfv.verify()
}
