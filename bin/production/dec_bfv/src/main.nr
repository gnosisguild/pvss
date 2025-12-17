use lib::configs::production::bfv::{
    DEC_BFV_BIT_CT, DEC_BFV_BIT_NOISE, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_S, DEC_BFV_BIT_U,
    DEC_BFV_CONFIGS, L, N,
};
use lib::core::bfv_dec::BfvDec;
use lib::math::polynomial::Polynomial;

/// Honest parties.
pub global H: u32 = 5;

// TODO: needs update
fn main(
    honest_c0: [[Polynomial<N>; L]; H],
    honest_c1: [[Polynomial<N>; L]; H],
    sum_c0: [Polynomial<N>; L],
    sum_c1: [Polynomial<N>; L],
    s: [Polynomial<N>; L],
    u_i: [Polynomial<N>; L],
    r_1: [Polynomial<(2 * N) - 1>; L],
    r_2: [Polynomial<N - 1>; L],
    u_global: Polynomial<N>,
    crt_quotients: [Polynomial<N>; L],
    message: Polynomial<N>,
) {
    let dec_bfv: BfvDec<N, H, L, DEC_BFV_BIT_CT, DEC_BFV_BIT_S, DEC_BFV_BIT_U, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_NOISE> = BfvDec::new(
        DEC_BFV_CONFIGS,
        honest_c0,
        honest_c1,
        sum_c0,
        sum_c1,
        s,
        u_i,
        r_1,
        r_2,
        u_global,
        crt_quotients,
        message,
    );
    dec_bfv.verify();
}
