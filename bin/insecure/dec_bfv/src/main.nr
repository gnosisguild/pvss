use lib::configs::insecure::bfv::{
    DEC_BFV_BIT_CT, DEC_BFV_BIT_MSG, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_S, DEC_BFV_BIT_U,
    DEC_BFV_CONFIGS, L_PRIME, L_TRBFV, N,
};
use lib::core::bfv_dec_no_hom_add::BfvDecNoHomAdd;
use lib::math::polynomial::Polynomial;

/// Honest parties.
pub global H: u32 = 5;

fn main(
    expected_sk_commitment: pub Field,
    honest_c0: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    honest_c1: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    s: Polynomial<N>,
    u_i: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    r_1: [[[Polynomial<2 * N - 1>; L_PRIME]; L_TRBFV]; H],
    r_2: [[[Polynomial<N - 1>; L_PRIME]; L_TRBFV]; H],
    u_global: [[Polynomial<N>; L_TRBFV]; H],
    crt_quotients: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    decrypted_shares: [[Polynomial<N>; L_TRBFV]; H],
    expected_aggregated_shares: [Polynomial<N>; L_TRBFV],
) -> pub Field {
    let dec_bfv: BfvDecNoHomAdd<N, H, L_TRBFV, L_PRIME, DEC_BFV_BIT_CT, DEC_BFV_BIT_S, DEC_BFV_BIT_U, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2, DEC_BFV_BIT_MSG> = BfvDecNoHomAdd::new(
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
        decrypted_shares,
        expected_aggregated_shares,
    );
    dec_bfv.verify()
}
