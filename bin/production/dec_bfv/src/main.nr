use lib::configs::production::bfv::{DEC_BFV_BIT_MSG, L_TRBFV, N};
use lib::core::bfv_dec::BfvDecCommitVerify;
use lib::math::polynomial::Polynomial;

pub global H: u32 = 5; // number of honest parties

fn main(
    expected_commitments: [[Field; L_TRBFV]; H],
    decrypted_shares: [[Polynomial<N>; L_TRBFV]; H],
) -> pub Field {
    let circuit: BfvDecCommitVerify<N, L_TRBFV, H, DEC_BFV_BIT_MSG> =
        BfvDecCommitVerify::new(expected_commitments, decrypted_shares);

    circuit.verify()
}
