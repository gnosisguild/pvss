use lib::configs::production::trbfv::{
    L, N, VERIFY_SHARES_BIT_SHARE, VERIFY_SHARES_BIT_SK, VERIFY_SHARES_CONFIGS,
};
use lib::core::trbfv_verify_shares::VerifyShares;
use lib::math::polynomial::Polynomial;

/// Number of parties.
pub global N_PARTIES: u32 = 5;
/// Threshold.
pub global T: u32 = 2;

fn main(
    expected_sk_commitment: Field,
    sk: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L]; N],
    h: [[[Field; N_PARTIES + 1]; T + 1]; L],
) -> pub [[Field; L]; N_PARTIES] {
    let sk_shares: VerifyShares<N, L, N_PARTIES, T, VERIFY_SHARES_BIT_SK, VERIFY_SHARES_BIT_SHARE>
         = VerifyShares::new(VERIFY_SHARES_CONFIGS, expected_sk_commitment, sk, y, h);

    sk_shares.verify()
}
