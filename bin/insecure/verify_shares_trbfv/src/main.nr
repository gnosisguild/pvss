use lib::configs::insecure::trbfv::{
    L, N, VERIFY_SHARES_BIT_SECRET, VERIFY_SHARES_BIT_SHARE, VERIFY_SHARES_CONFIGS,
};
use lib::core::trbfv_verify_shares::VerifyShares;
use lib::math::polynomial::Polynomial;

/// Number of parties.
pub global N_PARTIES: u32 = 5;
/// Threshold.
pub global T: u32 = 2;

fn main(
    expected_secret_commitment: Field,
    secret: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L]; N],
    h: [[[Field; N_PARTIES + 1]; T + 1]; L],
) -> pub [[Field; L]; N_PARTIES] {
    let verify_shares: VerifyShares<N, L, N_PARTIES, T, VERIFY_SHARES_BIT_SECRET, VERIFY_SHARES_BIT_SHARE> = VerifyShares::new(
        VERIFY_SHARES_CONFIGS,
        expected_secret_commitment,
        secret,
        y,
        h,
    );

    verify_shares.verify()
}
