use circuits::{
    crypto::sk_shares::sk_share_2::{Params, SecretKeySharesVerificationCircuit},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<4>,
    sk: Polynomial<8192>,
    y: [[[Field; 6]; 4]; 8192],
    h: [[[Field; 6]; 3]; 4],
) -> pub Field {
    let sk_shares: SecretKeySharesVerificationCircuit<8192, 4, 5, 2, 2, 54> =
        SecretKeySharesVerificationCircuit::new(params, sk, y, h);

    sk_shares.verify()
}
