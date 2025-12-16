use circuits::{
    crypto::sk_shares::sk_share_2::{Params, SecretKeySharesVerificationCircuit},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<2>,
    expected_sk_commitment: Field,
    sk: Polynomial<512>,
    y: [[[Field; 6]; 2]; 512],
    h: [[[Field; 6]; 3]; 2],
) -> pub [[Field; 2]; 5] {
    let sk_shares: SecretKeySharesVerificationCircuit<512, 2, 5, 2, 2, 37> =
        SecretKeySharesVerificationCircuit::new(params, expected_sk_commitment, sk, y, h);

    sk_shares.verify()
}
