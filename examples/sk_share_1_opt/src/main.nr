use circuits::{
    crypto::sk_shares::sk_shares_1_opt::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};
fn main(
    params: Params<2>,
    x_powers: [[[Field; 3]; 5]; 2], // [L][N_PARTIES][T + 1]
    sk: Polynomial<512>,
    f: [[Polynomial<3>; 2]; 512],
) -> pub Field {
    let sk_shares: SecretKeySharesCircuit<512, 2, 5, 2, 2, 70> =
        SecretKeySharesCircuit::new(params, x_powers, sk, f);

    sk_shares.verify()
}
