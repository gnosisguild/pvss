use circuits::{
    crypto::sk_shares::sk_shares::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<512, 1>,
    x_coords: [Field; 5],
    y: [[[Field; 5]; 1]; 512],
    sk: Polynomial<512>,
    f: [[Polynomial<1 + 1>; 1]; 512],
    f_randomness: [[Field; 1]; 512],
    r: [[[Field; 5]; 1]; 512],
    d: [[Field; 1]; 512],
) {
    let sk_shares: SecretKeySharesCircuit<512, 1, 5, 1> =
        SecretKeySharesCircuit::new(params, x_coords, y, sk, f, f_randomness, r, d);

    sk_shares.verify_correct_trbfv_secret_sharing();
}
