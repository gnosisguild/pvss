use circuits::{
    crypto::sk_shares::sk_share_1::{Params, SecretKeySharesCircuit},
    math::polynomial::Polynomial,
};

fn main(params: Params<2>, x_coords: [Field; 5], sk: Polynomial<512>, f: [[Polynomial<3>; 2]; 512])
//-> pub Field
{
    let sk_shares: SecretKeySharesCircuit<512, 2, 5, 2, 1> =
        SecretKeySharesCircuit::new(params, x_coords, sk, f);

    sk_shares.verify()
}
