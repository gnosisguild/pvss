use circuits::{
    crypto::sk_shares::sk_share_2::{Params, SecretKeySharesVerificationCircuit},
    math::polynomial::Polynomial,
};

fn main(
    params: Params<2>, //L
    sk: Polynomial<512>,
    y: [[[Field; 6]; 2]; 512], // [[[Field; N_PARTIES + 1]; L]; N]
    h: [[[Field; 4]; 6]; 2], // [[[Field; N_PARTIES + 1 - T]; N_PARTIES + 1]; L]
) -> pub Field {
    let circuit: SecretKeySharesVerificationCircuit<512, 2, 5, 2, 14, 70> =
        SecretKeySharesVerificationCircuit::new(params, sk, y, h);

    circuit.verify()
}
