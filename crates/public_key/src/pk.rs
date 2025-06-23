use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, SecretKey};
use fhe::lbfv::LBFVPublicKey;
use fhe::lbfv::LBFVRelinearizationKey;
use rand::prelude::*;

pub fn keygen() -> (SecretKey, LBFVPublicKey) {
    let mut rng = thread_rng();

    let n: u64 = 1024;
    let plaintext_modulus: u64 = 2048;
    let moduli: Vec<u64> = vec![4503599625535489, 4503599626321921];

    let params = BfvParametersBuilder::new()
        .set_degree(n as usize)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .unwrap();

    let sk = SecretKey::random(&params, &mut rng);
    let pk = LBFVPublicKey::new(&sk, &mut rng);

    (sk, pk)
}

pub fn relinearization_key(sk: SecretKey, pk: LBFVPublicKey) -> LBFVRelinearizationKey {
    let mut rng = thread_rng();
    // Create relinearization key
    let relin_key = LBFVRelinearizationKey::new(
        &sk, &pk, None, // Use random d1_seed
        0,    // ciphertext level
        0,    // key level
        &mut rng,
    )
    .unwrap();

    relin_key
}

#[test]
fn test_pk() {
    let (sk, pk) = keygen();

    println!("Secret key sk: {:?}", sk);
    println!("Public key pk: {:?}", pk);
}
