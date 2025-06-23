use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
use rand::prelude::*;

pub fn keygen_with_library() -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();

    let n: u64 = 1024;
    let plaintext_modulus: u64 = 2048;
    let moduli: Vec<u64> = vec![4503599625535489, 4503599626321921];

    let params = BfvParametersBuilder::new()
        .set_degree(n as usize)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        //.set_moduli_sizes(&moduli_sizes)
        .build_arc()
        .unwrap();

    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    (sk, pk)
}

#[test]
fn test_pk() {
    let (sk, pk) = keygen_with_library();

    println!("Secret key sk: {:?}", sk);
    println!("Public key pk: {:?}", pk);
}
