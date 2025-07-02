//! BFV Parameter Utilities and Encryption Sampler
//!
//! This module provides utilities for working with BFV encryption parameters,
//! generating sample encryptions, and managing encryption contexts.

use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, PublicKey, SecretKey};
use fhe_math::rq::Poly;
use num_bigint::BigInt;
use num_traits::Num;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;

/// Configuration structure for instantiating BFV parameters.
#[derive(Clone, Debug)]
pub struct BfvConfig {
    /// Polynomial degree (usually a power of 2, e.g., 1024, 2048, etc.)
    pub degree: usize,
    /// Plaintext modulus `t`
    pub plaintext_modulus: u64,
    /// Ciphertext modulus `q` split into RNS primes
    pub moduli: Vec<u64>,
}

impl Default for BfvConfig {
    fn default() -> Self {
        Self {
            degree: 2048,
            plaintext_modulus: 1032193,
            moduli: vec![18014398492704769],
        }
    }
}

/// Output structure representing all components involved in a sample BFV encryption.
/// Useful for validating inputs or simulating end-to-end encryption.
pub struct EncryptionData {
    /// The resulting ciphertext `[c0, c1]`
    pub ciphertext: Ciphertext,
    /// The secret key used for encryption
    pub secret_key: SecretKey,
    /// The public polynomial `a` used in the encryption (i.e., `-c1`)
    pub a: Poly,
    /// The secret key in NTT representation, lifted to RNS
    pub sk_rns: Poly,
    /// The error polynomial `e` used in encryption, in NTT representation
    pub e_rns: Poly,
}

/// Helper structure for managing BFV parameters and generating sample encryptions.
pub struct BfvHelper {
    /// Shared BFV parameters used for encryption and key generation
    pub params: Arc<BfvParameters>,
}

impl BfvHelper {
    /// Constructs a new [`BfvHelper`] from the provided [`BfvConfig`].
    ///
    /// # Errors
    /// Returns an error if parameter construction fails (e.g., invalid modulus configuration).
    pub fn new(config: BfvConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(config.degree)
            .set_plaintext_modulus(config.plaintext_modulus)
            .set_moduli(&config.moduli)
            .build_arc()?;

        Ok(BfvHelper { params })
    }

    /// Generates a sample ciphertext using a random secret key.
    ///
    /// This includes the secret key, encryption polynomial `a = -c1`,
    /// the secret key in RNS + NTT domain, and the error polynomial.
    ///
    /// Useful for generating input vectors for zero-knowledge circuits
    /// or verifying encryption behavior.
    pub fn generate_sample_encryption(&self) -> Result<EncryptionData, Box<dyn std::error::Error>> {
        let mut rng = StdRng::seed_from_u64(0);

        // Generate a random secret key
        let secret_key = SecretKey::random(&self.params, &mut rng);

        // Perform encryption and extract intermediate values (a, sk, e)
        let (ciphertext, a, sk_rns, e_rns) = PublicKey::new_extended(&secret_key, &mut rng)?;

        Ok(EncryptionData {
            ciphertext,
            a,
            secret_key,
            sk_rns,
            e_rns,
        })
    }

    /// Returns the default ZKP-compatible modulus as a `BigInt`.
    ///
    /// This is commonly used in SNARK-friendly settings (e.g., BN254 scalar field).
    pub fn default_zkp_modulus() -> BigInt {
        BigInt::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .expect("Invalid ZKP modulus")
    }
}
