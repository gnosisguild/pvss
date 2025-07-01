//! BFV parameter utilities and encryption helpers.
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

/// Configuration for BFV parameters
#[derive(Clone, Debug)]
pub struct BfvConfig {
    pub degree: usize,
    pub plaintext_modulus: u64,
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

/// Data from a sample BFV encryption
pub struct EncryptionData {
    pub ciphertext: Ciphertext,
    pub secret_key: SecretKey,
    pub a: Poly,
    pub sk_rns: Poly,
    pub e_rns: Poly,
}

/// Helper for working with BFV parameters and operations
pub struct BfvHelper {
    pub params: Arc<BfvParameters>,
}

impl BfvHelper {
    /// Create a new BFV helper from configuration
    pub fn new(config: BfvConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(config.degree)
            .set_plaintext_modulus(config.plaintext_modulus)
            .set_moduli(&config.moduli)
            .build_arc()?;

        Ok(BfvHelper { params })
    }

    /// Generate a sample encryption with all the data needed for input validation
    pub fn generate_sample_encryption(&self) -> Result<EncryptionData, Box<dyn std::error::Error>> {
        let mut rng = StdRng::seed_from_u64(0);
        // Generate keys
        let secret_key = SecretKey::random(&self.params, &mut rng);
        // Use new extended to get all the values needed
        let (ciphertext, a, sk_rns, e_rns) = PublicKey::new_extended(&secret_key, &mut rng)?;
        Ok(EncryptionData {
            ciphertext,
            a,
            secret_key,
            sk_rns,
            e_rns,
        })
    }

    /// Get the default ZKP modulus
    pub fn default_zkp_modulus() -> BigInt {
        BigInt::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .expect("Invalid ZKP modulus")
    }
}
