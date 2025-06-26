//! BFV parameter utilities and encryption helpers.
//!
//! This module provides utilities for working with BFV encryption parameters,
//! generating sample encryptions, and managing encryption contexts.

use fhe::bfv::{BfvParameters, BfvParametersBuilder, SecretKey};
use fhe::lbfv::LBFVPublicKey;
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
pub struct PVSSData {
    pub public_key: LBFVPublicKey,
    pub secret_key: SecretKey,
    pub e_ek: Poly,
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

    /// Generate a sample with all the data needed
    pub fn generate_sample(&self) -> Result<PVSSData, Box<dyn std::error::Error>> {
        let mut rng = StdRng::seed_from_u64(0);

        // Generate keys
        let sk = SecretKey::random(&self.params, &mut rng);
        let pk = LBFVPublicKey::new_extended(&sk, &mut rng)?;

        Ok(PVSSData {
            public_key: pk.0,
            secret_key: sk,
            e_ek: pk.1,
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
