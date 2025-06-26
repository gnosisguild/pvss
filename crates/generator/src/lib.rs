//! # Greco Generator Library
//!
//! A library for generating cryptographic parameters and constants for Greco zero-knowledge proofs
//! in the context of BFV homomorphic encryption.

pub mod bfv;
pub mod bounds;
pub mod cli;
pub mod generators;
pub mod utils;
pub mod vectors;

// Re-export main types that currently work
pub use bfv::{BfvConfig, BfvHelper};
pub use cli::CliConfig;
pub use generators::{noir::NoirGenerator, toml::TomlGenerator};

use num_traits::Num;
use polynomial::BigInt;
use std::path::PathBuf;

use crate::{bounds::PVSSBounds, vectors::PVSSVectors};

/// Configuration for output generation
#[derive(Clone, Debug)]
pub struct GeneratorConfig {
    pub output_dir: PathBuf,
    pub generate_toml: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            output_dir: "output".into(),
            generate_toml: true,
        }
    }
}

/// Results from generation process
#[derive(Debug)]
pub struct GenerationResults {
    pub vectors: PVSSVectors,
    pub bounds: PVSSBounds,
    pub noir_file: Option<PathBuf>,
    pub toml_file: Option<PathBuf>,
}

/// High-level function to generate all outputs given BFV configuration
pub fn generate_all_outputs(
    bfv_config: BfvConfig,
    generator_config: GeneratorConfig,
) -> Result<GenerationResults, Box<dyn std::error::Error>> {
    // Store values we'll need later before moving bfv_config
    let moduli = bfv_config.moduli.clone();
    let degree = bfv_config.degree;

    // Create BFV helper and generate encryption
    let helper = BfvHelper::new(bfv_config)?;
    let pvss_data = helper.generate_sample()?;

    // Compute input validation vectors
    let vectors = PVSSVectors::compute(
        &pvss_data.e_ek,
        &pvss_data.secret_key,
        &pvss_data.public_key,
        &helper.params,
    )?;

    // Compute bounds
    let bounds = PVSSBounds::compute(&helper.params, 0)?;

    // Get ZKP modulus
    let zkp_modulus = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )?;

    // Check constraints
    bounds.check_constraints(&vectors, &zkp_modulus);

    // Create output directory
    std::fs::create_dir_all(&generator_config.output_dir)?;

    let mut results = GenerationResults {
        vectors: vectors.clone(),
        bounds: bounds.clone(),
        noir_file: None,
        toml_file: None,
    };

    // Generate Noir constants if requested
    let noir_generator = NoirGenerator::new();
    // We need to create a context for the noir generator
    let context = fhe_math::rq::Context::new(&moduli, degree)?;
    let noir_path = noir_generator.generate(
        &bounds,
        &helper.params,
        &context,
        &generator_config.output_dir,
    )?;
    results.noir_file = Some(noir_path);

    // Generate Prover TOML if requested
    if generator_config.generate_toml {
        let toml_generator = TomlGenerator::new();
        let toml_path = toml_generator.generate(
            &vectors.standard_form(&zkp_modulus),
            &generator_config.output_dir,
        )?;
        results.toml_file = Some(toml_path);
    }

    Ok(results)
}

/// Test function to check what specific errors we get with vectors
#[cfg(test)]
#[test]
pub fn test_vectors_computation() -> Result<(), Box<dyn std::error::Error>> {
    let config = BfvConfig {
        degree: 2048,
        plaintext_modulus: 1032193,
        moduli: vec![18014398492704769],
    };

    let helper = BfvHelper::new(config)?;
    let encryption_data = helper.generate_sample()?;

    // Try to compute vectors - this will show us the exact errors
    let _vectors = PVSSVectors::compute(
        &encryption_data.e_ek,
        &encryption_data.secret_key,
        &encryption_data.public_key,
        &helper.params,
    )?;

    println!("Vectors computation successful!");
    Ok(())
}

/// Test bounds computation
#[cfg(test)]
#[test]
pub fn test_bounds_computation() -> Result<(), Box<dyn std::error::Error>> {
    let config = BfvConfig {
        degree: 2048,
        plaintext_modulus: 1032193,
        moduli: vec![18014398492704769],
    };

    let helper = BfvHelper::new(config)?;
    let encryption_data = helper.generate_sample()?;

    // Try to compute bounds
    let _bounds = PVSSBounds::compute(&helper.params, 0)?;

    println!("Bounds computation successful!");
    Ok(())
}
