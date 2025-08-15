//! # PVSS Generator Library
//!
//! A library for generating cryptographic parameters and constants for use in
//! Publicly Verifiable Secret Sharing (PVSS) protocols based on the BFV homomorphic encryption scheme.
//!
//! It supports generation of encryption samples, constraint bounds, and Noir-compatible
//! input formats to support zero-knowledge proof circuits.

pub mod bfv;
pub mod bounds;
pub mod cli;
pub mod generators;
pub mod sk_shares;
pub mod utils;
pub mod vectors;

// Re-export public types for convenience
pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use bounds::InputValidationBounds;
pub use cli::CliConfig;
pub use generators::{noir::NoirGenerator, toml::TomlGenerator};
use rand::thread_rng;
pub use vectors::InputValidationVectors;

use num_traits::Num;
use polynomial::BigInt;
use std::path::PathBuf;

/// Configuration structure for controlling output generation targets
#[derive(Clone, Debug)]
pub struct GeneratorConfig {
    pub output_dir: PathBuf,
    pub generate_toml: bool,
    pub circuit: String,
    pub n_parties: usize,
    pub k_dim: usize,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            output_dir: "output".into(),
            generate_toml: true,
            circuit: "pk_trbfv".to_string(),
            n_parties: 3,
            k_dim: 2,
        }
    }
}

/// Structure containing the results of the generation process
#[derive(Debug)]
pub struct GenerationResults {
    pub vectors: InputValidationVectors,
    pub bounds: InputValidationBounds,
    pub noir_file: Option<PathBuf>,
    pub toml_file: Option<PathBuf>,
}

/// High-level wrapper that generates input validation vectors, bounds,
/// and optionally Noir and TOML files for PVSS input preparation.
///
/// This function routes to circuit-specific generation functions based on the
/// circuit name in the generator configuration. Each circuit can have its own
/// custom generation logic for constants and Prover.toml files.
pub fn generate_all_outputs(
    bfv_config: BfvConfig,
    generator_config: GeneratorConfig,
) -> Result<GenerationResults, Box<dyn std::error::Error>> {
    // Route to circuit-specific generation function
    match generator_config.circuit.as_str() {
        "pk_trbfv" => generate_pk_trbfv_outputs(bfv_config, generator_config),
        "pk_pvw" => generate_pk_pvw_outputs(bfv_config, generator_config),
        "sk_shares" => generate_sk_shares_outputs(bfv_config, generator_config),
        _ => Err(format!("Unknown circuit: {}", generator_config.circuit).into()),
    }
}

/// Generate outputs for pk_trbfv circuit
fn generate_pk_trbfv_outputs(
    bfv_config: BfvConfig,
    generator_config: GeneratorConfig,
) -> Result<GenerationResults, Box<dyn std::error::Error>> {
    // Retain relevant values before bfv_config is moved
    let moduli = bfv_config.moduli.clone();
    let degree = bfv_config.degree;

    // Create helper and sample an encryption instance
    let helper = BfvHelper::new(bfv_config)?;
    let encryption_data = helper.generate_sample_encryption()?;

    // Compute validation vectors for input encoding
    let vectors = InputValidationVectors::compute(
        &encryption_data.sk_rns,
        &encryption_data.e_rns,
        &encryption_data.a,
        &encryption_data.public_key,
        &helper.params,
    )?;

    // Derive bounds from BFV parameters at level 0
    let bounds = InputValidationBounds::compute(&helper.params, 0)?;

    // Use ZK-friendly modulus (e.g., BN254 scalar field)
    let zkp_modulus = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )?;

    // Sanity-check that vectors respect the bounds
    bounds.check_constraints(&vectors, &zkp_modulus);

    // Create circuit-specific directory for constants in output directory
    let circuit_constants_dir = generator_config.output_dir.join(&generator_config.circuit);
    std::fs::create_dir_all(&circuit_constants_dir)?;

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
        &circuit_constants_dir,
        &generator_config.circuit,
    )?;
    results.noir_file = Some(noir_path);

    // Generate Prover TOML if requested
    if generator_config.generate_toml {
        let toml_generator = TomlGenerator::new();
        let toml_path = toml_generator
            .generate(&vectors.standard_form(&zkp_modulus), &circuit_constants_dir)?;
        results.toml_file = Some(toml_path);
    }

    Ok(results)
}

/// Generate outputs for pk_pvw circuit
fn generate_pk_pvw_outputs(
    bfv_config: BfvConfig,
    generator_config: GeneratorConfig,
) -> Result<GenerationResults, Box<dyn std::error::Error>> {
    // Retain relevant values before bfv_config is moved
    let moduli = bfv_config.moduli.clone();
    let degree = bfv_config.degree;

    // Create helper and sample an encryption instance
    let helper = BfvHelper::new(bfv_config)?;
    let encryption_data = helper.generate_sample_encryption()?;

    // Compute validation vectors for input encoding
    let vectors = InputValidationVectors::compute(
        &encryption_data.sk_rns,
        &encryption_data.e_rns,
        &encryption_data.a,
        &encryption_data.public_key,
        &helper.params,
    )?;

    // Derive bounds from BFV parameters at level 0
    let bounds = InputValidationBounds::compute(&helper.params, 0)?;

    // Use ZK-friendly modulus (e.g., BN254 scalar field)
    let zkp_modulus = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )?;

    // Sanity-check that vectors respect the bounds
    bounds.check_constraints(&vectors, &zkp_modulus);

    // Create circuit-specific directory for constants in output directory
    let circuit_constants_dir = generator_config.output_dir.join(&generator_config.circuit);
    std::fs::create_dir_all(&circuit_constants_dir)?;

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
        &circuit_constants_dir,
        &generator_config.circuit,
    )?;
    results.noir_file = Some(noir_path);

    // Generate Prover TOML if requested
    if generator_config.generate_toml {
        let toml_generator = TomlGenerator::new();
        let toml_path = toml_generator
            .generate(&vectors.standard_form(&zkp_modulus), &circuit_constants_dir)?;
        results.toml_file = Some(toml_path);
    }

    Ok(results)
}

/// Generate outputs for sk_shares circuit
fn generate_sk_shares_outputs(
    bfv_config: BfvConfig,
    generator_config: GeneratorConfig,
) -> Result<GenerationResults, Box<dyn std::error::Error>> {
    // Retain relevant values before bfv_config is moved
    let moduli = bfv_config.moduli.clone();
    let degree = bfv_config.degree;

    // Create helper and sample an encryption instance
    let helper = BfvHelper::new(bfv_config)?;
    let encryption_data = helper.generate_sample_encryption()?;

    // Compute validation vectors for input encoding
    let vectors = InputValidationVectors::compute(
        &encryption_data.sk_rns,
        &encryption_data.e_rns,
        &encryption_data.a,
        &encryption_data.public_key,
        &helper.params,
    )?;

    // Derive bounds from BFV parameters at level 0
    let bounds = InputValidationBounds::compute(&helper.params, 0)?;

    // Use ZK-friendly modulus (e.g., BN254 scalar field)
    let zkp_modulus = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )?;

    // Sanity-check that vectors respect the bounds
    bounds.check_constraints(&vectors, &zkp_modulus);
    let rng = thread_rng();
    let sss_inputs = crate::sk_shares::compute_sss_inputs(
        generator_config.n_parties,
        generator_config.k_dim,
        degree,
        &moduli,
        4,
        rng,
    )
    .unwrap();

    // Create circuit-specific directory for constants in output directory
    let circuit_constants_dir = generator_config.output_dir.join(&generator_config.circuit);
    std::fs::create_dir_all(&circuit_constants_dir)?;

    // Generate Noir constants if requested
    let noir_generator = NoirGenerator::new();
    // We need to create a context for the noir generator
    let context = fhe_math::rq::Context::new(&moduli, degree)?;
    let noir_path = noir_generator.generate_with_pvw(
        &bounds,
        &helper.params,
        &context,
        &circuit_constants_dir,
        &generator_config.circuit,
        Some(sss_inputs.k_dim as u32),
        Some(sss_inputs.n_parties as u32),
    )?;

    let mut toml_file = None;
    // Generate Prover TOML if requested
    if generator_config.generate_toml {
        let toml_path = crate::sk_shares::generate_sss_toml(&sss_inputs, &circuit_constants_dir)?;
        toml_file = Some(toml_path);
    }

    // Fill results (vectors field unused for PVW; provide empty placeholder)
    let placeholder_vectors = InputValidationVectors::new(moduli.len(), degree);
    let results = GenerationResults {
        vectors: placeholder_vectors,
        bounds,
        noir_file: Some(noir_path),
        toml_file: toml_file,
    };

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
    let encryption_data = helper.generate_sample_encryption()?;

    // Try to compute vectors - this will show us the exact errors
    let _vectors = InputValidationVectors::compute(
        &encryption_data.sk_rns,
        &encryption_data.e_rns,
        &encryption_data.a,
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
    let _encryption_data = helper.generate_sample_encryption()?;

    // Try to compute bounds
    let _bounds = InputValidationBounds::compute(&helper.params, 0)?;

    println!("Bounds computation successful!");
    Ok(())
}
