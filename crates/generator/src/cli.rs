//! CLI interface for the PVSS parameter generator.
//!
//! This module provides command-line argument parsing and the main CLI entry point
//! for the generator binary used in Publicly Verifiable Secret Sharing (PVSS) setups
//! based on BFV encryption schemes.

use crate::{generate_all_outputs, BfvConfig, GeneratorConfig};
use clap::{Arg, Command};
use std::path::PathBuf;

/// CLI configuration structure for setting up BFV and generator parameters
#[derive(Debug, Clone)]
pub struct CliConfig {
    pub bfv_config: BfvConfig,
    pub generator_config: GeneratorConfig,
}

impl CliConfig {
    /// Parse CLI arguments and create configuration structure
    pub fn from_args() -> Result<Self, Box<dyn std::error::Error>> {
        let matches = Command::new("pvss-generator")
            .about(
                "Generates cryptographic parameters and constants for PVSS input validation and circuit integration",
            )
            .arg(
                Arg::new("degree")
                    .long("degree")
                    .short('d')
                    .value_name("DEGREE")
                    .help("Cyclotomic polynomial degree (power of 2)")
                    .default_value("2048"),
            )
            .arg(
                Arg::new("plaintext-modulus")
                    .long("plaintext-modulus")
                    .short('t')
                    .value_name("MODULUS")
                    .help("Plaintext modulus used for encoding messages")
                    .default_value("1032193"),
            )
            .arg(
                Arg::new("moduli")
                    .long("moduli")
                    .short('q')
                    .value_name("MODULI")
                    .help("Ciphertext moduli used in RNS decomposition (comma-separated list)")
                    .default_value("18014398492704769"),
            )
            .arg(
                Arg::new("output-dir")
                    .long("output-dir")
                    .short('o')
                    .value_name("DIR")
                    .help("Directory where generated constants and metadata will be saved")
                    .default_value("output"),
            )
            .arg(
                Arg::new("no-toml")
                    .long("no-toml")
                    .help("Skip generation of Prover.toml output file")
                    .action(clap::ArgAction::SetTrue),
            )
            .get_matches();

        // Parse polynomial degree
        let degree: usize = matches
            .get_one::<String>("degree")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid degree: {}", e))?;

        // Ensure degree is power of 2
        if !degree.is_power_of_two() {
            return Err("Degree must be a power of 2".into());
        }

        // Parse plaintext modulus
        let plaintext_modulus: u64 = matches
            .get_one::<String>("plaintext-modulus")
            .unwrap()
            .parse()
            .map_err(|e| format!("Invalid plaintext modulus: {}", e))?;

        // Parse ciphertext moduli from comma-separated string
        let moduli_str = matches.get_one::<String>("moduli").unwrap();
        let moduli: Result<Vec<u64>, _> = moduli_str
            .split(',')
            .map(|s| s.trim().parse::<u64>())
            .collect();
        let moduli = moduli.map_err(|e| format!("Invalid moduli: {}", e))?;

        // Check if Prover.toml generation should be skipped
        let generate_toml = !matches.get_flag("no-toml");

        // Get output directory path
        let output_dir = PathBuf::from(matches.get_one::<String>("output-dir").unwrap());

        let bfv_config = BfvConfig {
            degree,
            plaintext_modulus,
            moduli,
        };

        let generator_config = GeneratorConfig {
            output_dir,
            generate_toml,
        };

        Ok(CliConfig {
            bfv_config,
            generator_config,
        })
    }

    /// Run the generator CLI based on parsed configuration
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("PVSS Generator");
        println!("Generating cryptographic parameters...");

        // Display parsed input parameters
        println!("\nConfiguration:");
        println!("- Degree: {}", self.bfv_config.degree);
        println!("- Plaintext modulus: {}", self.bfv_config.plaintext_modulus);
        println!("- Ciphertext moduli: {:?}", self.bfv_config.moduli);
        println!("- Output directory: {:?}", self.generator_config.output_dir);
        println!("- Generate TOML: {}", self.generator_config.generate_toml);

        // Perform generation and save to disk
        let results = generate_all_outputs(self.bfv_config.clone(), self.generator_config.clone())?;

        println!("\nOutputs:");
        if let Some(noir_path) = &results.noir_file {
            println!("- Noir constants: {:?}", noir_path);
        }

        if let Some(toml_path) = &results.toml_file {
            println!("- Prover TOML: {:?}", toml_path);
        }

        Ok(())
    }
}

/// Main CLI entry point for PVSS generator
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = CliConfig::from_args()?;
    config.run()
}
