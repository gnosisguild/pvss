//! Prover TOML generator.
//!
//! This module generates Prover.toml files containing input validation vectors
//! for use with Noir provers.

use crate::utils::to_string_1d_vec;
use crate::vectors::InputValidationVectors;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Generator for Prover TOML files
pub struct TomlGenerator;

/// Structure for individual vector tables in TOML
#[derive(Serialize)]
struct ProverVectorsTable {
    coefficients: Vec<String>,
}

/// Structure for the complete Prover.toml format
#[derive(Serialize)]
struct ProverTomlFormat {
    pk0is: Vec<ProverVectorsTable>,
    pk1is: Vec<ProverVectorsTable>,
    r1is: Vec<ProverVectorsTable>,
    r2is: Vec<ProverVectorsTable>,
    sk: ProverVectorsTable,
    eek: ProverVectorsTable,
    a: ProverVectorsTable,
}

impl TomlGenerator {
    /// Create a new TOML generator
    pub fn new() -> Self {
        Self
    }

    /// Generate Prover.toml file
    pub fn generate(
        &self,
        vectors: &InputValidationVectors,
        output_dir: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let output_path = output_dir.join("Prover.toml");
        let mut file = File::create(&output_path)?;

        // Convert vectors to TOML format
        let toml_data = self.to_prover_toml_format(vectors);

        // Serialize to TOML
        let toml_string = toml::to_string(&toml_data)?;

        // Write to file
        file.write_all(toml_string.as_bytes())?;

        Ok(output_path)
    }

    /// Convert InputValidationVectors to ProverTomlFormat
    fn to_prover_toml_format(&self, vecs: &InputValidationVectors) -> ProverTomlFormat {
        ProverTomlFormat {
            pk0is: vecs
                .pk0is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            pk1is: vecs
                .pk1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            r1is: vecs
                .r1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            r2is: vecs
                .r2is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            sk: ProverVectorsTable {
                coefficients: to_string_1d_vec(&vecs.sk),
            },
            eek: ProverVectorsTable {
                coefficients: to_string_1d_vec(&vecs.e),
            },
            a: ProverVectorsTable {
                coefficients: to_string_1d_vec(&vecs.a),
            },
        }
    }
}
