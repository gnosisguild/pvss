//! Greco Generator Binary
//!
//! Command-line tool for generating cryptographic parameters and constants
//! for Greco zero-knowledge proofs.

use pvss_generator::cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cli::main()
}
