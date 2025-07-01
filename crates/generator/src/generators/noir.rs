//! Noir constants file generation.
//!
//! This module generates Noir constants files with BFV parameters and bounds
//! for use in zero-knowledge proof circuits.

use crate::bounds::InputValidationBounds;
use fhe::bfv::BfvParameters;
use fhe_math::rq::Context;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Generator for Noir constants files
pub struct NoirGenerator {}

impl NoirGenerator {
    /// Create a new Noir generator
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a Noir constants file
    pub fn generate(
        &self,
        bounds: &InputValidationBounds,
        params: &Arc<BfvParameters>,
        _context: &Context,
        output_dir: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let output_path = output_dir.join("constants.nr");
        let mut file = File::create(&output_path)?;

        // Write header comment
        writeln!(file, "/// `N` is the degree of the cyclotomic polynomial defining the ring `Rq = Zq[X]/(X^N + 1)`.")?;
        writeln!(file, "pub global N: u32 = {};", params.degree())?;

        writeln!(file, "/// `L` is the dimension size of the polynomials.")?;
        writeln!(file, "pub global L: u32 = {};", bounds.moduli.len())?;

        // Q_MOD_T
        writeln!(file, "/// `q_mod_t` is the remainder of the ciphertext modulus `q` divided by the plaintext modulus `t`.")?;
        writeln!(file, "pub global Q_MOD_T: Field = {};", bounds.q_mod_t)?;

        // PK bounds
        writeln!(file, "/// The coefficients of the polynomial `pk0is` and `pk1is` should exist in the interval `[-PK_BOUND, PK_BOUND]`.")?;
        write!(
            file,
            "pub global PK_BOUND: [u64; {}] = [",
            bounds.moduli.len()
        )?;
        for (i, bound) in bounds.pk_bounds.iter().enumerate() {
            if i > 0 {
                write!(file, ", ")?;
            }
            write!(file, "{}", bound)?;
        }
        writeln!(file, "];")?;

        // E bound
        writeln!(file, "/// The coefficients of the polynomial `e` should exist in the interval `[-E_BOUND, E_BOUND]` where `E_BOUND` is the upper bound of the gaussian distribution with Sigma = 3.2.")?;
        writeln!(file, "pub global E_BOUND: u64 = {};", bounds.e_bound)?;

        // SK bound
        writeln!(file, "/// The coefficients of the polynomial `sk` should exist in the interval `[-S_BOUND, S_BOUND]`.")?;
        writeln!(file, "pub global SK_BOUND: u64 = {};", bounds.sk_bound)?;

        // R1 bounds
        writeln!(file, "/// The coefficients of the polynomials `r1is` should exist in the interval `[R1_LOW_BOUNDS[i], R1_UP_BOUNDS[i]]` where R1_LOW_BOUNDS is equal to $\\frac{{\\frac{{-(t - 1)}}{{2}} \\cdot |K_{{0,i}}| - (N \\cdot B +2) \\cdot \\frac{{q_i - 1}}{{2}} + B}}{{q_i}}$ and `R1_UP_BOUNDS[i]` is equal to `$\\frac{{\\frac{{(t - 1)}}{{2}} \\cdot |K_{{0,i}}| + (N \\cdot +2) \\cdot \\frac{{q_i - 1}}{{2}} + B}}{{q_i}}$ .")?;
        write!(
            file,
            "pub global R1_LOW_BOUNDS: [i64; {}] = [",
            bounds.moduli.len()
        )?;
        for (i, bound) in bounds.r1_low_bounds.iter().enumerate() {
            if i > 0 {
                write!(file, ", ")?;
            }
            write!(file, "{}", bound)?;
        }
        writeln!(file, "];")?;

        write!(
            file,
            "pub global R1_UP_BOUNDS: [u64; {}] = [",
            bounds.moduli.len()
        )?;
        for (i, bound) in bounds.r1_up_bounds.iter().enumerate() {
            if i > 0 {
                write!(file, ", ")?;
            }
            write!(file, "{}", bound)?;
        }
        writeln!(file, "];")?;

        // R2 bounds
        writeln!(file, "/// The coefficients of the polynomials `r2is` should exist in the interval `[-R2_BOUND[i], R2_BOUND[i]]` where `R2_BOUND[i]` is equal to `(qi-1)/2`.")?;
        write!(
            file,
            "pub global R2_BOUNDS: [u64; {}] = [",
            bounds.moduli.len()
        )?;
        for (i, bound) in bounds.r2_bounds.iter().enumerate() {
            if i > 0 {
                write!(file, ", ")?;
            }
            write!(file, "{}", bound)?;
        }
        writeln!(file, "];")?;

        // QIS (moduli)
        writeln!(file, "/// List of scalars `qis` such that `qis[i]` is the modulus of the i-th CRT basis of `q` (ciphertext space modulus).")?;
        write!(file, "pub global QIS: [Field; {}] = [", bounds.moduli.len())?;
        for (i, modulus) in bounds.moduli.iter().enumerate() {
            if i > 0 {
                write!(file, ", ")?;
            }
            write!(file, "{}", modulus)?;
        }
        writeln!(file, "];")?;

        // SIZE of the payload
        writeln!(file, "/// Size of the payload.")?;
        writeln!(file, "pub global SIZE: u32 = {:?};", bounds.size)?;

        // TAG constant
        writeln!(file, "/// Constant value for the SAFE sponge algorithm.")?;
        writeln!(file, "pub global TAG: Field = {};", bounds.tag)?;

        Ok(output_path)
    }
}
