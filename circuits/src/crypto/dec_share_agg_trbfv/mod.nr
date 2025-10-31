pub mod dec_share_agg_trbfv;


/// Computes Lagrange coefficient L_i(0) mod q for interpolation at point 0
///
/// For party i with ID x_i, computes:
/// L_i(0) = ∏(j≠i) (-x_j) / (x_i - x_j) mod q
///
/// # Arguments
/// * `party_idx` - Index of the party (i)
/// * `party_ids` - Array of all party IDs [x_0, x_1, ..., x_t]
/// * `q` - The modulus to work in
///
/// # Returns
/// L_i(0) mod q
fn compute_lagrange_coeff_at_zero<let T: u32>(
    party_idx: u32,
    party_ids: [Field; T + 1],
    q: Field
) -> Field {
    // Create BigNum instance with q as modulus
    // q is ~58 bits, fits in 1 limb (< 120 bits)
    let modulus_limbs: [Field; 1] = [q];
    let params = BigNumParamsTrait::derive_from_modulus(modulus_limbs);
    let bn = BigNumInstance::new(params);
    
    // Initialize numerator and denominator to 1
    let mut numerator = bn.one();
    let mut denominator = bn.one();
    
    let x_i = bn.from_field(party_ids[party_idx]);
    
    // Compute product over all j ≠ i
    for j in 0..(T + 1) {
        if j != party_idx {
            let x_j = bn.from_field(party_ids[j]);
            
            // Numerator: multiply by (-x_j) mod q
            // -x_j mod q = q - x_j (when x_j != 0)
            let neg_x_j = bn.modulus.sub(x_j);
            numerator = numerator.mul(neg_x_j);
            
            // Denominator: multiply by (x_i - x_j) mod q
            // We need to handle the case where x_i < x_j
            let diff = if x_i.gte(x_j) {
                x_i.sub(x_j)
            } else {
                // If x_i < x_j, then x_i - x_j is negative
                // In modular arithmetic: -(x_j - x_i) ≡ q - (x_j - x_i) (mod q)
                let pos_diff = x_j.sub(x_i);
                bn.modulus.sub(pos_diff)
            };
            
            denominator = denominator.mul(diff);
        }
    }
    
    // Compute denominator^(-1) mod q
    let denom_inv = denominator.inv();
    
    // Return numerator * denominator^(-1) mod q
    let result = numerator.mul(denom_inv);
    result.to_field()
}

/// Computes all Lagrange coefficients for all coefficient positions and all bases
///
/// Since the party IDs (x-coordinates) are the same for all coefficient positions
/// and all bases, we only need to vary the modulus q_i for each basis.
///
/// # Returns
/// Array of Lagrange coefficients: [coeff_idx][basis_idx][party_idx]
/// Note: coeff_idx dimension exists but all values are the same since we're
/// interpolating at the same point (0) with the same x-coordinates
fn compute_all_lagrange_coeffs(self) -> [[[Field; T + 1]; L]; N] {
    let mut lagrange_coeffs = [[[0 as Field; T + 1]; L]; N];
    
    let crypto_params = self.params.crypto_params();
    
    // For each basis (modulus q_i)
    for basis_idx in 0..L {
        let q_i = crypto_params.qis[basis_idx];
        
        // Compute Lagrange coefficients for each party
        for party_idx in 0..(T + 1) {
            let l_i_at_0 = compute_lagrange_coeff_at_zero(
                party_idx,
                self.party_ids,
                q_i
            );
            
            // The same Lagrange coefficient applies to all coefficient positions
            // since we're always interpolating at x=0 with the same party IDs
            for coeff_idx in 0..N {
                lagrange_coeffs[coeff_idx][basis_idx][party_idx] = l_i_at_0;
            }
        }
    }
    
    lagrange_coeffs
}