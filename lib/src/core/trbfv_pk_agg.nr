use crate::math::modulo::U128::ModU128;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for TRBFV public key aggregation circuit.
pub struct Configs<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// TRBFV Public Key Aggregation Circuit.
///
/// Verifies that for each CRT basis l and each coefficient i:
/// - pk0_agg[l][i] = sum_h(pk0[h][l][i]) mod q_l
/// - pk1_agg[l][i] = sum_h(pk1[h][l][i]) mod q_l
pub struct TrbfvPublicKeyAggregation<let N: u32, let H: u32, let L: u32> {
    /// Circuit parameters including CRT moduli
    configs: Configs<L>,

    /// Individual public keys from H honest parties (public inputs)
    /// pk0[party_idx][basis_idx] - first component of public key for each party and CRT basis
    pk0: [[Polynomial<N>; L]; H],
    /// pk1[party_idx][basis_idx] - second component of public key for each party and CRT basis
    pk1: [[Polynomial<N>; L]; H],

    /// Claimed aggregated public key (public inputs)
    /// pk0_agg[basis_idx] - first component of aggregated public key for each CRT basis
    pk0_agg: [Polynomial<N>; L],
    /// pk1_agg[basis_idx] - second component of aggregated public key for each CRT basis
    pk1_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32> TrbfvPublicKeyAggregation<N, H, L> {
    pub fn new(
        configs: Configs<L>,
        pk0: [[Polynomial<N>; L]; H],
        pk1: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
        pk1_agg: [Polynomial<N>; L],
    ) -> Self {
        TrbfvPublicKeyAggregation { configs, pk0, pk1, pk0_agg, pk1_agg }
    }

    /// Main verification function
    pub fn verify(self) {
        // Verify pk0 aggregation
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];
            let mod_q_l = ModU128::new(q_l);

            for coeff_idx in 0..N {
                // Sum pk0 coefficients from all honest parties
                let mut sum_pk0: Field = 0;
                for party_idx in 0..H {
                    sum_pk0 = sum_pk0 + self.pk0[party_idx][basis_idx].coefficients[coeff_idx];
                }

                // Reduce mod q_l
                let sum_pk0_reduced = mod_q_l.reduce_mod(sum_pk0);

                // Verify equality
                assert(
                    sum_pk0_reduced == self.pk0_agg[basis_idx].coefficients[coeff_idx],
                    "pk0 aggregation mismatch",
                );
            }
        }

        // Verify pk1 aggregation
        for basis_idx in 0..L {
            let q_l = self.configs.qis[basis_idx];
            let mod_q_l = ModU128::new(q_l);

            for coeff_idx in 0..N {
                // Sum pk1 coefficients from all honest parties
                let mut sum_pk1: Field = 0;
                for party_idx in 0..H {
                    sum_pk1 = sum_pk1 + self.pk1[party_idx][basis_idx].coefficients[coeff_idx];
                }

                // Reduce mod q_l
                let sum_pk1_reduced = mod_q_l.reduce_mod(sum_pk1);

                // Verify equality
                assert(
                    sum_pk1_reduced == self.pk1_agg[basis_idx].coefficients[coeff_idx],
                    "pk1 aggregation mismatch",
                );
            }
        }
    }
}
