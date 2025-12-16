use crate::math::modular_fns::reduce_mod;
use crate::math::polynomial::Polynomial;

/// Cryptographic parameters for TRBFV public key aggregation circuit.
pub struct CryptographicParams<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> CryptographicParams<L> {
    pub fn new(qis: [Field; L]) -> Self {
        CryptographicParams { qis }
    }
}

/// Complete parameters for TRBFV public key aggregation circuit.
pub struct Params<let L: u32> {
    pub crypto: CryptographicParams<L>,
}

impl<let L: u32> Params<L> {
    pub fn new(qis: [Field; L]) -> Self {
        let crypto = CryptographicParams::new(qis);
        Params { crypto }
    }

    pub fn crypto_params(self) -> CryptographicParams<L> {
        self.crypto
    }
}

/// TRBFV Public Key Aggregation Circuit
///
/// This circuit verifies the correct aggregation of TRBFV public keys from honest parties.
/// Based on the results of Circuits 1-5, we identify honest parties and sum their public keys.
///
/// Verifies:
/// - pk0_agg[l][i] = sum_h(pk0[h][l][i]) mod q_l for all bases l, coefficients i
/// - pk1_agg[l][i] = sum_h(pk1[h][l][i]) mod q_l for all bases l, coefficients i
///
/// All inputs/outputs are public (no commitments needed).
///
/// # Generic Parameters
/// * `N` - Number of polynomial coefficients
/// * `H` - Number of honest parties
/// * `L` - Number of CRT bases
pub struct TrbfvPublicKeyAggregation<let N: u32, let H: u32, let L: u32> {
    /// Circuit parameters
    params: Params<L>,

    /// Individual public keys from honest parties
    /// pk0[party_idx][basis_idx] - first component
    pk0: [[Polynomial<N>; L]; H],
    /// pk1[party_idx][basis_idx] - second component
    pk1: [[Polynomial<N>; L]; H],

    /// Claimed aggregated public key
    /// pk0_agg[basis_idx]
    pk0_agg: [Polynomial<N>; L],
    /// pk1_agg[basis_idx]
    pk1_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32> TrbfvPublicKeyAggregation<N, H, L> {
    pub fn new(
        params: Params<L>,
        pk0: [[Polynomial<N>; L]; H],
        pk1: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
        pk1_agg: [Polynomial<N>; L],
    ) -> Self {
        TrbfvPublicKeyAggregation { params, pk0, pk1, pk0_agg, pk1_agg }
    }

    /// Main verification function
    pub fn verify(self) {
        let crypto_params = self.params.crypto_params();

        // Verify pk0 aggregation
        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            for coeff_idx in 0..N {
                // Sum pk0 coefficients from all honest parties
                let mut sum_pk0: Field = 0;
                for party_idx in 0..H {
                    sum_pk0 = sum_pk0 + self.pk0[party_idx][basis_idx].coefficients[coeff_idx];
                }

                // Reduce mod q_l
                let sum_pk0_reduced = reduce_mod(sum_pk0, q_l);

                // Verify equality
                assert(
                    sum_pk0_reduced == self.pk0_agg[basis_idx].coefficients[coeff_idx],
                    "pk0 aggregation mismatch",
                );
            }
        }

        // Verify pk1 aggregation
        for basis_idx in 0..L {
            let q_l = crypto_params.qis[basis_idx];

            for coeff_idx in 0..N {
                // Sum pk1 coefficients from all honest parties
                let mut sum_pk1: Field = 0;
                for party_idx in 0..H {
                    sum_pk1 = sum_pk1 + self.pk1[party_idx][basis_idx].coefficients[coeff_idx];
                }

                // Reduce mod q_l
                let sum_pk1_reduced = reduce_mod(sum_pk1, q_l);

                // Verify equality
                assert(
                    sum_pk1_reduced == self.pk1_agg[basis_idx].coefficients[coeff_idx],
                    "pk1 aggregation mismatch",
                );
            }
        }
    }
}
