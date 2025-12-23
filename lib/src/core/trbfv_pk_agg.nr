use crate::math::helpers::{compute_safe, flatten};
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
pub struct TrbfvPublicKeyAggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> {
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

impl<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> TrbfvPublicKeyAggregation<N, H, L, BIT_PK> {
    pub fn new(
        configs: Configs<L>,
        pk0: [[Polynomial<N>; L]; H],
        pk1: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
        pk1_agg: [Polynomial<N>; L],
    ) -> Self {
        TrbfvPublicKeyAggregation { configs, pk0, pk1, pk0_agg, pk1_agg }
    }

    /// Computes commitment to the aggregated public key
    fn commit_to_pk_agg(self) -> Field {
        let pk_agg_payload = Self::pk_agg_payload(self.pk0_agg, self.pk1_agg);

        // Domain separator - "Greco" (must match greco circuit)
        let domain_separator = [
            0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = pk_agg_payload.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, pk_agg_payload, io_pattern).get(0)
    }

    /// Flattens aggregated public key polynomials into Vec<Field> for commitment
    fn pk_agg_payload(pk0_agg: [Polynomial<N>; L], pk1_agg: [Polynomial<N>; L]) -> Vec<Field> {
        let mut inputs = Vec::new();

        // Flatten pk0_agg polynomials
        inputs = flatten::<_, _, BIT_PK>(inputs, pk0_agg);
        // Flatten pk1_agg polynomials
        inputs = flatten::<_, _, BIT_PK>(inputs, pk1_agg);

        inputs
    }

    fn verify_pk_for_basis(
        self,
        pk: [[Polynomial<N>; L]; H],
        pk_agg: [Polynomial<N>; L],
        basis_idx: u32,
    ) {
        let q_l = self.configs.qis[basis_idx];
        let mod_q_l = ModU128::new(q_l);

        for coeff_idx in 0..N {
            // Sum pk coefficients from all honest parties
            let mut sum_pk: Field = 0;
            for party_idx in 0..H {
                sum_pk = sum_pk + pk[party_idx][basis_idx].coefficients[coeff_idx];
            }

            // Reduce mod q_l
            let sum_pk_reduced = mod_q_l.reduce_mod(sum_pk);

            // Verify equality
            assert(
                sum_pk_reduced == pk_agg[basis_idx].coefficients[coeff_idx],
                "pk aggregation mismatch",
            );
        }
    }

    /// Main verification function
    /// Returns commitment to aggregated public key
    pub fn verify(self) -> Field {
        // 1. Verify pk & pk1 aggregations for each basis
        for basis_idx in 0..L {
            self.verify_pk_for_basis(self.pk0, self.pk0_agg, basis_idx);
            self.verify_pk_for_basis(self.pk1, self.pk1_agg, basis_idx);
        }

        // 2. Commit to aggregated public key
        self.commit_to_pk_agg()
    }
}
