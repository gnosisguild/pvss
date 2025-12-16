use circuits::{
    crypto::dec_bfv_no_hom_add::dec_bfv_no_hom_add::{
        HonestCiphertextAggregationDecryptionNoHomAdd, Params,
    },
    math::polynomial::Polynomial,
};

fn main(
    params: Params<512, 5, 2, 1>,
    expected_sk_commitment: Field,
    honest_c0: [[[Polynomial<512>; 1]; 2]; 5],
    honest_c1: [[[Polynomial<512>; 1]; 2]; 5],
    s: Polynomial<512>,
    u_i: [[[Polynomial<512>; 1]; 2]; 5],
    r_1: [[[Polynomial<1023>; 1]; 2]; 5],
    r_2: [[[Polynomial<511>; 1]; 2]; 5],
    u_global: [[Polynomial<512>; 2]; 5],
    crt_quotients: [[[Polynomial<512>; 1]; 2]; 5],
    decrypted_shares: [[Polynomial<512>; 2]; 5],
    expected_aggregated_shares: [Polynomial<512>; 2],
) -> pub Field {
    // N, H, L, L_PRIME, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_MSG
    let circuit: HonestCiphertextAggregationDecryptionNoHomAdd<512, 5, 2, 1, 51, 2, 51, 51, 51, 51>
         = HonestCiphertextAggregationDecryptionNoHomAdd::new(
            params,
            expected_sk_commitment,
            honest_c0,
            honest_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            decrypted_shares,
            expected_aggregated_shares,
        );

    circuit.verify()
}
