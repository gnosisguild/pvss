// use circuits::{
//     crypto::dec_share_agg_trbfv::dec_share_agg_trbfv::{DecryptionShareAggregation, Params},
//     math::polynomial::Polynomial,
// };

// fn main(
//     params: Params<8192, 4, 2>,
//     decryption_shares: [[Polynomial<8192>; 4]; 3],
//     party_ids: [Field; 3],
//     message: Polynomial<8192>,
//     u_global: Polynomial<8192>,
//     crt_quotients: [Polynomial<8192>; 4],
// ) {
//     let dec_share_agg: DecryptionShareAggregation<8192, 4, 2, 201> = DecryptionShareAggregation::new(
//         params,
//         decryption_shares,
//         party_ids,
//         message,
//         u_global,
//         crt_quotients,
//     );

//     dec_share_agg.verify();
// }
