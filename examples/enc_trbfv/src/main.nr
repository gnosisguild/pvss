// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};
fn main(
    params: Params<512, 2>,
    pk0is: [Polynomial<512>; 2],
    pk1is: [Polynomial<512>; 2],
    ct0is: [Polynomial<512>; 2],
    ct1is: [Polynomial<512>; 2],
    u: Polynomial<512>,
    e0: Polynomial<512>,
    e0is: [Polynomial<512>; 2],
    e0_quotients: [Polynomial<512>; 2],
    e1: Polynomial<512>,
    k1: Polynomial<512>,
    r1is: [Polynomial<1023>; 2],
    r2is: [Polynomial<511>; 2],
    p1is: [Polynomial<1023>; 2],
    p2is: [Polynomial<511>; 2],
    // Symphony projection optimization fields
    projection_seed: Field,
    u_projected: Polynomial<128>,
    e0_projected: Polynomial<128>,
    e1_projected: Polynomial<128>,
    pk0is_projected: [Polynomial<128>; 2],
    pk1is_projected: [Polynomial<128>; 2],
    r1is_projected: [Polynomial<128>; 2],
    r2is_projected: [Polynomial<128>; 2],
    p1is_projected: [Polynomial<128>; 2],
    p2is_projected: [Polynomial<128>; 2],
) {
    let greco: Greco<512, 2, 36, 36, 2, 6, 6, 4, 10, 36, 10, 36> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e0is,
        e0_quotients,
        e1,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
        projection_seed,
        u_projected,
        e0_projected,
        e1_projected,
        pk0is_projected,
        pk1is_projected,
        r1is_projected,
        r2is_projected,
        p1is_projected,
        p2is_projected,
    );
    let is_greco_valid = greco.verify();

    assert(is_greco_valid);
}
