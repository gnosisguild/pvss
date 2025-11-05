// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};
fn main(
    params: Params<8192, 4>,
    pk0is: [Polynomial<8192>; 4],
    pk1is: [Polynomial<8192>; 4],
    ct0is: [Polynomial<8192>; 4],
    ct1is: [Polynomial<8192>; 4],
    u: Polynomial<8192>,
    e0: Polynomial<8192>,
    e1: Polynomial<8192>,
    e1is: [Polynomial<8192>; 4],
    k1: Polynomial<8192>,
    r1is: [Polynomial<16383>; 4],
    r2is: [Polynomial<8191>; 4],
    p1is: [Polynomial<16383>; 4],
    p2is: [Polynomial<8191>; 4],
    // TODO: Other parameters...
) {
    // TODO: Your logic here...

    // Create Greco circuit instance.
    let greco: Greco<8192, 4, 56, 56, 2, 6, 110, 10, 55, 56, 55, 56> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
        e1is,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    let is_greco_valid = greco.verify();

    assert(is_greco_valid);
    // TODO: Your logic here...
}
