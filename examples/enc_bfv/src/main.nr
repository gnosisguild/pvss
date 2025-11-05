use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};

fn main(
    params: Params<8192, 2>,
    pk0is: [Polynomial<8192>; 2],
    pk1is: [Polynomial<8192>; 2],
    ct0is: [Polynomial<8192>; 2],
    ct1is: [Polynomial<8192>; 2],
    u: Polynomial<8192>,
    e0: Polynomial<8192>,
    e1is: [Polynomial<8192>; 2],
    k1: Polynomial<8192>,
    r1is: [Polynomial<16383>; 2],
    r2is: [Polynomial<8191>; 2],
    p1is: [Polynomial<16383>; 2],
    p2is: [Polynomial<8191>; 2],
) {
    let greco: Greco<8192, 2, 59, 59, 2, 6, 6, 57, 57, 59, 18, 59> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1is,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    let is_greco_valid = greco.verify();
    assert(is_greco_valid);
}
