use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};

fn main(
    params: Params<512, 1>,
    pk0is: [Polynomial<512>; 1],
    pk1is: [Polynomial<512>; 1],
    ct0is: [Polynomial<512>; 1],
    ct1is: [Polynomial<512>; 1],
    u: Polynomial<512>,
    e0: Polynomial<512>,
    e0is: [Polynomial<512>; 1],
    e0_quotients: [Polynomial<512>; 1],
    e1: Polynomial<512>,
    k1: Polynomial<512>,
    r1is: [Polynomial<1023>; 1],
    r2is: [Polynomial<511>; 1],
    p1is: [Polynomial<1023>; 1],
    p2is: [Polynomial<511>; 1],
) {
    let greco: Greco<512, 1, 51, 51, 2, 4, 4, 36, 36, 51, 10, 51> = Greco::new(
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
    );
    let is_greco_valid = greco.verify();
    assert(is_greco_valid);
}
