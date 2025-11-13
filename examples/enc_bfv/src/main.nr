use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};

fn main(
    params: Params<2048>,
    pk0: Polynomial<2048>,
    pk1: Polynomial<2048>,
    ct0: Polynomial<2048>,
    ct1: Polynomial<2048>,
    u: Polynomial<2048>,
    e0: Polynomial<2048>,
    e1: Polynomial<2048>,
    k1: Polynomial<2048>,
    r2: Polynomial<2047>,
    p2: Polynomial<2047>,
) {
    // Create Greco circuit instance.
    let greco: Greco<2048, 49, 49, 2, 6, 6, 20, 18, 49> = Greco::new(
        params,
        pk0,
        pk1,
        ct0,
        ct1,
        u,
        e0,
        e1,
        k1,
        r2,
        p2,
    );
    
    let is_greco_valid = greco.verify();
    assert(is_greco_valid);
}
