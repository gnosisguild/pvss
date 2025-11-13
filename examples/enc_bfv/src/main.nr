use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};

fn main(
    params: Params<1024>,
    pk0: Polynomial<1024>,
    pk1: Polynomial<1024>,
    ct0: Polynomial<1024>,
    ct1: Polynomial<1024>,
    u: Polynomial<1024>,
    e0: Polynomial<1024>,
    e1: Polynomial<1024>,
    k1: Polynomial<1024>,
    r2: Polynomial<1023>,
    p2: Polynomial<1023>,
) {
    // Create Greco circuit instance.
    let greco: Greco<1024, 41, 41, 2, 6, 6, 20, 20, 41> = Greco::new(
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
