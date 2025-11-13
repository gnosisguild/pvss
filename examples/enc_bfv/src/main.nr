use circuits::{crypto::greco::greco::{Greco, Params}, math::polynomial::Polynomial};

fn main(
    params: Params<256>,
    pk0: Polynomial<256>,
    pk1: Polynomial<256>,
    ct0: Polynomial<256>,
    ct1: Polynomial<256>,
    u: Polynomial<256>,
    e0: Polynomial<256>,
    e1: Polynomial<256>,
    k1: Polynomial<256>,
    r2: Polynomial<255>,
    p2: Polynomial<255>,
) {
    // Create Greco circuit instance.
    let greco: Greco<256, 41, 41, 2, 6, 6, 20, 20, 41> = Greco::new(
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

