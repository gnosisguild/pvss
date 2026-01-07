use lib::configs::production::bfv::{L, N, PK_BFV_BIT_PK};
use lib::core::bfv_pk::BfvPkCommit;
use lib::math::polynomial::Polynomial;

fn main(pk0: [Polynomial<N>; L], pk1: [Polynomial<N>; L]) -> pub Field {
    let circuit: BfvPkCommit<N, L, PK_BFV_BIT_PK> = BfvPkCommit::new(pk0, pk1);

    circuit.verify()
}
