use crate::crypto::pk_trbfv::constants::{EEK_BOUND, L, N, QIS, R1_LOW_BOUNDS, R1_UP_BOUNDS, R2_BOUNDS, SK_BOUND};
use crate::math::polynomial::Polynomial;
use poseidon::poseidon2::Poseidon2;

//the formulas are in the RNS mode
pub struct BfvPublicKeyCircuit {
    a: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1is: [Polynomial<2 * N - 1>; L],
    r2is: [Polynomial<2 * N - 1>; L],
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
}

impl BfvPublicKeyCircuit {
    pub fn new(
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1is: [Polynomial<2 * N - 1>; L],
        r2is: [Polynomial<2 * N - 1>; L],
        pk0is: [Polynomial<N>; L],
        pk1is: [Polynomial<N>; L],
    ) -> Self {
        BfvPublicKeyCircuit {
            a,
            eek,
            sk,
            r1is,
            r2is,
            pk0is,
            pk1is,
        }
    }

    pub fn correct_bfv_public_key(self) {
        // Bound checks
        self.eek.range_check_1bound(EEK_BOUND);
        self.sk.range_check_1bound(SK_BOUND);

        for i in 0..L {
            self.r1is[i].range_check_2bounds(R1_UP_BOUNDS[i], R1_LOW_BOUNDS[i]);
            self.r2is[i].range_check_1bound(R2_BOUNDS[i]);
        }

        // @todo: generate the input using the safe API
        let input = [1, 2, 3];
        let size = 3;
        let gamma = Poseidon2::hash(input, size);
        let a_at_gamma = self.a.map(|a| a.eval(gamma));
        let eek_at_gamma = self.eek.eval(gamma);
        let sk_at_gamma = self.sk.eval(gamma);

        let r1i_at_gamma = self.r1is.map(|r1| r1.eval(gamma));
        let r2i_at_gamma = self.r2is.map(|r2| r2.eval(gamma));

        // Evaluate the public key polynomials at gamma
        let pk0is_at_gamma = self.pk0is.map(|p1| p1.eval(gamma));
        let pk1is_at_gamma = self.pk1is.map(|p2| p2.eval(gamma));

        // cyclo poly is equal to x^N + 1
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;

        // Check the correctness of the public key
        for i in 0..L {
            assert_eq(
                pk0is_at_gamma[i],
                -a_at_gamma[i] * sk_at_gamma
                    + eek_at_gamma
                    + r2i_at_gamma[i] * cyclo_at_gamma
                    + r1i_at_gamma[i] * QIS[i],
            );
            assert_eq(pk1is_at_gamma[i], -a_at_gamma[i]);
        }
    }
}
