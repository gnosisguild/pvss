// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::polynomial::{flatten, Polynomial};
use crate::math::safe::SafeSponge;

/// PLEASE NOTE THIS VERSION OF GRECO IS JUST USED FOR DEVELOPMENT.
/// REFER TO THE ORIGINAL GRECO CIRCUIT FOR THE PRODUCTION VERSION IN ENCLAVE MONOREPO.

pub struct Bounds<let L: u32> {
    pub pk_bounds: [Field; L],
    pub e0_bound: Field,
    pub e1_bound: Field,
    pub u_bound: Field,
    pub r1_low_bounds: [Field; L],
    pub r1_up_bounds: [Field; L],
    pub r2_bounds: [Field; L],
    pub p1_bounds: [Field; L],
    pub p2_bounds: [Field; L],
    pub k1_low_bound: Field,
    pub k1_up_bound: Field,
}

impl<let L: u32> Bounds<L> {
    pub fn new(
        pk_bounds: [Field; L],
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
        k1_low_bound: Field,
        k1_up_bound: Field,
    ) -> Self {
        Bounds {
            pk_bounds,
            e0_bound,
            e1_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            p1_bounds,
            p2_bounds,
            k1_low_bound,
            k1_up_bound,
        }
    }
}

pub struct Constants<let N: u32, let L: u32> {
    pub qis: [Field; L],
    pub q_mod_t: Field,
    pub k0is: [Field; L],
    pub bounds: Bounds<L>,
}

impl<let N: u32, let L: u32> Constants<N, L> {
    pub fn new(
        q_mod_t: Field,
        qis: [Field; L],
        k0is: [Field; L],
        pk_bounds: [Field; L],
        e0_bound: Field,
        e1_bound: Field,
        u_bound: Field,
        r1_low_bounds: [Field; L],
        r1_up_bounds: [Field; L],
        r2_bounds: [Field; L],
        p1_bounds: [Field; L],
        p2_bounds: [Field; L],
        k1_low_bound: Field,
        k1_up_bound: Field,
    ) -> Self {
        let bounds = Bounds::new(
            pk_bounds,
            e0_bound,
            e1_bound,
            u_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            p1_bounds,
            p2_bounds,
            k1_low_bound,
            k1_up_bound,
        );

        Constants { qis, q_mod_t, k0is, bounds }
    }
}

pub struct Greco<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> {
    constants: Constants<N, L>,
    commitment_pk_ct: Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    k1: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_E1: u32, let BIT_K: u32, let BIT_R1: u32, let BIT_R2: u32, let BIT_P1: u32, let BIT_P2: u32> Greco<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R1, BIT_R2, BIT_P1, BIT_P2> {
    pub fn new(
        constants: Constants<N, L>,
        commitment_pk_ct: Field,
        pk0is: [Polynomial<N>; L],
        pk1is: [Polynomial<N>; L],
        ct0is: [Polynomial<N>; L],
        ct1is: [Polynomial<N>; L],
        u: Polynomial<N>,
        e0: Polynomial<N>,
        e1: Polynomial<N>,
        e0is: [Polynomial<N>; L],
        k1: Polynomial<N>,
        r1is: [Polynomial<2 * N - 1>; L],
        r2is: [Polynomial<N - 1>; L],
        p1is: [Polynomial<2 * N - 1>; L],
        p2is: [Polynomial<N - 1>; L],
    ) -> Greco<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_E1, BIT_K, BIT_R1, BIT_R2, BIT_P1, BIT_P2> {
        Greco {
            constants,
            commitment_pk_ct,
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            u,
            e0,
            e1,
            e0is,
            k1,
            r1is,
            r2is,
            p1is,
            p2is,
        }
    }

    pub fn verify(self) -> bool {
        self.check_range_bounds();
        self.verify_evaluations(self.generate_challenge())
    }

    fn commitment_payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk0is);
        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk1is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct0is);
        inputs = flatten::<_, _, BIT_CT>(inputs, self.ct1is);

        inputs
    }

    fn gammas_payload(self) -> Vec<Field> {
        let mut inputs = Vec::new();

        inputs.push(self.commitment_pk_ct);
        // Flatten common polynomials (used across all CRT bases)
        inputs = flatten::<_, _, BIT_E0>(inputs, [self.e0]);
        inputs = flatten::<_, _, BIT_E1>(inputs, [self.e1]);
        inputs = flatten::<_, _, BIT_U>(inputs, [self.u]);
        inputs = flatten::<_, _, BIT_K>(inputs, [self.k1]);

        // Flatten randomness polynomials for each CRT basis
        inputs = flatten::<_, _, BIT_R1>(inputs, self.r1is);
        inputs = flatten::<_, _, BIT_R2>(inputs, self.r2is);
        inputs = flatten::<_, _, BIT_P1>(inputs, self.p1is);
        inputs = flatten::<_, _, BIT_P2>(inputs, self.p2is);

        inputs
    }

    fn check_range_bounds(self) {
        let bound_params = self.constants.bounds;

        self.u.range_check_2bounds::<BIT_U>(bound_params.u_bound, bound_params.u_bound);
        self.e0.range_check_2bounds::<BIT_E0>(bound_params.e0_bound, bound_params.e0_bound);
        self.e1.range_check_2bounds::<BIT_E1>(bound_params.e1_bound, bound_params.e1_bound);
        self.k1.range_check_2bounds::<BIT_K>(bound_params.k1_up_bound, bound_params.k1_low_bound);

        for i in 0..L {
            self.pk0is[i].range_check_2bounds::<BIT_PK>(
                bound_params.pk_bounds[i],
                bound_params.pk_bounds[i],
            );
            self.pk1is[i].range_check_2bounds::<BIT_PK>(
                bound_params.pk_bounds[i],
                bound_params.pk_bounds[i],
            );

            self.r1is[i].range_check_2bounds::<BIT_R1>(
                bound_params.r1_up_bounds[i],
                bound_params.r1_low_bounds[i],
            );
            self.r2is[i].range_check_2bounds::<BIT_R2>(
                bound_params.r2_bounds[i],
                bound_params.r2_bounds[i],
            );

            self.p1is[i].range_check_2bounds::<BIT_P1>(
                bound_params.p1_bounds[i],
                bound_params.p1_bounds[i],
            );
            self.p2is[i].range_check_2bounds::<BIT_P2>(
                bound_params.p2_bounds[i],
                bound_params.p2_bounds[i],
            );
        }
    }

    fn generate_challenge(self) -> Vec<Field> {
        let domain_separator = [
            0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(1)
        let inputs = self.commitment_payload();
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | 1];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let commitment = sponge.squeeze();
        sponge.finish();

        print(commitment);

        assert_eq(commitment.get(0), self.commitment_pk_ct);

        // IO Pattern: ABSORB(input_size), SQUEEZE(2*L)
        let inputs = self.gammas_payload();
        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000000 | (2 * L)];

        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(inputs);
        let gammas = sponge.squeeze();

        sponge.finish();
        gammas
    }

    fn verify_evaluations(self, gammas: Vec<Field>) -> bool {
        let gamma = gammas.get(0);
        let cyclo_at_gamma = gamma.pow_32(N as Field) + 1;
        let u_at_gamma = self.u.eval(gamma);
        let e1_at_gamma = self.e1.eval(gamma);
        let k1_at_gamma = self.k1.eval(gamma);

        let mut sum = (0, 0);
        for i in 0..L {
            let pk0is_at_gamma = self.pk0is[i].eval(gamma);
            let r1i_at_gamma = self.r1is[i].eval(gamma);
            let r2i_at_gamma = self.r2is[i].eval(gamma);
            let e0is_at_gamma = self.e0is[i].eval(gamma);
            let pk0_u = (pk0is_at_gamma * u_at_gamma) + e0is_at_gamma;
            let mut ct0_rhs = pk0_u + (k1_at_gamma * self.constants.k0is[i]);
            ct0_rhs += r1i_at_gamma * self.constants.qis[i];
            ct0_rhs += r2i_at_gamma * cyclo_at_gamma;
            let ct0_lhs = self.ct0is[i].eval(gamma);
            let pk1is_at_gamma = self.pk1is[i].eval(gamma);
            let p1is_at_gamma = self.p1is[i].eval(gamma);
            let p2is_at_gamma = self.p2is[i].eval(gamma);
            let pk1_u = (pk1is_at_gamma * u_at_gamma) + e1_at_gamma;
            let mut ct1_rhs = pk1_u + p2is_at_gamma * cyclo_at_gamma;
            ct1_rhs += p1is_at_gamma * self.constants.qis[i];
            let ct1_lhs = self.ct1is[i].eval(gamma);
            let gamma_i = if i == 0 { 1 } else { gammas.get(i) };
            sum = (
                sum.0 + ct0_lhs * gamma_i + ct1_lhs * gammas.get(i + L),
                sum.1 + ct0_rhs * gamma_i + ct1_rhs * gammas.get(i + L),
            );
        }
        sum.0 == sum.1
    }
}
