use crate::math::helpers::{compute_safe, flatten};
use crate::math::polynomial::Polynomial;

/// BFV Public Key Commitment Circuit (Circuit 0).
///
/// commit to the BFV public key for later verification.
/// No validation of pk correctness - that's caught by decryption failures in Circuit 4.
pub struct BfvPkCommit<let N: u32, let L: u32, let BIT_PK: u32> {
    /// BFV public key components (public input)
    /// pk0[i] is the first component for modulus i
    pk0: [Polynomial<N>; L],
    /// pk1[i] is the second component for modulus i
    pk1: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_PK: u32> BfvPkCommit<N, L, BIT_PK> {
    pub fn new(pk0: [Polynomial<N>; L], pk1: [Polynomial<N>; L]) -> Self {
        BfvPkCommit { pk0, pk1 }
    }

    /// Computes commitment to the BFV public key
    fn commit_to_pk(self) -> Field {
        let mut inputs = Vec::new();

        // Flatten pk0 polynomials
        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk0);

        // Flatten pk1 polynomials
        inputs = flatten::<_, _, BIT_PK>(inputs, self.pk1);

        // Domain separator - "PVSS_pk_bfv" in hex
        let domain_separator = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x62, 0x66, 0x76, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let input_size = inputs.len();
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        compute_safe(domain_separator, inputs, io_pattern).get(0)
    }

    /// Main verification function
    /// Returns commitment to BFV public key
    pub fn verify(self) -> Field {
        self.commit_to_pk()
    }
}
