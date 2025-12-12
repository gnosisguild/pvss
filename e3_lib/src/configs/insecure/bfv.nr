use crate::core::greco::{Bounds, Constants};

// Global configs for BFV
pub global N: u32 = 8192;
pub global L: u32 = 2;
pub global QIS: [Field; 2] = [72057594082099201, 72057594062438401];
pub global Q_MOD_T: Field = 1082658244788225;

/************************************
-------------------------------------
CIRCUIT 4 (ENCRYPTION BFV - GRECO)
-------------------------------------
************************************/

// Circuit4 - Bit parameters
pub global C4_BIT_PK: u32 = 57;
pub global C4_BIT_CT: u32 = 57;
pub global C4_BIT_U: u32 = 2;
pub global C4_BIT_E0: u32 = 6;
pub global C4_BIT_E1: u32 = 6;
pub global C4_BIT_K: u32 = 55;
pub global C4_BIT_R1: u32 = 54;
pub global C4_BIT_R2: u32 = 57;
pub global C4_BIT_P1: u32 = 14;
pub global C4_BIT_P2: u32 = 57;

// Circuit4 - Bounds
pub global C4_PK_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global C4_E0_BOUND: Field = 20;
pub global C4_E1_BOUND: Field = 20;
pub global C4_U_BOUND: Field = 1;
pub global C4_R1_LOW_BOUNDS: [Field; 2] = [8856849607495681, 5929880944709633];
pub global C4_R1_UP_BOUNDS: [Field; 2] = [8856849607495680, 5929880944709632];
pub global C4_R2_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global C4_P1_BOUNDS: [Field; 2] = [4096, 4096];
pub global C4_P2_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global C4_K1_LOW_BOUND: Field = 9007199254740992;
pub global C4_K1_UP_BOUND: Field = 9007199254740991;

// Circuit4 - Other configs
pub global C4_K0IS: [Field; 2] = [70854796903366627, 47439047573780733];

// Circuit4 - Constants
pub global C4_CONSTANTS: Constants<N, L> = Constants::new(
    Q_MOD_T,
    QIS,
    C4_K0IS,
    C4_PK_BOUNDS,
    C4_E0_BOUND,
    C4_E1_BOUND,
    C4_U_BOUND,
    C4_R1_LOW_BOUNDS,
    C4_R1_UP_BOUNDS,
    C4_R2_BOUNDS,
    C4_P1_BOUNDS,
    C4_P2_BOUNDS,
    C4_K1_LOW_BOUND,
    C4_K1_UP_BOUND,
);

/************************************
-------------------------------------
CIRCUIT 5 (DECRYPTION BFV)
-------------------------------------
************************************/