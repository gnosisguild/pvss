use crate::core::bfv_dec::Configs as BfvDecConfigs;
use crate::core::bfv_pk::Configs as BfvPkConfigs;
use crate::core::greco::Configs as GrecoConfigs;

// Global configs for BFV parameter set
pub global N: u32 = 8192;
pub global L: u32 = 2;
pub global QIS: [Field; L] = [72057594082099201, 72057594062438401];
pub global Q_MOD_T: Field = 1082658244788225;
pub global PLAINTEXT_MODULUS: Field = 18014398509481984;
pub global Q_INVERSE_MOD_T: Field = 3634521516277761;
pub global T_INVERSE_MOD_Q: Field = 4144717358717138174408418870545186;

/************************************
-------------------------------------
pk_bfv (CIRCUIT 2 - PUBLIC KEY BFV)
-------------------------------------
************************************/

// pk_bfv - bit parameters
pub global PK_BFV_BIT_EEK: u32 = 6;
pub global PK_BFV_BIT_SK: u32 = 2;
pub global PK_BFV_BIT_R1: u32 = 18;
pub global PK_BFV_BIT_R2: u32 = 57;

// pk_bfv - bounds
pub global PK_BFV_EEK_BOUND: Field = 20;
pub global PK_BFV_SK_BOUND: Field = 1;
pub global PK_BFV_R1_BOUNDS: [Field; L] = [81920, 81920];
pub global PK_BFV_R2_BOUNDS: [Field; L] = [36028797041049600, 36028797031219200];

// pk_bfv - configs
pub global PK_BFV_CONFIGS: BfvPkConfigs<N, L> = BfvPkConfigs::new(
    QIS,
    PK_BFV_EEK_BOUND,
    PK_BFV_SK_BOUND,
    PK_BFV_R1_BOUNDS,
    PK_BFV_R2_BOUNDS,
);

/************************************
-------------------------------------
enc_bfv (CIRCUIT 4 - ENCRYPTION BFV - GRECO)
-------------------------------------
************************************/

// enc_bfv - bit parameters
pub global ENC_BFV_BIT_PK: u32 = 57;
pub global ENC_BFV_BIT_CT: u32 = 57;
pub global ENC_BFV_BIT_U: u32 = 2;
pub global ENC_BFV_BIT_E0: u32 = 6;
pub global ENC_BFV_BIT_E1: u32 = 6;
pub global ENC_BFV_BIT_K: u32 = 55;
pub global ENC_BFV_BIT_R1: u32 = 54;
pub global ENC_BFV_BIT_R2: u32 = 57;
pub global ENC_BFV_BIT_P1: u32 = 14;
pub global ENC_BFV_BIT_P2: u32 = 57;

// enc_bfv - bounds
pub global ENC_PK_BFV_BOUNDS: [Field; L] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_E0_BOUND: Field = 20;
pub global ENC_BFV_E1_BOUND: Field = 20;
pub global ENC_BFV_U_BOUND: Field = 1;
pub global ENC_BFV_R1_LOW_BOUNDS: [Field; L] = [8856849607495681, 5929880944709633];
pub global ENC_BFV_R1_UP_BOUNDS: [Field; L] = [8856849607495680, 5929880944709632];
pub global ENC_BFV_R2_BOUNDS: [Field; L] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_P1_BOUNDS: [Field; L] = [4096, 4096];
pub global ENC_BFV_P2_BOUNDS: [Field; L] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_K1_LOW_BOUND: Field = 9007199254740992;
pub global ENC_BFV_K1_UP_BOUND: Field = 9007199254740991;

// enc_bfv - misc
pub global ENC_BFV_K0IS: [Field; L] = [70854796903366627, 47439047573780733];

// enc_bfv - configs
pub global ENC_BFV_CONFIGS: GrecoConfigs<N, L> = GrecoConfigs::new(
    Q_MOD_T,
    QIS,
    ENC_BFV_K0IS,
    ENC_PK_BFV_BOUNDS,
    ENC_BFV_E0_BOUND,
    ENC_BFV_E1_BOUND,
    ENC_BFV_U_BOUND,
    ENC_BFV_R1_LOW_BOUNDS,
    ENC_BFV_R1_UP_BOUNDS,
    ENC_BFV_R2_BOUNDS,
    ENC_BFV_P1_BOUNDS,
    ENC_BFV_P2_BOUNDS,
    ENC_BFV_K1_LOW_BOUND,
    ENC_BFV_K1_UP_BOUND,
);

/************************************
-------------------------------------
dec_bfv (CIRCUIT 5 - DECRYPTION BFV)
-------------------------------------
************************************/
// dec_bfv - bit parameters
pub global DEC_BFV_BIT_CT: u32 = 57;
pub global DEC_BFV_BIT_S: u32 = 2;
pub global DEC_BFV_BIT_U: u32 = 114;
pub global DEC_BFV_BIT_R1: u32 = 15;
pub global DEC_BFV_BIT_R2: u32 = 57;
pub global DEC_BFV_BIT_NOISE: u32 = 59;

// dec_bfv - bounds
pub global DEC_BFV_S_BOUND: Field = 1;
pub global DEC_BFV_U_I_BOUNDS: [Field; L] = [295183934157319372800, 295183934076778905600];
pub global DEC_BFV_U_GLOBAL_BOUND: Field = 5192296863483867847775730833817601;
pub global DEC_BFV_R1_BOUNDS: [Field; L] = [8192, 8192];
pub global DEC_BFV_R2_BOUNDS: [Field; L] = [36028797041049600, 36028797031219200];

// dec_bfv - misc
pub global DEC_BFV_DELTA: Field = 288230376426438664;
pub global DEC_BFV_DELTA_HALF: Field = 144115188213219332;

// dec_bfv - configs
pub global DEC_BFV_CONFIGS: BfvDecConfigs<L> = BfvDecConfigs::new(
    QIS,
    PLAINTEXT_MODULUS,
    Q_INVERSE_MOD_T,
    DEC_BFV_S_BOUND,
    DEC_BFV_U_I_BOUNDS,
    DEC_BFV_U_GLOBAL_BOUND,
    DEC_BFV_R1_BOUNDS,
    DEC_BFV_R2_BOUNDS,
    DEC_BFV_DELTA,
    DEC_BFV_DELTA_HALF,
);
