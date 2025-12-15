use crate::core::bfv_pk::Configs as BfvPkConfigs;
use crate::core::greco::Configs as GrecoConfigs;

// Global configs for BFV parameter set
pub global N: u32 = 8192;
pub global L: u32 = 2;
pub global QIS: [Field; 2] = [72057594082099201, 72057594062438401];
pub global Q_MOD_T: Field = 1082658244788225;

/************************************
-------------------------------------
bfv_pk (CIRCUIT 2 - PUBLIC KEY BFV)
-------------------------------------
************************************/

// bfv_pk - bit parameters
pub global BFV_PK_BIT_EEK: u32 = 6;
pub global BFV_PK_BIT_SK: u32 = 2;
pub global BFV_PK_BIT_R1: u32 = 18;
pub global BFV_PK_BIT_R2: u32 = 57;

// bfv_pk - bounds
pub global BFV_PK_EEK_BOUND: Field = 20;
pub global BFV_PK_SK_BOUND: Field = 1;
pub global BFV_PK_R1_BOUNDS: [Field; 2] = [81920, 81920];
pub global BFV_PK_R2_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];

// bfv_pk - configs
pub global BFV_PK_CONFIGS: BfvPkConfigs<N, L> = BfvPkConfigs::new(
    QIS,
    BFV_PK_EEK_BOUND,
    BFV_PK_SK_BOUND,
    BFV_PK_R1_BOUNDS,
    BFV_PK_R2_BOUNDS,
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
pub global ENC_BFV_PK_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_E0_BOUND: Field = 20;
pub global ENC_BFV_E1_BOUND: Field = 20;
pub global ENC_BFV_U_BOUND: Field = 1;
pub global ENC_BFV_R1_LOW_BOUNDS: [Field; 2] = [8856849607495681, 5929880944709633];
pub global ENC_BFV_R1_UP_BOUNDS: [Field; 2] = [8856849607495680, 5929880944709632];
pub global ENC_BFV_R2_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_P1_BOUNDS: [Field; 2] = [4096, 4096];
pub global ENC_BFV_P2_BOUNDS: [Field; 2] = [36028797041049600, 36028797031219200];
pub global ENC_BFV_K1_LOW_BOUND: Field = 9007199254740992;
pub global ENC_BFV_K1_UP_BOUND: Field = 9007199254740991;

// enc_bfv - misc
pub global ENC_BFV_K0IS: [Field; 2] = [70854796903366627, 47439047573780733];

// enc_bfv - configs
pub global ENC_BFV_CONFIGS: GrecoConfigs<N, L> = GrecoConfigs::new(
    Q_MOD_T,
    QIS,
    ENC_BFV_K0IS,
    ENC_BFV_PK_BOUNDS,
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
CIRCUIT 5 (DECRYPTION BFV)
-------------------------------------
************************************/
