use crate::core::bfv_dec_no_hom_add::Config as BfvDecNoHomAddConfig;
use crate::core::bfv_pk::Configs as BfvPkConfigs;
use crate::core::greco::Configs as GrecoConfigs;

// Global configs for BFV parameter set
pub global N: u32 = 512;
pub global L: u32 = 1;
pub global L_PRIME: u32 = 1;
pub global L_TRBFV: u32 = 2;
pub global QIS: [Field; L] = [2251799813554177];
pub global Q_MOD_T: Field = 1082658244788225;
pub global TRBFV_QIS: [Field; L_TRBFV] = [68719403009, 68719230977];
pub global BFV_Q_INVERSE_MOD_T: Field = 39210117854;
pub global BFV_PLAINTEXT_MODULUS: Field = 68719403009;

/************************************
-------------------------------------
pk_bfv (CIRCUIT 2 - PUBLIC KEY BFV)
-------------------------------------
************************************/

// pk_bfv - bit parameters
pub global PK_BFV_BIT_EEK: u32 = 4;
pub global PK_BFV_BIT_SK: u32 = 2;
pub global PK_BFV_BIT_R1: u32 = 12;
pub global PK_BFV_BIT_R2: u32 = 51;

// pk_bfv - bounds
pub global PK_BFV_EEK_BOUND: Field = 6;
pub global PK_BFV_SK_BOUND: Field = 1;
pub global PK_BFV_R1_BOUNDS: [Field; L] = [1536];
pub global PK_BFV_R2_BOUNDS: [Field; L] = [1125899906777088];

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
pub global ENC_BFV_BIT_PK: u32 = 51;
pub global ENC_BFV_BIT_CT: u32 = 51;
pub global ENC_BFV_BIT_U: u32 = 2;
pub global ENC_BFV_BIT_E0: u32 = 4;
pub global ENC_BFV_BIT_E1: u32 = 4;
pub global ENC_BFV_BIT_K: u32 = 36;
pub global ENC_BFV_BIT_R1: u32 = 36;
pub global ENC_BFV_BIT_R2: u32 = 51;
pub global ENC_BFV_BIT_P1: u32 = 10;
pub global ENC_BFV_BIT_P2: u32 = 51;

// enc_bfv - bounds
pub global ENC_PK_BFV_BOUNDS: [Field; L] = [1125899906777088];
pub global ENC_BFV_E0_BOUND: Field = 6;
pub global ENC_BFV_E1_BOUND: Field = 6;
pub global ENC_BFV_U_BOUND: Field = 1;
pub global ENC_BFV_R1_LOW_BOUNDS: [Field; L] = [19605059183];
pub global ENC_BFV_R1_UP_BOUNDS: [Field; L] = [19605059183];
pub global ENC_BFV_R2_BOUNDS: [Field; L] = [1125899906777088];
pub global ENC_BFV_P1_BOUNDS: [Field; L] = [256];
pub global ENC_BFV_P2_BOUNDS: [Field; L] = [1125899906777088];
pub global ENC_BFV_K1_LOW_BOUND: Field = 34359701504;
pub global ENC_BFV_K1_UP_BOUND: Field = 34359701504;

// enc_bfv - misc
pub global ENC_BFV_K0IS: [Field; L] = [1284838520228573];

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
dec_bfv (CIRCUIT 5 - DECRYPTION BFV NO HOM ADD)
-------------------------------------
************************************/
// dec_bfv - bit parameters
pub global DEC_BFV_BIT_CT: u32 = 51;
pub global DEC_BFV_BIT_S: u32 = 2;
pub global DEC_BFV_BIT_U: u32 = 61;
pub global DEC_BFV_BIT_R1: u32 = 11;
pub global DEC_BFV_BIT_R2: u32 = 51;
pub global DEC_BFV_BIT_MSG: u32 = 16;

// dec_bfv - bounds
pub global DEC_BFV_S_BOUND: Field = 1;
pub global DEC_BFV_U_I_BOUNDS: [Field; L] = [577586652176646144];
pub global DEC_BFV_U_GLOBAL_BOUND: Field = 2251799813554177;
pub global DEC_BFV_R1_BOUNDS: [Field; L] = [512];
pub global DEC_BFV_R2_BOUNDS: [Field; L] = [1125899906777088];

// dec_bfv - misc
pub global DEC_BFV_DELTA: Field = 288230376426438664;
pub global DEC_BFV_DELTA_HALF: Field = 144115188213219332;

// dec_bfv - configs
pub global DEC_BFV_CONFIGS: BfvDecNoHomAddConfig<L_TRBFV, L_PRIME> = BfvDecNoHomAddConfig::new(
    QIS,
    BFV_PLAINTEXT_MODULUS,
    BFV_Q_INVERSE_MOD_T,
    TRBFV_QIS,
    DEC_BFV_S_BOUND,
    DEC_BFV_U_I_BOUNDS,
    DEC_BFV_U_GLOBAL_BOUND,
    DEC_BFV_R1_BOUNDS,
    DEC_BFV_R2_BOUNDS,
    DEC_BFV_DELTA,
    DEC_BFV_DELTA_HALF,
);
