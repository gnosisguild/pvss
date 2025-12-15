use crate::core::bfv_pk::Configs as BfvPkConfigs;
use crate::core::greco::Configs as GrecoConfigs;

// Global configs for BFV parameter set
pub global N: u32 = 8192;
pub global L: u32 = 4;
pub global QIS: [Field; L] =
    [2251799822204929, 4503599627763713, 4503599631433729, 4503599634579457];
pub global Q_MOD_T: Field =
    21888242871839275222246405745257275088548364400416034343698204186575808495598;

/************************************
-------------------------------------
pk_trbfv (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

// pk_trbfv - bit parameters
pub global PK_TRBFV_BIT_EEK: u32 = 6;
pub global PK_TRBFV_BIT_SK: u32 = 2;
pub global PK_TRBFV_BIT_R1: u32 = 18;
pub global PK_TRBFV_BIT_R2: u32 = 53;

// pk_trbfv - bounds
pub global PK_TRBFV_EEK_BOUND: Field = 20;
pub global PK_TRBFV_SK_BOUND: Field = 1;
pub global PK_TRBFV_R1_BOUNDS: [Field; L] = [81920, 81920, 81920, 81920];
pub global PK_TRBFV_R2_BOUNDS: [Field; L] =
    [1125899911102464, 2251799813881856, 2251799815716864, 2251799817289728];

// pk_trbfv - configs
pub global PK_TRBFV_CONFIGS: BfvPkConfigs<N, L> = BfvPkConfigs::new(
    QIS,
    PK_TRBFV_EEK_BOUND,
    PK_TRBFV_SK_BOUND,
    PK_TRBFV_R1_BOUNDS,
    PK_TRBFV_R2_BOUNDS,
);

/************************************
-------------------------------------
enc_trbfv (CIRCUIT 6 - ENCRYPTION THRESHOLD BFV - GRECO)
-------------------------------------
************************************/

// enc_trbfv - bit parameters
pub global ENC_TRBFV_BIT_PK: u32 = 52;
pub global ENC_TRBFV_BIT_CT: u32 = 52;
pub global ENC_TRBFV_BIT_U: u32 = 2;
pub global ENC_TRBFV_BIT_E0: u32 = 107;
pub global ENC_TRBFV_BIT_E1: u32 = 6;
pub global ENC_TRBFV_BIT_K: u32 = 7;
pub global ENC_TRBFV_BIT_R1: u32 = 14;
pub global ENC_TRBFV_BIT_R2: u32 = 53;
pub global ENC_TRBFV_BIT_P1: u32 = 14;
pub global ENC_TRBFV_BIT_P2: u32 = 53;

// enc_trbfv - bounds
pub global ENC_TRBFV_PK_BOUNDS: [Field; L] =
    [1125899911102464, 2251799813881856, 2251799815716864, 2251799817289728];
pub global ENC_TRBFV_E0_BOUND: Field = 54890881146011919040994244755389;
pub global ENC_TRBFV_E1_BOUND: Field = 20;
pub global ENC_TRBFV_U_BOUND: Field = 1;
pub global ENC_TRBFV_R1_LOW_BOUNDS: [Field; L] = [4132, 4136, 4131, 4143];
pub global ENC_TRBFV_R1_UP_BOUNDS: [Field; L] = [4131, 4135, 4131, 4142];
pub global ENC_TRBFV_R2_BOUNDS: [Field; L] =
    [1125899911102464, 2251799813881856, 2251799815716864, 2251799817289728];
pub global ENC_TRBFV_P1_BOUNDS: [Field; L] = [4096, 4096, 4096, 4096];
pub global ENC_TRBFV_P2_BOUNDS: [Field; L] =
    [1125899911102464, 2251799813881856, 2251799815716864, 2251799817289728];
pub global ENC_TRBFV_K1_LOW_BOUND: Field = 50;
pub global ENC_TRBFV_K1_UP_BOUND: Field = 49;

// enc_trbfv - misc
pub global ENC_TRBFV_K0IS: [Field; L] =
    [1553741877321401, 3467771713378059, 3107483745689273, 4188347660158895];

// enc_trbfv - configs
pub global ENC_TRBFV_CONFIGS: GrecoConfigs<N, L> = GrecoConfigs::new(
    Q_MOD_T,
    QIS,
    ENC_TRBFV_K0IS,
    ENC_TRBFV_PK_BOUNDS,
    ENC_TRBFV_E0_BOUND,
    ENC_TRBFV_E1_BOUND,
    ENC_TRBFV_U_BOUND,
    ENC_TRBFV_R1_LOW_BOUNDS,
    ENC_TRBFV_R1_UP_BOUNDS,
    ENC_TRBFV_R2_BOUNDS,
    ENC_TRBFV_P1_BOUNDS,
    ENC_TRBFV_P2_BOUNDS,
    ENC_TRBFV_K1_LOW_BOUND,
    ENC_TRBFV_K1_UP_BOUND,
);
