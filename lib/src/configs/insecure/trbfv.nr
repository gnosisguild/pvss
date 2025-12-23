use crate::core::bfv_pk::Configs as BfvPkConfigs;
use crate::core::greco::Configs as GrecoConfigs;
use crate::core::trbfv_dec_share::Configs as DecShareTrBfvConfigs;
use crate::core::trbfv_dec_shares_agg::Configs as DecShareAggTrBfvConfigs;
use crate::core::trbfv_pk_agg::Configs as PkAggTrBfvConfigs;
use crate::core::trbfv_verify_shares::Configs as VerifySharesConfigs;

// Global configs for BFV parameter set
pub global N: u32 = 512;
pub global L: u32 = 2;
pub global PLAINTEXT_MODULUS: Field = 10;
pub global QIS: [Field; L] = [68719403009, 68719230977];
pub global Q_MOD_T_MOD_P: Field = 3;
pub global Q_MOD_T: Field = 3;
pub global Q_INVERSE_MOD_T: Field = 7;
pub global T_INV_MOD_Q: Field = 1416703358393105942938;

/************************************
-------------------------------------
pk_trbfv (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

// pk_trbfv - bit parameters
pub global PK_TRBFV_BIT_EEK: u32 = 6;
pub global PK_TRBFV_BIT_SK: u32 = 2;
pub global PK_TRBFV_BIT_R1: u32 = 14;
pub global PK_TRBFV_BIT_R2: u32 = 36;

// pk_trbfv - bounds
pub global PK_TRBFV_EEK_BOUND: Field = 20;
pub global PK_TRBFV_SK_BOUND: Field = 1;
pub global PK_TRBFV_R1_BOUNDS: [Field; L] = [5120, 5120];
pub global PK_TRBFV_R2_BOUNDS: [Field; L] = [34359701504, 34359615488];

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
verify_shares (CIRCUIT 3 - VERIFY SHARES)
-------------------------------------
************************************/

// verify_shares - bit parameters
pub global VERIFY_SHARES_BIT_SK: u32 = 2;
pub global VERIFY_SHARES_BIT_SHARE: u32 = 37;

// verify_shares - bounds
pub global VERIFY_SHARES_SK_BOUND: Field = 1;

// verify_shares - configs
pub global VERIFY_SHARES_CONFIGS: VerifySharesConfigs<L> =
    VerifySharesConfigs::new(QIS, VERIFY_SHARES_SK_BOUND);

/************************************
-------------------------------------
pk_agg_trbfv (CIRCUIT 6 - PUBLIC KEY AGGREGATION TRBFV)
-------------------------------------
************************************/

// pk_agg_trbfv - configs
pub global PK_AGG_TRBFV_CONFIGS: PkAggTrBfvConfigs<L> = PkAggTrBfvConfigs::new(QIS);

/************************************
-------------------------------------
greco (CIRCUIT 7 - ENCRYPTION TRBFV - GRECO)
-------------------------------------
************************************/

// greco - bit parameters
pub global ENC_TRBFV_BIT_PK: u32 = 36;
pub global ENC_TRBFV_BIT_CT: u32 = 36;
pub global ENC_TRBFV_BIT_U: u32 = 2;
pub global ENC_TRBFV_BIT_E0: u32 = 6;
pub global ENC_TRBFV_BIT_E1: u32 = 6;
pub global ENC_TRBFV_BIT_K: u32 = 4;
pub global ENC_TRBFV_BIT_R1: u32 = 10;
pub global ENC_TRBFV_BIT_R2: u32 = 36;
pub global ENC_TRBFV_BIT_P1: u32 = 10;
pub global ENC_TRBFV_BIT_P2: u32 = 36;

// greco - bounds
pub global ENC_TRBFV_Q_MOD_T: Field = 3;
pub global ENC_TRBFV_K0IS: [Field; L] = [61847462708, 20615769293];
pub global ENC_TRBFV_PK_BOUNDS: [Field; L] = [34359701504, 34359615488];
pub global ENC_TRBFV_E0_BOUND: Field = 20;
pub global ENC_TRBFV_E1_BOUND: Field = 20;
pub global ENC_TRBFV_U_BOUND: Field = 1;
pub global ENC_TRBFV_K1_LOW_BOUND: Field = 5;
pub global ENC_TRBFV_K1_UP_BOUND: Field = 4;
pub global ENC_TRBFV_R1_LOW_BOUNDS: [Field; L] = [261, 258];
pub global ENC_TRBFV_R1_UP_BOUNDS: [Field; L] = [260, 258];
pub global ENC_TRBFV_R2_BOUNDS: [Field; L] = [34359701504, 34359615488];
pub global ENC_TRBFV_P1_BOUNDS: [Field; L] = [256, 256];
pub global ENC_TRBFV_P2_BOUNDS: [Field; L] = [34359701504, 34359615488];

// greco - configs
pub global ENC_TRBFV_CONFIGS: GrecoConfigs<N, L> = GrecoConfigs::new(
    ENC_TRBFV_Q_MOD_T,
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

/************************************
-------------------------------------
trbfv_dec_share (CIRCUIT 8 - THRESHOLD BFV DECRYPTION SHARE)
-------------------------------------
************************************/

// dec_share_trbfv - bit parameters
pub global DEC_SHARES_BIT_CT: u32 = 36;
pub global DEC_SHARES_BIT_S: u32 = 36;
pub global DEC_SHARES_BIT_E: u32 = 36;
pub global DEC_SHARES_BIT_R1: u32 = 44;
pub global DEC_SHARES_BIT_R2: u32 = 36;
pub global DEC_SHARES_BIT_D: u32 = 36;

// dec_share_trbfv - bounds
pub global DEC_SHARES_DECRYPTION_SHARE_BOUND: Field = 34359701504;
pub global DEC_SHARES_R1_BOUNDS: [Field; L] = [8796083584897, 8796061564801];
pub global DEC_SHARES_R2_BOUNDS: [Field; L] = [34359701504, 34359615488];

// dec_share_trbfv - configs
pub global DEC_SHARES_CONFIGS: DecShareTrBfvConfigs<L> = DecShareTrBfvConfigs::new(
    QIS,
    DEC_SHARES_DECRYPTION_SHARE_BOUND,
    DEC_SHARES_R1_BOUNDS,
    DEC_SHARES_R2_BOUNDS,
);

/************************************
-------------------------------------
trbfv_dec_shares_agg (CIRCUIT 9 - THRESHOLD BFV DECRYPTION SHARES AGGREGATION)
-------------------------------------
************************************/

// dec_share_agg_trbfv - bit parameters
pub global DEC_SHARES_AGG_BIT_NOISE: u32 = 69;

// dec_share_agg_trbfv - configs
pub global DEC_SHARES_AGG_CONFIGS: DecShareAggTrBfvConfigs<L> =
    DecShareAggTrBfvConfigs::new(QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T);
