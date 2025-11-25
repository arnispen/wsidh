#include "wsidh_variants.h"
#include "wsidh_kem.h"

const wsidh_param_info_t wsidh_active_params = {
    .name = WSIDH_VARIANT_NAME,
    .id = (wsidh_param_id_t)WSIDH_PARAM_SET,
    .degree = WSIDH_N,
    .modulus = WSIDH_Q,
    .bound_s = WSIDH_BOUND_S,
    .bound_e = WSIDH_BOUND_E,
    .pk_bytes = WSIDH_PK_BYTES,
    .sk_bytes = WSIDH_SK_BYTES,
    .ct_bytes = WSIDH_CT_BYTES,
    .ss_bytes = WSIDH_SS_BYTES,
};

const wsidh_param_info_t wsidh_known_variants[] = {
    {
        .name = "WSIDH512",
        .id = WSIDH_PARAM_WS512,
        .degree = 256,
        .modulus = 3329,
        .bound_s = 3,
        .bound_e = 2,
        .pk_bytes = 384,
        .sk_bytes = 1472,
        .ct_bytes = 768,
        .ss_bytes = 32,
    },
    {
        .name = "WSIDH768",
        .id = WSIDH_PARAM_WS768,
        .degree = 256, // TODO: generalize to N=384 once NTT roots are extended.
        .modulus = 3329,
        .bound_s = 4,
        .bound_e = 3,
        .pk_bytes = 384,
        .sk_bytes = 1472,
        .ct_bytes = 768,
        .ss_bytes = 32,
    },
    {
        .name = "WSIDH1024",
        .id = WSIDH_PARAM_WS1024,
        .degree = 256, // TODO: bump to N=512 when wave/NTT tables are generalized.
        .modulus = 3329,
        .bound_s = 5,
        .bound_e = 4,
        .pk_bytes = 384,
        .sk_bytes = 1472,
        .ct_bytes = 768,
        .ss_bytes = 32,
    },
};

const size_t wsidh_known_variants_len =
    sizeof(wsidh_known_variants) / sizeof(wsidh_known_variants[0]);
