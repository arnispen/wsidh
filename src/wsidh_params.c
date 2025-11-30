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
        .degree = WSIDH_N,
        .modulus = WSIDH_Q,
        .bound_s = WSIDH_BOUND_S,
        .bound_e = WSIDH_BOUND_E,
        .pk_bytes = WSIDH_PK_BYTES,
        .sk_bytes = WSIDH_SK_BYTES,
        .ct_bytes = WSIDH_CT_BYTES,
        .ss_bytes = WSIDH_SS_BYTES,
    },
};

const size_t wsidh_known_variants_len =
    sizeof(wsidh_known_variants) / sizeof(wsidh_known_variants[0]);
