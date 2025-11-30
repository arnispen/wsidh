// include/wsidh_variants.h
#ifndef WSIDH_VARIANTS_H
#define WSIDH_VARIANTS_H

#include <stddef.h>
#include <stdint.h>

#define WSIDH_PARAM_WS512  512

typedef int wsidh_param_id_t;

#ifndef WSIDH_PARAM_SET
#define WSIDH_PARAM_SET WSIDH_PARAM_WS512
#elif WSIDH_PARAM_SET != WSIDH_PARAM_WS512
#error "WSIDH now exposes only the WSIDH512 parameter set."
#endif

#define WSIDH_VARIANT_NAME "WSIDH512"

#define WSIDH_PARAM_N        256
#define WSIDH_PARAM_Q        3329
#define WSIDH_PARAM_BOUND_S  3
#define WSIDH_PARAM_BOUND_E  2

typedef struct {
    const char *name;
    wsidh_param_id_t id;
    int degree;
    int modulus;
    int bound_s;
    int bound_e;
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes;
} wsidh_param_info_t;

extern const wsidh_param_info_t wsidh_active_params;
extern const wsidh_param_info_t wsidh_known_variants[];
extern const size_t wsidh_known_variants_len;

#endif // WSIDH_VARIANTS_H
