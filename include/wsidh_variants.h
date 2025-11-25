// include/wsidh_variants.h
#ifndef WSIDH_VARIANTS_H
#define WSIDH_VARIANTS_H

#include <stddef.h>
#include <stdint.h>

#define WSIDH_PARAM_WS512  512
#define WSIDH_PARAM_WS768  768
#define WSIDH_PARAM_WS1024 1024

typedef int wsidh_param_id_t;

#ifndef WSIDH_PARAM_SET
#define WSIDH_PARAM_SET WSIDH_PARAM_WS512
#endif

#ifndef WSIDH_VARIANT_NAME
#if WSIDH_PARAM_SET == WSIDH_PARAM_WS512
#define WSIDH_VARIANT_NAME "WSIDH512"
#elif WSIDH_PARAM_SET == WSIDH_PARAM_WS768
#define WSIDH_VARIANT_NAME "WSIDH768"
#elif WSIDH_PARAM_SET == WSIDH_PARAM_WS1024
#define WSIDH_VARIANT_NAME "WSIDH1024"
#else
#error "Unknown WSIDH_PARAM_SET"
#endif
#endif

/*
 * Parameter skeletons for each WSIDH variant.
 *
 * NOTE: For now, all parameter sets reuse the same lattice dimension (N = 256)
 * and modulus (q = 12289) until the NTT layer is generalized. The noise bounds
 * are widened for WSIDH768/WSIDH1024 to mimic higher-security settings.
 */
#if WSIDH_PARAM_SET == WSIDH_PARAM_WS512
#define WSIDH_PARAM_N        256
#define WSIDH_PARAM_Q        3329
#define WSIDH_PARAM_BOUND_S  3
#define WSIDH_PARAM_BOUND_E  2
#elif WSIDH_PARAM_SET == WSIDH_PARAM_WS768
#define WSIDH_PARAM_N        256
#define WSIDH_PARAM_Q        3329
#define WSIDH_PARAM_BOUND_S  4
#define WSIDH_PARAM_BOUND_E  3
#elif WSIDH_PARAM_SET == WSIDH_PARAM_WS1024
#define WSIDH_PARAM_N        256
#define WSIDH_PARAM_Q        3329
#define WSIDH_PARAM_BOUND_S  5
#define WSIDH_PARAM_BOUND_E  4
#endif

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
