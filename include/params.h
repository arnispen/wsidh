// include/params.h
#ifndef WSIDH_PARAMS_H
#define WSIDH_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#include "wsidh_variants.h"

#if WSIDH_PARAM_SET != WSIDH_PARAM_WS512
#error "Only WSIDH512 parameter data is wired in; add WSIDH_PARAMS_<N> before building other variants."
#endif

#define WSIDH_N WSIDH_PARAM_N
#define WSIDH_Q WSIDH_PARAM_Q

// Secrets/noise sample from [-BOUND, +BOUND]; keep bounds tight for low noise.
#define WSIDH_BOUND_S WSIDH_PARAM_BOUND_S
#define WSIDH_BOUND_E WSIDH_PARAM_BOUND_E

#define WSIDH_SEED_BYTES 32    // seed size for deterministic samplers / FO transform

typedef void (*rand_func_t)(uint8_t *out, size_t outlen);

typedef struct {
    int N;
    int Q;
    int16_t bound_s;
    int16_t bound_e;
    int32_t barrett_v;
    const int16_t *wave_table;
    size_t wave_table_len;
    const int16_t *zetas;
    const int16_t *zetas_inv;
    size_t stage_count;
    int16_t n_inv;
} wsidh_params_t;

const wsidh_params_t *wsidh_params_active(void);
void wsidh_params_select(const wsidh_params_t *params);
void wsidh_params_reset(void);

#endif // WSIDH_PARAMS_H
