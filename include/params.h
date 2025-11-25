// include/params.h
#ifndef WSIDH_PARAMS_H
#define WSIDH_PARAMS_H

#include <stdint.h>
#include <stddef.h>
#include "wsidh_variants.h"

#define WSIDH_N WSIDH_PARAM_N
#define WSIDH_Q WSIDH_PARAM_Q

// Secrets/noise sample from [-BOUND, +BOUND]; keep bounds tight for low noise.
#define WSIDH_BOUND_S WSIDH_PARAM_BOUND_S
#define WSIDH_BOUND_E WSIDH_PARAM_BOUND_E

#define WSIDH_SEED_BYTES 32    // seed size for deterministic samplers / FO transform

typedef void (*rand_func_t)(uint8_t *out, size_t outlen);

#endif // WSIDH_PARAMS_H
