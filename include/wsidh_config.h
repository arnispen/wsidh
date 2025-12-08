#ifndef WSIDH_CONFIG_H
#define WSIDH_CONFIG_H

#include "wsidh_variants.h"

#ifndef WSIDH_PARAM_SET
#define WSIDH_PARAM_SET WSIDH_PARAM_WS512
#endif

#if WSIDH_PARAM_SET != WSIDH_PARAM_WS512
#error "Only the WSIDH512 parameter set is currently supported."
#endif

#define WSIDH_SECURITY_LEVEL 1

#if defined(WSIDH_USE_AVX2) && defined(WSIDH_USE_CLEAN)
#error "Select either WSIDH_USE_AVX2 or WSIDH_USE_CLEAN, not both."
#endif

#if defined(WSIDH_USE_AVX2)
#define WSIDH_ENABLE_AVX2 1
#else
#define WSIDH_USE_CLEAN 1
#endif

#define WSIDH_N        WSIDH_PARAM_N
#define WSIDH_Q        WSIDH_PARAM_Q
#define WSIDH_BOUND_S  WSIDH_PARAM_BOUND_S
#define WSIDH_BOUND_E  WSIDH_PARAM_BOUND_E

#ifndef WSIDH_WAVE_LAMBDA
#define WSIDH_WAVE_LAMBDA 1
#endif

#endif /* WSIDH_CONFIG_H */
