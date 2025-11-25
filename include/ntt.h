#ifndef WSIDH_NTT_H
#define WSIDH_NTT_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"

// Forward NTT: in-place
void ntt(int16_t a[WSIDH_N]);
void ntt_batch(int16_t *vecs[], size_t count);

// Inverse NTT: in-place
void inv_ntt(int16_t a[WSIDH_N]);
void inv_ntt_batch(int16_t *vecs[], size_t count);

// Pointwise multiplication in NTT domain
void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]);

#endif
