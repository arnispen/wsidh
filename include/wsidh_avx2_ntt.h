#ifndef WSIDH_AVX2_NTT_H
#define WSIDH_AVX2_NTT_H

#ifdef WSIDH_USE_AVX2
#include <stdint.h>
#include "params.h"

void wsidh_ntt_avx(int16_t a[WSIDH_N]);
void wsidh_invntt_avx(int16_t a[WSIDH_N]);
void wsidh_basemul_avx(int16_t r[WSIDH_N],
                       const int16_t a[WSIDH_N],
                       const int16_t b[WSIDH_N]);

#endif /* WSIDH_USE_AVX2 */

#endif /* WSIDH_AVX2_NTT_H */
