#ifndef WSIDH_AVX2_H
#define WSIDH_AVX2_H

#ifdef WSIDH_USE_AVX2
#include <stdint.h>

void wsidh_avx2_ntt(int16_t *coeffs);
void wsidh_avx2_invntt(int16_t *coeffs);
void wsidh_avx2_basemul(int16_t *r,
                        const int16_t *a,
                        const int16_t *b);

#endif /* WSIDH_USE_AVX2 */

#endif /* WSIDH_AVX2_H */
