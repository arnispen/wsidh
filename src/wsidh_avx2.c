#include "params.h"

#ifdef WSIDH_USE_AVX2

#include <string.h>
#include <immintrin.h>

#include "wsidh_avx2.h"
#include "wsidh_avx2_paths.h"

#define KYBER_N 256

typedef union {
    int16_t coeffs[KYBER_N];
    __m256i vec[KYBER_N / 16];
} wsidh_avx2_poly;

#include WSIDH_AVX2_HEADER(consts.h)
#include WSIDH_AVX2_HEADER(ntt.h)
#include WSIDH_AVX2_HEADER(reduce.h)

static void wsidh_avx2_load(wsidh_avx2_poly *dst, const int16_t *src) {
    memcpy(dst->coeffs, src, KYBER_N * sizeof(int16_t));
}

static void wsidh_avx2_store(int16_t *dst, const wsidh_avx2_poly *src) {
    memcpy(dst, src->coeffs, KYBER_N * sizeof(int16_t));
}

void wsidh_avx2_ntt(int16_t *coeffs) {
    wsidh_avx2_poly tmp;
    wsidh_avx2_load(&tmp, coeffs);
    PQCLEAN_MLKEM512_AVX2_ntt_avx(tmp.vec, PQCLEAN_MLKEM512_AVX2_qdata.vec);
    wsidh_avx2_store(coeffs, &tmp);
}

void wsidh_avx2_invntt(int16_t *coeffs) {
    wsidh_avx2_poly tmp;
    wsidh_avx2_load(&tmp, coeffs);
    PQCLEAN_MLKEM512_AVX2_invntt_avx(tmp.vec, PQCLEAN_MLKEM512_AVX2_qdata.vec);
    PQCLEAN_MLKEM512_AVX2_reduce_avx(tmp.vec, PQCLEAN_MLKEM512_AVX2_qdata.vec);
    wsidh_avx2_store(coeffs, &tmp);
}

void wsidh_avx2_basemul(int16_t *r,
                        const int16_t *a,
                        const int16_t *b) {
    wsidh_avx2_poly tmp_r;
    wsidh_avx2_poly tmp_a;
    wsidh_avx2_poly tmp_b;
    wsidh_avx2_load(&tmp_a, a);
    wsidh_avx2_load(&tmp_b, b);
    PQCLEAN_MLKEM512_AVX2_basemul_avx(tmp_r.vec,
                                      tmp_a.vec,
                                      tmp_b.vec,
                                      PQCLEAN_MLKEM512_AVX2_qdata.vec);
    PQCLEAN_MLKEM512_AVX2_reduce_avx(tmp_r.vec, PQCLEAN_MLKEM512_AVX2_qdata.vec);
    wsidh_avx2_store(r, &tmp_r);
}

void wsidh_avx2_reduce(int16_t *coeffs) {
    wsidh_avx2_poly tmp;
    wsidh_avx2_load(&tmp, coeffs);
    PQCLEAN_MLKEM512_AVX2_reduce_avx(tmp.vec, PQCLEAN_MLKEM512_AVX2_qdata.vec);
    wsidh_avx2_store(coeffs, &tmp);
}

#endif /* WSIDH_USE_AVX2 */
