#include "params.h"

#ifdef WSIDH_USE_AVX2

#include <string.h>

#include "wsidh_avx2_ntt.h"

#include "../third_party/PQClean/crypto_kem/kyber512/avx2/poly.h"

static void wsidh_poly_from_array(poly *dst, const int16_t *src) {
    memcpy(dst->coeffs, src, WSIDH_N * sizeof(int16_t));
}

static void wsidh_poly_to_array(int16_t *dst, const poly *src) {
    memcpy(dst, src->coeffs, WSIDH_N * sizeof(int16_t));
}

void wsidh_ntt_avx(int16_t a[WSIDH_N]) {
    poly tmp;
    wsidh_poly_from_array(&tmp, a);
    PQCLEAN_MLKEM512_AVX2_poly_ntt(&tmp);
    wsidh_poly_to_array(a, &tmp);
}

void wsidh_invntt_avx(int16_t a[WSIDH_N]) {
    poly tmp;
    wsidh_poly_from_array(&tmp, a);
    PQCLEAN_MLKEM512_AVX2_poly_invntt_tomont(&tmp);
    PQCLEAN_MLKEM512_AVX2_poly_reduce(&tmp);
    for (int i = 0; i < WSIDH_N; i++) {
        int32_t v = (int32_t)tmp.coeffs[i] * WSIDH_MONT_RINV;
        v %= WSIDH_Q;
        if (v < 0) v += WSIDH_Q;
        tmp.coeffs[i] = (int16_t)v;
    }
    wsidh_poly_to_array(a, &tmp);
}

void wsidh_basemul_avx(int16_t r[WSIDH_N],
                       const int16_t a[WSIDH_N],
                       const int16_t b[WSIDH_N]) {
    poly tmp_r;
    poly tmp_a;
    poly tmp_b;
    wsidh_poly_from_array(&tmp_a, a);
    wsidh_poly_from_array(&tmp_b, b);
    PQCLEAN_MLKEM512_AVX2_poly_basemul_montgomery(&tmp_r, &tmp_a, &tmp_b);
    PQCLEAN_MLKEM512_AVX2_poly_reduce(&tmp_r);
    for (int i = 0; i < WSIDH_N; i++) {
        int32_t v = (int32_t)tmp_r.coeffs[i] * WSIDH_MONT_R;
        v %= WSIDH_Q;
        if (v < 0) v += WSIDH_Q;
        tmp_r.coeffs[i] = (int16_t)v;
    }
    wsidh_poly_to_array(r, &tmp_r);
}

#endif /* WSIDH_USE_AVX2 */
