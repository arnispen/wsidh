#include <stdint.h>
#include <string.h>

#include "ntt.h"
#include "wsidh_profiler.h"

#ifdef WSIDH_USE_AVX2
#include "wsidh_avx2_ntt.h"
#else
#include "../third_party/PQClean/crypto_kem/kyber512/clean/poly.h"
#endif

#ifndef WSIDH_USE_AVX2
static inline int16_t wsidh_scale_mod_q(int16_t value, int32_t scale) {
    int32_t v = (int32_t)value * scale;
    v %= WSIDH_Q;
    if (v < 0) {
        v += WSIDH_Q;
    }
    return (int16_t)v;
}

static void wsidh_poly_from_array_clean(poly *dst, const int16_t *src) {
    memcpy(dst->coeffs, src, WSIDH_N * sizeof(int16_t));
}

static void wsidh_poly_to_array_clean(int16_t *dst, const poly *src) {
    memcpy(dst, src->coeffs, WSIDH_N * sizeof(int16_t));
}

static void wsidh_ntt_clean(int16_t a[WSIDH_N]) {
    poly tmp;
    wsidh_poly_from_array_clean(&tmp, a);
    PQCLEAN_MLKEM512_CLEAN_poly_ntt(&tmp);
    wsidh_poly_to_array_clean(a, &tmp);
}

static void wsidh_invntt_clean(int16_t a[WSIDH_N]) {
    poly tmp;
    wsidh_poly_from_array_clean(&tmp, a);
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&tmp);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&tmp);
    for (int i = 0; i < WSIDH_N; i++) {
        tmp.coeffs[i] = wsidh_scale_mod_q(tmp.coeffs[i], WSIDH_MONT_RINV);
    }
    wsidh_poly_to_array_clean(a, &tmp);
}

static void wsidh_basemul_clean(int16_t r[WSIDH_N],
                                const int16_t a[WSIDH_N],
                                const int16_t b[WSIDH_N]) {
    poly tmp_r;
    poly tmp_a;
    poly tmp_b;
    wsidh_poly_from_array_clean(&tmp_a, a);
    wsidh_poly_from_array_clean(&tmp_b, b);
    PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&tmp_r, &tmp_a, &tmp_b);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&tmp_r);
    for (int i = 0; i < WSIDH_N; i++) {
        tmp_r.coeffs[i] = wsidh_scale_mod_q(tmp_r.coeffs[i], WSIDH_MONT_R);
    }
    wsidh_poly_to_array_clean(r, &tmp_r);
}
#endif

static void wsidh_ntt_impl(int16_t a[WSIDH_N]) {
    if (!a) {
        return;
    }
#ifdef WSIDH_USE_AVX2
    wsidh_ntt_avx(a);
#else
    wsidh_ntt_clean(a);
#endif
}

static void wsidh_invntt_impl(int16_t a[WSIDH_N]) {
    if (!a) {
        return;
    }
#ifdef WSIDH_USE_AVX2
    wsidh_invntt_avx(a);
#else
    wsidh_invntt_clean(a);
#endif
}

static void wsidh_basemul_impl(int16_t r[WSIDH_N],
                               const int16_t a[WSIDH_N],
                               const int16_t b[WSIDH_N]) {
#ifdef WSIDH_USE_AVX2
    wsidh_basemul_avx(r, a, b);
#else
    wsidh_basemul_clean(r, a, b);
#endif
}

void ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(ntt_single_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
    wsidh_ntt_impl(a);
    WSIDH_PROFILE_END(ntt_single_scope);
}

void ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) {
        return;
    }
    WSIDH_PROFILE_BEGIN(ntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            wsidh_ntt_impl(vecs[i]);
        }
    }
    WSIDH_PROFILE_END(ntt_batch_scope);
}

void inv_ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(invntt_single_scope, WSIDH_PROFILE_EVENT_NTT_INV);
    wsidh_invntt_impl(a);
    WSIDH_PROFILE_END(invntt_single_scope);
}

void inv_ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) {
        return;
    }
    WSIDH_PROFILE_BEGIN(invntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_INV);
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            wsidh_invntt_impl(vecs[i]);
        }
    }
    WSIDH_PROFILE_END(invntt_batch_scope);
}

void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]) {
    if (!r || !a || !b) {
        return;
    }
    WSIDH_PROFILE_BEGIN(basemul_scope, WSIDH_PROFILE_EVENT_POINTWISE_MUL);
    wsidh_basemul_impl(r, a, b);
    WSIDH_PROFILE_END(basemul_scope);
}
