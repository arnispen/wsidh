#include "params.h"

#ifdef WSIDH_USE_AVX2

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdalign.h>

#include "wsidh_avx2.h"

#define WSIDH_QINV 62209
#define WSIDH_MONT 2285
#define WSIDH_MONT_R2 1353
#define WSIDH_NTT_MAX_STAGES 8

static alignas(32) int16_t g_ntt_twiddles_fwd[WSIDH_NTT_MAX_STAGES][WSIDH_N / 2];
static alignas(32) int16_t g_ntt_twiddles_inv[WSIDH_NTT_MAX_STAGES][WSIDH_N / 2];
static int16_t g_ntt_scale = 0;
static int g_ntt_ready = 0;
static const wsidh_params_t *g_ntt_params = NULL;

static inline int16_t wsidh_montgomery_reduce_scalar(int32_t a) {
    int32_t t = (int32_t)((int64_t)a * WSIDH_QINV) & 0xFFFF;
    t = (a - t * WSIDH_Q) >> 16;
    if (t < 0) {
        t += WSIDH_Q;
    }
    return (int16_t)t;
}

static inline int16_t wsidh_to_montgomery_scalar(int16_t x) {
    return wsidh_montgomery_reduce_scalar((int32_t)x * WSIDH_MONT_R2);
}

static inline int16_t wsidh_add_mod_scalar(int16_t a, int16_t b) {
    int16_t s = (int16_t)(a + b);
    if (s >= WSIDH_Q) {
        s -= WSIDH_Q;
    }
    return s;
}

static inline int16_t wsidh_sub_mod_scalar(int16_t a, int16_t b) {
    int16_t d = (int16_t)(a - b);
    if (d < 0) {
        d += WSIDH_Q;
    }
    return d;
}

static void wsidh_ntt_prepare_twiddles(void) {
    const wsidh_params_t *params = wsidh_params_active();
    if (g_ntt_ready && params == g_ntt_params) {
        return;
    }
    g_ntt_params = params;
    memset(g_ntt_twiddles_fwd, 0, sizeof(g_ntt_twiddles_fwd));
    memset(g_ntt_twiddles_inv, 0, sizeof(g_ntt_twiddles_inv));

    int len = 2;
    for (size_t stage = 0; stage < params->stage_count && stage < WSIDH_NTT_MAX_STAGES; stage++) {
        int half = len >> 1;
        int blocks = WSIDH_N / len;
        int16_t wlen = wsidh_to_montgomery_scalar((int16_t)params->zetas[stage]);
        size_t idx = 0;
        for (int blk = 0; blk < blocks; blk++) {
            int16_t w = WSIDH_MONT;
            for (int j = 0; j < half; j++) {
                g_ntt_twiddles_fwd[stage][idx++] = w;
                w = wsidh_montgomery_reduce_scalar((int32_t)w * wlen);
            }
        }
        len <<= 1;
    }

    len = 2;
    for (size_t stage = 0; stage < params->stage_count && stage < WSIDH_NTT_MAX_STAGES; stage++) {
        int half = len >> 1;
        int blocks = WSIDH_N / len;
        int16_t wlen = wsidh_to_montgomery_scalar((int16_t)params->zetas_inv[stage]);
        size_t idx = 0;
        for (int blk = 0; blk < blocks; blk++) {
            int16_t w = WSIDH_MONT;
            for (int j = 0; j < half; j++) {
                g_ntt_twiddles_inv[stage][idx++] = w;
                w = wsidh_montgomery_reduce_scalar((int32_t)w * wlen);
            }
        }
        len <<= 1;
    }

    g_ntt_scale = wsidh_to_montgomery_scalar((int16_t)params->n_inv);
    g_ntt_ready = 1;
}

static inline __m256i wsidh_montgomery_reduce_vec32(__m256i x32) {
    const __m256i qinv_vec = _mm256_set1_epi32(WSIDH_QINV);
    const __m256i q_vec32 = _mm256_set1_epi32(WSIDH_Q);
    const __m256i mask16 = _mm256_set1_epi32(0xFFFF);
    __m256i t = _mm256_mullo_epi32(x32, qinv_vec);
    t = _mm256_and_si256(t, mask16);
    __m256i prod = _mm256_mullo_epi32(t, q_vec32);
    __m256i diff = _mm256_sub_epi32(x32, prod);
    return _mm256_srai_epi32(diff, 16);
}

static inline __m256i wsidh_montgomery_mul_vec(__m256i a, __m256i b) {
    __m256i a_lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(a));
    __m256i b_lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(b));
    __m256i prod_lo = _mm256_mullo_epi32(a_lo, b_lo);
    __m256i red_lo = wsidh_montgomery_reduce_vec32(prod_lo);

    __m256i a_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(a, 1));
    __m256i b_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(b, 1));
    __m256i prod_hi = _mm256_mullo_epi32(a_hi, b_hi);
    __m256i red_hi = wsidh_montgomery_reduce_vec32(prod_hi);

    return _mm256_packs_epi32(red_lo, red_hi);
}

static inline __m256i wsidh_from_mont_vec(__m256i v) {
    __m256i lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(v));
    __m256i hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(v, 1));
    __m256i red_lo = wsidh_montgomery_reduce_vec32(lo);
    __m256i red_hi = wsidh_montgomery_reduce_vec32(hi);
    return _mm256_packs_epi32(red_lo, red_hi);
}

static inline __m256i wsidh_vec_add_mod(__m256i a,
                                        __m256i b,
                                        const __m256i q_vec,
                                        const __m256i q_minus1) {
    __m256i sum = _mm256_add_epi16(a, b);
    __m256i mask = _mm256_cmpgt_epi16(sum, q_minus1);
    return _mm256_sub_epi16(sum, _mm256_and_si256(mask, q_vec));
}

static inline __m256i wsidh_vec_sub_mod(__m256i a,
                                        __m256i b,
                                        const __m256i q_vec) {
    __m256i diff = _mm256_sub_epi16(a, b);
    __m256i mask = _mm256_cmpgt_epi16(_mm256_setzero_si256(), diff);
    return _mm256_add_epi16(diff, _mm256_and_si256(mask, q_vec));
}

static inline void wsidh_to_montgomery_vec(int16_t *coeffs) {
    const __m256i r2 = _mm256_set1_epi16(WSIDH_MONT_R2);
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i v = _mm256_loadu_si256((const __m256i *)&coeffs[i]);
        __m256i conv = wsidh_montgomery_mul_vec(v, r2);
        _mm256_storeu_si256((__m256i *)&coeffs[i], conv);
    }
}

void wsidh_avx2_ntt(int16_t *coeffs) {
    if (!coeffs) return;
    wsidh_ntt_prepare_twiddles();
    const __m256i q_vec = _mm256_set1_epi16(WSIDH_Q);
    const __m256i q_minus1 = _mm256_set1_epi16(WSIDH_Q - 1);
    wsidh_to_montgomery_vec(coeffs);

    int len = 2;
    for (size_t stage = 0; stage < g_ntt_params->stage_count && stage < WSIDH_NTT_MAX_STAGES; stage++) {
        int half = len >> 1;
        size_t tw_idx = 0;
        for (int start = 0; start < WSIDH_N; start += len) {
            int j = 0;
            for (; j + 16 <= half; j += 16) {
                __m256i w = _mm256_load_si256((const __m256i *)&g_ntt_twiddles_fwd[stage][tw_idx]);
                tw_idx += 16;
                __m256i lo = _mm256_loadu_si256((const __m256i *)&coeffs[start + j]);
                __m256i hi = _mm256_loadu_si256((const __m256i *)&coeffs[start + j + half]);
                __m256i t = wsidh_montgomery_mul_vec(hi, w);
                __m256i sum = wsidh_vec_add_mod(lo, t, q_vec, q_minus1);
                __m256i diff = wsidh_vec_sub_mod(lo, t, q_vec);
                _mm256_storeu_si256((__m256i *)&coeffs[start + j], sum);
                _mm256_storeu_si256((__m256i *)&coeffs[start + j + half], diff);
            }
            for (; j < half; j++) {
                int16_t w = g_ntt_twiddles_fwd[stage][tw_idx++];
                int16_t u = coeffs[start + j];
                int16_t v = wsidh_montgomery_reduce_scalar((int32_t)coeffs[start + j + half] * w);
                coeffs[start + j] = wsidh_add_mod_scalar(u, v);
                coeffs[start + j + half] = wsidh_sub_mod_scalar(u, v);
            }
        }
        len <<= 1;
    }
}

void wsidh_avx2_invntt(int16_t *coeffs) {
    if (!coeffs) return;
    wsidh_ntt_prepare_twiddles();
    const __m256i q_vec = _mm256_set1_epi16(WSIDH_Q);
    const __m256i q_minus1 = _mm256_set1_epi16(WSIDH_Q - 1);

    int len = 2;
    for (size_t stage = 0; stage < g_ntt_params->stage_count && stage < WSIDH_NTT_MAX_STAGES; stage++) {
        int half = len >> 1;
        size_t tw_idx = 0;
        for (int start = 0; start < WSIDH_N; start += len) {
            int j = 0;
            for (; j + 16 <= half; j += 16) {
                __m256i lo = _mm256_loadu_si256((const __m256i *)&coeffs[start + j]);
                __m256i hi = _mm256_loadu_si256((const __m256i *)&coeffs[start + j + half]);
                __m256i sum = wsidh_vec_add_mod(lo, hi, q_vec, q_minus1);
                __m256i diff = wsidh_vec_sub_mod(lo, hi, q_vec);
                __m256i w = _mm256_load_si256((const __m256i *)&g_ntt_twiddles_inv[stage][tw_idx]);
                tw_idx += 16;
                __m256i prod = wsidh_montgomery_mul_vec(diff, w);
                _mm256_storeu_si256((__m256i *)&coeffs[start + j], sum);
                _mm256_storeu_si256((__m256i *)&coeffs[start + j + half], prod);
            }
            for (; j < half; j++) {
                int16_t t = coeffs[start + j];
                coeffs[start + j] = wsidh_add_mod_scalar(t, coeffs[start + j + half]);
                int16_t diff = (int16_t)(coeffs[start + j + half] - t);
                if (diff < 0) diff += WSIDH_Q;
                int16_t w = g_ntt_twiddles_inv[stage][tw_idx++];
                coeffs[start + j + half] =
                    wsidh_montgomery_reduce_scalar((int32_t)diff * w);
            }
        }
        len <<= 1;
    }

    const __m256i scale = _mm256_set1_epi16(g_ntt_scale);
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i v = _mm256_loadu_si256((const __m256i *)&coeffs[i]);
        __m256i scaled = wsidh_montgomery_mul_vec(v, scale);
        __m256i out = wsidh_from_mont_vec(scaled);
        _mm256_storeu_si256((__m256i *)&coeffs[i], out);
    }
}

void wsidh_avx2_basemul(int16_t *r,
                        const int16_t *a,
                        const int16_t *b) {
    if (!r || !a || !b) return;
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i va = _mm256_loadu_si256((const __m256i *)&a[i]);
        __m256i vb = _mm256_loadu_si256((const __m256i *)&b[i]);
        __m256i prod = wsidh_montgomery_mul_vec(va, vb);
        _mm256_storeu_si256((__m256i *)&r[i], prod);
    }
}

#endif /* WSIDH_USE_AVX2 */
