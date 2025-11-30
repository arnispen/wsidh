#ifndef WSIDH_POLY_H
#define WSIDH_POLY_H

#include <stdint.h>
#include <string.h>
#include <stdalign.h>
#include "params.h"
#ifdef WSIDH_USE_AVX2
#include <immintrin.h>
#endif

typedef struct {
    alignas(32) int16_t coeffs[WSIDH_N];
} poly;

static inline int16_t wsidh_mod_q(int32_t x) {
    int32_t r = x % WSIDH_Q;
    if (r < 0) {
        r += WSIDH_Q;
    }
    return (int16_t)r;
}

static inline void poly_clear(poly *a) {
    for (int i = 0; i < WSIDH_N; i++) {
        a->coeffs[i] = 0;
    }
}

static inline void poly_copy(poly *dest, const poly *src) {
    for (int i = 0; i < WSIDH_N; i++) {
        dest->coeffs[i] = src->coeffs[i];
    }
}

static inline void poly_add(poly *c, const poly *a, const poly *b) {
#ifdef WSIDH_USE_AVX2
    const __m256i qvec = _mm256_set1_epi16(WSIDH_Q);
    const __m256i qminus1 = _mm256_set1_epi16(WSIDH_Q - 1);
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i va = _mm256_load_si256((const __m256i *)&a->coeffs[i]);
        __m256i vb = _mm256_load_si256((const __m256i *)&b->coeffs[i]);
        __m256i sum = _mm256_add_epi16(va, vb);
        __m256i mask = _mm256_cmpgt_epi16(sum, qminus1);
        sum = _mm256_sub_epi16(sum, _mm256_and_si256(mask, qvec));
        _mm256_store_si256((__m256i *)&c->coeffs[i], sum);
    }
#else
    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = wsidh_mod_q((int32_t)a->coeffs[i] + b->coeffs[i]);
    }
#endif
}

static inline void poly_sub(poly *c, const poly *a, const poly *b) {
#ifdef WSIDH_USE_AVX2
    const __m256i qvec = _mm256_set1_epi16(WSIDH_Q);
    const __m256i zero = _mm256_setzero_si256();
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i va = _mm256_load_si256((const __m256i *)&a->coeffs[i]);
        __m256i vb = _mm256_load_si256((const __m256i *)&b->coeffs[i]);
        __m256i diff = _mm256_sub_epi16(va, vb);
        __m256i mask = _mm256_cmpgt_epi16(zero, diff);
        diff = _mm256_add_epi16(diff, _mm256_and_si256(mask, qvec));
        _mm256_store_si256((__m256i *)&c->coeffs[i], diff);
    }
#else
    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = wsidh_mod_q((int32_t)a->coeffs[i] - b->coeffs[i]);
    }
#endif
}

static inline uint32_t wsidh_load24_little(const uint8_t *x) {
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16);
}

static inline uint32_t wsidh_load32_little(const uint8_t *x) {
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) |
           ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

static inline size_t wsidh_sample_bytes_required(int bound) {
    (void)bound;
    return 2 * WSIDH_N;
}

static inline uint8_t wsidh_cbt_mask(int bound) {
    if (bound <= 0) {
        return 0;
    } else if (bound >= 8) {
        return 0xFF;
    }
    return (uint8_t)(((uint32_t)1u << bound) - 1u);
}

static inline int wsidh_popcount8(uint8_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcount((unsigned int)x);
#else
    int cnt = 0;
    while (x) {
        cnt += (int)(x & 1u);
        x >>= 1;
    }
    return cnt;
#endif
}

#ifdef WSIDH_USE_AVX2
static inline __m256i wsidh_avx2_popcount_epi8(__m256i v) {
    const __m256i low_mask = _mm256_set1_epi8(0x0F);
    const __m256i lut = _mm256_setr_epi8(
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4);
    __m256i lo = _mm256_and_si256(v, low_mask);
    __m256i hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), low_mask);
    __m256i pop_lo = _mm256_shuffle_epi8(lut, lo);
    __m256i pop_hi = _mm256_shuffle_epi8(lut, hi);
    return _mm256_add_epi8(pop_lo, pop_hi);
}

static inline void wsidh_sample_cbt_avx2(int16_t *out,
                                         const uint8_t *buf,
                                         int bound) {
    const uint8_t mask_byte = wsidh_cbt_mask(bound);
    const __m256i byte_mask = _mm256_set1_epi8((char)mask_byte);
    const __m256i pair_weights = _mm256_setr_epi8(
        1, -1, 1, -1, 1, -1, 1, -1,
        1, -1, 1, -1, 1, -1, 1, -1,
        1, -1, 1, -1, 1, -1, 1, -1,
        1, -1, 1, -1, 1, -1, 1, -1);

    int i = 0;
    for (; i + 16 <= WSIDH_N; i += 16) {
        const __m256i raw = _mm256_loadu_si256(
            (const __m256i *)(buf + (size_t)2 * i));
        __m256i masked = _mm256_and_si256(raw, byte_mask);
        __m256i pops = wsidh_avx2_popcount_epi8(masked);
        __m256i diffs = _mm256_maddubs_epi16(pops, pair_weights);
        _mm256_storeu_si256((__m256i *)(out + i), diffs);
    }
    for (; i < WSIDH_N; i++) {
        uint8_t a_bits = buf[2 * i] & mask_byte;
        uint8_t b_bits = buf[2 * i + 1] & mask_byte;
        int val = wsidh_popcount8(a_bits) - wsidh_popcount8(b_bits);
        out[i] = (int16_t)val;
    }
}
#endif /* WSIDH_USE_AVX2 */

static inline void wsidh_sample_from_bytes(poly *a,
                                           const uint8_t *buf,
                                           int bound) {
    if (!a) {
        return;
    }
    if (!buf || bound <= 0) {
        poly_clear(a);
        return;
    }
#ifdef WSIDH_USE_AVX2
    wsidh_sample_cbt_avx2(a->coeffs, buf, bound);
#else
    const uint8_t mask = wsidh_cbt_mask(bound);
    for (int i = 0; i < WSIDH_N; i++) {
        uint8_t a_bits = buf[2 * i] & mask;
        uint8_t b_bits = buf[2 * i + 1] & mask;
        int val = wsidh_popcount8(a_bits) - wsidh_popcount8(b_bits);
        a->coeffs[i] = (int16_t)val;
    }
#endif
}

void poly_mul_ntt(poly *c, const poly *a, const poly *b);

// existing random sampler
void poly_sample_small(poly *a, rand_func_t rng, int bound);

// 🔥 NEW: deterministic sampler from a 32-byte seed
void poly_sample_small_from_seed(poly *a,
                                 const uint8_t seed[WSIDH_SEED_BYTES],
                                 int bound,
                                 uint8_t domain_sep);

void poly_from_wave(poly *a);
void poly_print_csv(const poly *a, const char *label);

void poly_canon(poly *p);


#endif
