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

static inline void wsidh_cbd_eta2(poly *a, const uint8_t *buf) {
    for (int i = 0; i < WSIDH_N / 8; i++) {
        uint32_t t = wsidh_load32_little(buf + 4 * i);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (int j = 0; j < 8; j++) {
            uint8_t a_bits = (d >> (4 * j)) & 0x3;
            uint8_t b_bits = (d >> (4 * j + 2)) & 0x3;
            a->coeffs[8 * i + j] = (int16_t)a_bits - (int16_t)b_bits;
        }
    }
}

static inline void wsidh_cbd_eta3(poly *a, const uint8_t *buf) {
    for (int i = 0; i < WSIDH_N / 4; i++) {
        uint32_t t = wsidh_load24_little(buf + 3 * i);
        uint32_t d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;
        for (int j = 0; j < 4; j++) {
            uint8_t a_bits = (d >> (6 * j)) & 0x7;
            uint8_t b_bits = (d >> (6 * j + 3)) & 0x7;
            a->coeffs[4 * i + j] = (int16_t)a_bits - (int16_t)b_bits;
        }
    }
}

static inline size_t wsidh_sample_bytes_required(int bound) {
    if (bound == 2) {
        return (WSIDH_N / 8) * 4;
    } else if (bound == 3) {
        return (WSIDH_N / 4) * 3;
    }
    return 2 * WSIDH_N;
}

#ifdef WSIDH_USE_AVX2
static inline void wsidh_cbd_eta2_avx2(int16_t *out, const uint8_t *buf) {
    const __m256i mask55 = _mm256_set1_epi32(0x55555555);
    const __m256i mask33 = _mm256_set1_epi32(0x33333333);
    const __m256i mask03 = _mm256_set1_epi32(0x03030303);
    const __m256i mask0F = _mm256_set1_epi32(0x0F0F0F0F);
    const __m256i *src = (const __m256i *)buf;
    __m256i *dst = (__m256i *)out;

    for (int i = 0; i < WSIDH_N / 64; i++) {
        __m256i f0 = _mm256_loadu_si256(&src[i]);
        __m256i f1 = _mm256_srli_epi16(f0, 1);
        f0 = _mm256_and_si256(mask55, f0);
        f1 = _mm256_and_si256(mask55, f1);
        f0 = _mm256_add_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 2);
        f0 = _mm256_and_si256(mask33, f0);
        f1 = _mm256_and_si256(mask33, f1);
        f0 = _mm256_add_epi8(f0, mask33);
        f0 = _mm256_sub_epi8(f0, f1);

        f1 = _mm256_srli_epi16(f0, 4);
        f0 = _mm256_and_si256(mask0F, f0);
        f1 = _mm256_and_si256(mask0F, f1);
        f0 = _mm256_sub_epi8(f0, mask03);
        f1 = _mm256_sub_epi8(f1, mask03);

        __m256i f2 = _mm256_unpacklo_epi8(f0, f1);
        __m256i f3 = _mm256_unpackhi_epi8(f0, f1);

        f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
        f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2, 1));
        f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
        f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3, 1));

        _mm256_storeu_si256(&dst[4 * i + 0], f0);
        _mm256_storeu_si256(&dst[4 * i + 1], f2);
        _mm256_storeu_si256(&dst[4 * i + 2], f1);
        _mm256_storeu_si256(&dst[4 * i + 3], f3);
    }
}

static inline void wsidh_cbd_eta3_avx2(int16_t *out, const uint8_t *buf) {
    const __m256i mask249 = _mm256_set1_epi32(0x249249);
    const __m256i mask6DB = _mm256_set1_epi32(0x6DB6DB);
    const __m256i mask07 = _mm256_set1_epi32(7);
    const __m256i mask70 = _mm256_set1_epi32(7 << 16);
    const __m256i mask3 = _mm256_set1_epi16(3);
    const __m256i shufbidx = _mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10,
                                             -1, 9, 8, 7, -1, 6, 5, 4,
                                             -1, 11, 10, 9, -1, 8, 7, 6,
                                             -1, 5, 4, 3, -1, 2, 1, 0);
    __m256i *dst = (__m256i *)out;

    for (int i = 0; i < WSIDH_N / 32; i++) {
        __m256i f0 = _mm256_loadu_si256((const __m256i *)&buf[24 * i]);
        f0 = _mm256_permute4x64_epi64(f0, 0x94);
        f0 = _mm256_shuffle_epi8(f0, shufbidx);

        __m256i f1 = _mm256_srli_epi32(f0, 1);
        __m256i f2 = _mm256_srli_epi32(f0, 2);
        f0 = _mm256_and_si256(mask249, f0);
        f1 = _mm256_and_si256(mask249, f1);
        f2 = _mm256_and_si256(mask249, f2);
        f0 = _mm256_add_epi32(f0, f1);
        f0 = _mm256_add_epi32(f0, f2);

        f1 = _mm256_srli_epi32(f0, 3);
        f0 = _mm256_add_epi32(f0, mask6DB);
        f0 = _mm256_sub_epi32(f0, f1);

        f1 = _mm256_slli_epi32(f0, 10);
        f2 = _mm256_srli_epi32(f0, 12);
        __m256i f3 = _mm256_srli_epi32(f0, 2);
        f0 = _mm256_and_si256(f0, mask07);
        f1 = _mm256_and_si256(f1, mask70);
        f2 = _mm256_and_si256(f2, mask07);
        f3 = _mm256_and_si256(f3, mask70);
        f0 = _mm256_add_epi16(f0, f1);
        f1 = _mm256_add_epi16(f2, f3);
        f0 = _mm256_sub_epi16(f0, mask3);
        f1 = _mm256_sub_epi16(f1, mask3);

        f2 = _mm256_unpacklo_epi32(f0, f1);
        f3 = _mm256_unpackhi_epi32(f0, f1);

        f0 = _mm256_permute2x128_si256(f2, f3, 0x20);
        f1 = _mm256_permute2x128_si256(f2, f3, 0x31);

        _mm256_storeu_si256(&dst[2 * i + 0], f0);
        _mm256_storeu_si256(&dst[2 * i + 1], f1);
    }
}
#endif

static inline void wsidh_sample_from_bytes(poly *a,
                                           const uint8_t *buf,
                                           int bound) {
#ifdef WSIDH_USE_AVX2
    if (bound == 2) {
        wsidh_cbd_eta2_avx2(a->coeffs, buf);
        return;
    } else if (bound == 3) {
        uint8_t tmp[3 * WSIDH_N / 4 + 32];
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, buf, (3 * WSIDH_N) / 4);
        wsidh_cbd_eta3_avx2(a->coeffs, tmp);
        return;
    }
#else
    if (bound == 2) {
        wsidh_cbd_eta2(a, buf);
        return;
    } else if (bound == 3) {
        wsidh_cbd_eta3(a, buf);
        return;
    }
#endif

    for (int i = 0; i < WSIDH_N; i++) {
        size_t idx = (size_t)i * 2;
        uint16_t r = ((uint16_t)buf[idx] << 8) | buf[idx + 1];
        int val = (int)(r % (2 * bound + 1)) - bound;
        a->coeffs[i] = (int16_t)val;
    }
}

void poly_mul_ntt(poly *c, const poly *a, const poly *b);

// existing random sampler
void poly_sample_small(poly *a, rand_func_t rng, int bound);

// 🔥 NEW: deterministic sampler from a 32-byte seed
void poly_sample_small_from_seed(poly *a,
                                 const uint8_t seed[WSIDH_SEED_BYTES],
                                 int bound,
                                 uint8_t domain_sep);

void poly_sample_uniform_q_from_seed(poly *a,
                                     const uint8_t seed[WSIDH_SEED_BYTES],
                                     uint8_t domain_sep);
void poly_sample_uniform_ntt_from_seed(int16_t out[WSIDH_N],
                                       const uint8_t seed[WSIDH_SEED_BYTES],
                                       uint8_t domain_sep);
void poly_print_csv(const poly *a, const char *label);

void poly_canon(poly *p);


#endif
