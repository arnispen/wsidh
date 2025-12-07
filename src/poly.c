// src/poly.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WSIDH_USE_AVX2
#include <immintrin.h>
#endif
#include "poly.h"
#include "ntt.h"
#include "sha3.h"
#include "wsidh_profiler.h"
#include "fips202.h"
#ifdef WSIDH_USE_AVX2
#include "../third_party/PQClean/crypto_kem/kyber512/avx2/rejsample.h"
#include "../third_party/PQClean/crypto_kem/kyber512/avx2/symmetric.h"
#endif

static void poly_default_rng(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
}

// Cyclic convolution: c(x) = a(x)*b(x) mod (x^N - 1, q)
// schoolbook O(N^2) for now — replace with NTT later.
// void poly_mul_schoolbook(poly *c, const poly *a, const poly *b) {
//     int32_t tmp[WSIDH_N] = {0};

//     for (int i = 0; i < WSIDH_N; i++) {
//         for (int j = 0; j < WSIDH_N; j++) {
//             int k = i + j;
//             if (k >= WSIDH_N) {
//                 k -= WSIDH_N; // wrap around for x^N ≡ 1
//             }
//             tmp[k] += (int32_t)a->coeffs[i] * (int32_t)b->coeffs[j];
//         }
//     }
//     for (int i = 0; i < WSIDH_N; i++) {
//         c->coeffs[i] = wsidh_mod_q(tmp[i]);
//     }
// }

static void expand_seed_bytes(uint8_t *out,
                              size_t outlen,
                              const uint8_t seed[WSIDH_SEED_BYTES],
                              uint8_t domain_sep) {
    uint8_t input[WSIDH_SEED_BYTES + 1];
    memcpy(input, seed, WSIDH_SEED_BYTES);
    input[WSIDH_SEED_BYTES] = domain_sep;
    wsidh_shake128(out, outlen, input, sizeof(input));
}

static void poly_sample_from_stream(poly *a,
                                    int bound,
                                    const uint8_t *buf) {
    wsidh_sample_from_bytes(a, buf, bound);
}

static size_t rej_uniform_q(int16_t *coeffs,
                            size_t len,
                            const uint8_t *buf,
                            size_t buflen) {
    size_t ctr = 0;
    size_t pos = 0;

    while (ctr < len && pos + 3 <= buflen) {
        uint32_t t0 = (uint32_t)buf[pos];
        uint32_t t1 = (uint32_t)buf[pos + 1];
        uint32_t t2 = (uint32_t)buf[pos + 2];
        pos += 3;

        uint32_t val0 = t0 | ((t1 & 0x0F) << 8);
        uint32_t val1 = (t1 >> 4) | (t2 << 4);

        if (val0 < (uint32_t)WSIDH_Q) {
            coeffs[ctr++] = (int16_t)val0;
        }
        if (ctr < len && val1 < (uint32_t)WSIDH_Q) {
            coeffs[ctr++] = (int16_t)val1;
        }
    }
    return ctr;
}

#ifndef WSIDH_USE_AVX2
static void sample_uniform_coeffs_portable(int16_t *coeffs,
                                           const uint8_t seed[WSIDH_SEED_BYTES],
                                           uint8_t domain_sep) {
    uint8_t input[WSIDH_SEED_BYTES + 1];
    memcpy(input, seed, WSIDH_SEED_BYTES);
    input[WSIDH_SEED_BYTES] = domain_sep;

    shake128incctx ctx;
    shake128_inc_init(&ctx);
    shake128_inc_absorb(&ctx, input, sizeof(input));
    shake128_inc_finalize(&ctx);

    uint8_t buf[SHAKE128_RATE];
    size_t produced = 0;
    while (produced < (size_t)WSIDH_N) {
        shake128_inc_squeeze(buf, sizeof(buf), &ctx);
        produced += rej_uniform_q(coeffs + produced,
                                  (size_t)WSIDH_N - produced,
                                  buf,
                                  sizeof(buf));
    }
    shake128_inc_ctx_release(&ctx);
}
#endif

static inline int16_t wsidh_mod_q_int32(int32_t x) {
    x %= WSIDH_Q;
    if (x < 0) x += WSIDH_Q;
    return (int16_t)x;
}

static const int16_t *wsidh_wave_table_time(void) {
    const wsidh_params_t *params = wsidh_params_active();
    if (!params || !params->wave_table ||
        params->wave_table_len != (size_t)WSIDH_N) {
        return NULL;
    }
    return params->wave_table;
}

static const int16_t *wsidh_wave_table_ntt(void) {
    static alignas(32) int16_t wave_ntt[WSIDH_N];
    static int wave_ready = 0;
    const int16_t *wave_time = wsidh_wave_table_time();
    if (!wave_time) {
        return NULL;
    }
    if (!wave_ready) {
        memcpy(wave_ntt, wave_time, sizeof(wave_ntt));
        ntt(wave_ntt);
        wave_ready = 1;
    }
    return wave_ntt;
}

#ifdef WSIDH_USE_AVX2
static void sample_uniform_coeffs_avx(int16_t *coeffs,
                                      const uint8_t seed[WSIDH_SEED_BYTES],
                                      uint8_t domain_sep) {
    shake128ctx state;
    alignas(32) uint8_t buf[REJ_UNIFORM_AVX_BUFLEN];
    uint8_t input[WSIDH_SEED_BYTES + 1];
    memcpy(input, seed, WSIDH_SEED_BYTES);
    input[WSIDH_SEED_BYTES] = domain_sep;

    shake128_absorb(&state, input, sizeof(input));
    shake128_squeezeblocks(buf, REJ_UNIFORM_AVX_NBLOCKS, &state);

    unsigned int ctr = PQCLEAN_MLKEM512_AVX2_rej_uniform_avx(coeffs, buf);
    while (ctr < WSIDH_N) {
        shake128_squeezeblocks(buf, 1, &state);
        ctr += rej_uniform_q(coeffs + ctr,
                             WSIDH_N - ctr,
                             buf,
                             SHAKE128_RATE);
    }
    shake128_ctx_release(&state);
}
#endif

static void sample_uniform_coeffs(int16_t *coeffs,
                                  const uint8_t seed[WSIDH_SEED_BYTES],
                                  uint8_t domain_sep) {
#ifdef WSIDH_USE_AVX2
    sample_uniform_coeffs_avx(coeffs, seed, domain_sep);
#else
    sample_uniform_coeffs_portable(coeffs, seed, domain_sep);
#endif
}
// Sample coefficients in [-bound..bound] using rng()
// rng must fill 'outlen' bytes with random data.
void poly_sample_small(poly *a, rand_func_t rng, int bound) {
    WSIDH_PROFILE_BEGIN(sample_small, WSIDH_PROFILE_EVENT_SAMPLE_SMALL);

    if (!rng) rng = poly_default_rng;

    uint8_t seed[WSIDH_SEED_BYTES];
    uint8_t buf[2 * WSIDH_N];
    size_t needed = wsidh_sample_bytes_required(bound);

    rng(seed, sizeof(seed));
    expand_seed_bytes(buf, needed, seed, 0xFF);
    poly_sample_from_stream(a, bound, buf);

    WSIDH_PROFILE_END(sample_small);
}

void poly_sample_small_from_seed(poly *a,
                                 const uint8_t seed[WSIDH_SEED_BYTES],
                                 int bound,
                                 uint8_t domain_sep) {
    WSIDH_PROFILE_BEGIN(sample_det, WSIDH_PROFILE_EVENT_SAMPLE_DET);
    uint8_t buf[2 * WSIDH_N];
    size_t needed = wsidh_sample_bytes_required(bound);
    expand_seed_bytes(buf, needed, seed, domain_sep);
    poly_sample_from_stream(a, bound, buf);
    WSIDH_PROFILE_END(sample_det);
}


void poly_sample_uniform_q_from_seed(poly *a,
                                     const uint8_t seed[WSIDH_SEED_BYTES],
                                     uint8_t domain_sep) {
    WSIDH_PROFILE_BEGIN(public_poly, WSIDH_PROFILE_EVENT_POLY_SAMPLE_UNIFORM);
    alignas(32) int16_t tmp[WSIDH_N];
    sample_uniform_coeffs(tmp, seed, domain_sep);
    const int16_t *wave_ntt = wsidh_wave_table_ntt();
    if (wave_ntt) {
        for (int i = 0; i < WSIDH_N; i++) {
            tmp[i] = wsidh_mod_q_int32((int32_t)tmp[i] + wave_ntt[i]);
        }
    }
    memcpy(a->coeffs, tmp, sizeof(tmp));
    inv_ntt(a->coeffs);
    poly_canon(a);
    WSIDH_PROFILE_END(public_poly);
}

void poly_sample_uniform_ntt_from_seed(int16_t out[WSIDH_N],
                                       const uint8_t seed[WSIDH_SEED_BYTES],
                                       uint8_t domain_sep) {
    WSIDH_PROFILE_BEGIN(public_poly_ntt, WSIDH_PROFILE_EVENT_POLY_SAMPLE_UNIFORM);
    sample_uniform_coeffs(out, seed, domain_sep);
    const int16_t *wave_ntt = wsidh_wave_table_ntt();
    if (wave_ntt) {
        for (int i = 0; i < WSIDH_N; i++) {
            out[i] = wsidh_mod_q_int32((int32_t)out[i] + wave_ntt[i]);
        }
    }
    WSIDH_PROFILE_END(public_poly_ntt);
}

void poly_print_csv(const poly *a, const char *label) {
    printf("# %s\n", label);
    for (int i = 0; i < WSIDH_N; i++) {
        printf("%d", a->coeffs[i]);
        if (i + 1 < WSIDH_N) printf(",");
    }
    printf("\n");
}


void poly_canon(poly *p) {
#ifdef WSIDH_USE_AVX2
    const __m256i q = _mm256_set1_epi16(WSIDH_Q);
    const __m256i q_minus_one = _mm256_set1_epi16(WSIDH_Q - 1);
    const __m256i zero = _mm256_setzero_si256();
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i coeffs = _mm256_load_si256((const __m256i *)&p->coeffs[i]);
        __m256i neg_mask = _mm256_cmpgt_epi16(zero, coeffs);
        coeffs = _mm256_add_epi16(coeffs, _mm256_and_si256(neg_mask, q));
        neg_mask = _mm256_cmpgt_epi16(zero, coeffs);
        coeffs = _mm256_add_epi16(coeffs, _mm256_and_si256(neg_mask, q));
        __m256i ge_mask = _mm256_cmpgt_epi16(coeffs, q_minus_one);
        coeffs = _mm256_sub_epi16(coeffs, _mm256_and_si256(ge_mask, q));
        ge_mask = _mm256_cmpgt_epi16(coeffs, q_minus_one);
        coeffs = _mm256_sub_epi16(coeffs, _mm256_and_si256(ge_mask, q));
        _mm256_store_si256((__m256i *)&p->coeffs[i], coeffs);
    }
#else
    for (int i = 0; i < WSIDH_N; i++) {
        int32_t x = p->coeffs[i];
        if (x < 0) x += WSIDH_Q;
        if (x < 0) x += WSIDH_Q;
        if (x >= WSIDH_Q) x -= WSIDH_Q;
        if (x >= WSIDH_Q) x -= WSIDH_Q;
        p->coeffs[i] = (int16_t)x;
    }
#endif
}

// Fast NTT-based multiplication
void poly_mul_ntt(poly *c, const poly *a, const poly *b) {
    WSIDH_PROFILE_BEGIN(poly_mul, WSIDH_PROFILE_EVENT_POLY_MUL_NTT);
    alignas(32) int16_t A[WSIDH_N];
    alignas(32) int16_t B[WSIDH_N];

    for (int i = 0; i < WSIDH_N; i++) {
        A[i] = a->coeffs[i];
        B[i] = b->coeffs[i];
    }

    int16_t *vecs[2] = {A, B};
    ntt_batch(vecs, 2);

    alignas(32) int16_t R[WSIDH_N];
    basemul(R, A, B);
    inv_ntt(R);

    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = R[i];
    }

    // ensure canonical [0, q-1]
    poly_canon(c);
    WSIDH_PROFILE_END(poly_mul);
}
