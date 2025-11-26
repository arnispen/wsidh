// src/poly.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "poly.h"
#include "ntt.h"
#include "sha3.h"
#include "wsidh_profiler.h"

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


// Build wave-based a(x) like your Python make_base_poly:
//    f_k = 400*sin(2πk/N) + 250*sin(4πk/N) + 150*sin(6πk/N)
void poly_from_wave(poly *a) {
    WSIDH_PROFILE_BEGIN(wave, WSIDH_PROFILE_EVENT_POLY_FROM_WAVE);
    const wsidh_params_t *params = wsidh_params_active();
    if (!params || !params->wave_table ||
        params->wave_table_len != (size_t)WSIDH_N) {
        WSIDH_PROFILE_END(wave);
        return;
    }
    memcpy(a->coeffs,
           params->wave_table,
           params->wave_table_len * sizeof(int16_t));
    WSIDH_PROFILE_END(wave);
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
    for (int i = 0; i < WSIDH_N; i++) {
        int16_t x = p->coeffs[i] % WSIDH_Q;
        if (x < 0) x += WSIDH_Q;
        p->coeffs[i] = x;
    }
}

// Fast NTT-based multiplication
void poly_mul_ntt(poly *c, const poly *a, const poly *b) {
    WSIDH_PROFILE_BEGIN(poly_mul, WSIDH_PROFILE_EVENT_POLY_MUL_NTT);
    int16_t A[WSIDH_N];
    int16_t B[WSIDH_N];

    for (int i = 0; i < WSIDH_N; i++) {
        A[i] = a->coeffs[i];
        B[i] = b->coeffs[i];
    }

    int16_t *vecs[2] = {A, B};
    ntt_batch(vecs, 2);

    int16_t R[WSIDH_N];
    basemul(R, A, B);
    inv_ntt(R);

    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = R[i];
    }

    // ensure canonical [0, q-1]
    poly_canon(c);
    WSIDH_PROFILE_END(poly_mul);
}
