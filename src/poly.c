// src/poly.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "poly.h"
#include "ntt.h"
#include "sha3.h"
#include "wsidh_profiler.h"

#if WSIDH_N != 256
#error "Precomputed wave table currently assumes WSIDH_N = 256"
#endif

static const int16_t wsidh_wave_table[WSIDH_N] = {
    0,33,66,99,132,164,195,227,257,287,316,344,371,397,422,446,
    468,490,510,528,546,562,576,589,600,610,619,626,631,635,638,639,
    639,637,635,630,625,619,611,602,593,582,571,559,546,532,518,504,
    489,474,458,442,427,411,395,379,363,348,333,318,303,289,276,263,
    250,238,227,216,206,196,188,179,172,165,159,154,149,145,141,138,
    135,133,132,131,130,130,130,130,131,132,133,134,135,136,137,138,
    139,140,140,141,141,141,140,140,138,137,135,133,130,127,123,119,
    115,110,105,99,93,87,80,73,66,58,50,42,34,26,17,9,
    0,2293,2285,2276,2268,2260,2252,2244,2236,2229,2222,2215,2209,2203,2197,2192,
    2187,2183,2179,2175,2172,2169,2167,2165,2164,2162,2162,2161,2161,2161,2162,2162,
    2163,2164,2165,2166,2167,2168,2169,2170,2171,2172,2172,2172,2172,2171,2170,2169,
    2167,2164,2161,2157,2153,2148,2143,2137,2130,2123,2114,2106,2096,2086,2075,2064,
    2052,2039,2026,2013,1999,1984,1969,1954,1939,1923,1907,1891,1875,1860,1844,1828,
    1813,1798,1784,1770,1756,1743,1731,1720,1709,1700,1691,1683,1677,1672,1667,1665,
    1663,1663,1664,1667,1671,1676,1683,1692,1702,1713,1726,1740,1756,1774,1792,1812,
    1834,1856,1880,1905,1931,1958,1986,2015,2045,2075,2107,2138,2170,2203,2236,2269
};

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
    memcpy(a->coeffs, wsidh_wave_table, sizeof(wsidh_wave_table));
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
