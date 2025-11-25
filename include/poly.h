#ifndef WSIDH_POLY_H
#define WSIDH_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
    int16_t coeffs[WSIDH_N];
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
    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = wsidh_mod_q((int32_t)a->coeffs[i] + b->coeffs[i]);
    }
}

static inline void poly_sub(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = wsidh_mod_q((int32_t)a->coeffs[i] - b->coeffs[i]);
    }
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

static inline void wsidh_sample_from_bytes(poly *a,
                                           const uint8_t *buf,
                                           int bound) {
    if (bound == 2) {
        wsidh_cbd_eta2(a, buf);
        return;
    } else if (bound == 3) {
        wsidh_cbd_eta3(a, buf);
        return;
    }

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

void poly_from_wave(poly *a);
void poly_print_csv(const poly *a, const char *label);

void poly_canon(poly *p);


#endif
