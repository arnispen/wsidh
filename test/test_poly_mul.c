#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "poly.h"

#define POLY_MUL_TRIALS 128

static void random_poly(poly *p) {
    for (int i = 0; i < WSIDH_N; i++) {
        p->coeffs[i] = (int16_t)(rand() % WSIDH_Q);
    }
}

static void poly_mul_schoolbook(poly *c, const poly *a, const poly *b) {
    int32_t tmp[WSIDH_N] = {0};
    for (int i = 0; i < WSIDH_N; i++) {
        for (int j = 0; j < WSIDH_N; j++) {
            int k = i + j;
            int32_t prod = (int32_t)a->coeffs[i] * b->coeffs[j];
            if (k >= WSIDH_N) {
                k -= WSIDH_N;
                tmp[k] -= prod;
            } else {
                tmp[k] += prod;
            }
        }
    }
    for (int i = 0; i < WSIDH_N; i++) {
        c->coeffs[i] = wsidh_mod_q(tmp[i]);
    }
}

static int compare_poly(const poly *a, const poly *b) {
    for (int i = 0; i < WSIDH_N; i++) {
        if (a->coeffs[i] != b->coeffs[i]) {
            return i;
        }
    }
    return -1;
}

int main(void) {
    srand((unsigned)time(NULL));
    for (int trial = 0; trial < POLY_MUL_TRIALS; trial++) {
        poly a, b, c_ntt, c_ref;
        random_poly(&a);
        random_poly(&b);
        poly_mul_ntt(&c_ntt, &a, &b);
        poly_mul_schoolbook(&c_ref, &a, &b);
        int mismatch = compare_poly(&c_ntt, &c_ref);
        if (mismatch >= 0) {
            fprintf(stderr,
                    "poly_mul mismatch trial %d coeff %d: ntt=%d ref=%d\n",
                    trial, mismatch, c_ntt.coeffs[mismatch], c_ref.coeffs[mismatch]);
            return 1;
        }
    }
    printf("poly_mul_ntt matches schoolbook for %d trials\n", POLY_MUL_TRIALS);
    return 0;
}
