#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntt.h"
#include "poly.h"

#define NTT_ROUNDTRIP_TRIALS 1000

static void random_poly(poly *p) {
    for (int i = 0; i < WSIDH_N; i++) {
        p->coeffs[i] = (int16_t)(rand() % WSIDH_Q);
    }
}

static int compare_polys(const poly *a, const poly *b) {
    for (int i = 0; i < WSIDH_N; i++) {
        if (a->coeffs[i] != b->coeffs[i]) {
            return i + 1;
        }
    }
    return 0;
}

int main(void) {
    srand((unsigned)time(NULL));
    for (int trial = 0; trial < NTT_ROUNDTRIP_TRIALS; trial++) {
        poly input;
        poly roundtrip;
        random_poly(&input);
        roundtrip = input;
        ntt(roundtrip.coeffs);
        inv_ntt(roundtrip.coeffs);
        poly_canon(&input);
        poly_canon(&roundtrip);
        int mismatch_idx = compare_polys(&input, &roundtrip);
        if (mismatch_idx != 0) {
            fprintf(stderr,
                    "NTT roundtrip mismatch at trial %d coeff %d (got %d expected %d)\n",
                    trial,
                    mismatch_idx - 1,
                    roundtrip.coeffs[mismatch_idx - 1],
                    input.coeffs[mismatch_idx - 1]);
            return 1;
        }
    }
    printf("NTT roundtrip OK (%d trials)\n", NTT_ROUNDTRIP_TRIALS);
    return 0;
}
