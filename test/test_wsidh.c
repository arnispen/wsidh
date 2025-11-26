#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/wsidh_kem.h"
#include "../include/ntt.h"
#include "../include/poly.h"
#include "../include/wsidh_variants.h"

static int ntt_self_check(void);

static void random_bytes(uint8_t *out, size_t outlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        for (size_t i = 0; i < outlen; i++) {
            out[i] = (uint8_t)(rand() & 0xFF);
        }
        return;
    }
    fread(out, 1, outlen, f);
    fclose(f);
}

static void flip_random_bits(uint8_t *buf, size_t len, size_t flips) {
    if (len == 0) return;
    for (size_t i = 0; i < flips; i++) {
        uint8_t rnd[4];
        random_bytes(rnd, sizeof(rnd));
        size_t idx = ((size_t)rnd[0] << 8 | rnd[1]) % len;
        uint8_t bit = (uint8_t)(rnd[2] & 7);
        buf[idx] ^= (uint8_t)(1u << bit);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int run_corruption_case(const char *label,
                               const uint8_t *sk,
                               const uint8_t *ct_valid,
                               size_t offset,
                               size_t span) {
    uint8_t ct_bad[WSIDH_CT_BYTES];
    uint8_t ss_ref[WSIDH_SS_BYTES];
    uint8_t ss_bad[WSIDH_SS_BYTES];

    memcpy(ct_bad, ct_valid, WSIDH_CT_BYTES);
    if (span == 0) return -1;
    flip_random_bits(ct_bad + offset, span, 4);

    wsidh_crypto_kem_dec(ss_ref, ct_valid, sk);
    wsidh_crypto_kem_dec(ss_bad, ct_bad, sk);

    int same = memcmp(ss_ref, ss_bad, WSIDH_SS_BYTES) == 0;
    printf("[corrupt %-5s] key matches reference? %s\n",
           label,
           same ? "YES (unexpected)" : "NO  (expected)");
    return same ? -1 : 0;
}

static int run_failure_rate_test(const uint8_t *pk, const uint8_t *sk) {
    const size_t trials = 10000;
    size_t failures = 0;
    uint8_t ct[WSIDH_CT_BYTES];
    uint8_t ss_enc[WSIDH_SS_BYTES];
    uint8_t ss_dec[WSIDH_SS_BYTES];

    for (size_t i = 0; i < trials; i++) {
        wsidh_crypto_kem_enc(ct, ss_enc, pk);
        wsidh_crypto_kem_dec(ss_dec, ct, sk);
        if (memcmp(ss_enc, ss_dec, WSIDH_SS_BYTES) != 0) {
            failures++;
        }
    }

    double rate = (double)failures / (double)trials;
    printf("[error-rate] trials=%zu failures=%zu rate=%.6e\n",
           trials, failures, rate);
    return failures == 0 ? 0 : -1;
}

int main(void) {
    if (ntt_self_check() != 0) {
        fprintf(stderr, "NTT self-check failed\n");
        return 1;
    }
    uint8_t pk[WSIDH_PK_BYTES];
    uint8_t sk[WSIDH_SK_BYTES];
    uint8_t ct[WSIDH_CT_BYTES];
    uint8_t ss_enc[WSIDH_SS_BYTES];
    uint8_t ss_dec[WSIDH_SS_BYTES];

    if (wsidh_crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "KeyGen failed\n");
        return 1;
    }

    if (wsidh_crypto_kem_enc(ct, ss_enc, pk) != 0) {
        fprintf(stderr, "Encaps failed\n");
        return 1;
    }

    if (wsidh_crypto_kem_dec(ss_dec, ct, sk) != 0) {
        fprintf(stderr, "Decaps failed\n");
        return 1;
    }

    int ok = (memcmp(ss_enc, ss_dec, WSIDH_SS_BYTES) == 0);

    const wsidh_params_t *params = wsidh_params_active();
    if (!params) {
        fprintf(stderr, "Active parameter struct unavailable\n");
        return 1;
    }
    printf("%s parameters: N=%d q=%d bound_s=%d bound_e=%d\n",
           wsidh_active_params.name,
           params->N, params->Q, params->bound_s, params->bound_e);
    printf("pk=%zu bytes, sk=%zu bytes, ct=%zu bytes, ss=%zu bytes\n",
           (size_t)WSIDH_PK_BYTES, (size_t)WSIDH_SK_BYTES,
           (size_t)WSIDH_CT_BYTES, (size_t)WSIDH_SS_BYTES);
    print_hex("ss_enc = ", ss_enc, WSIDH_SS_BYTES);
    print_hex("ss_dec = ", ss_dec, WSIDH_SS_BYTES);
    printf("Round-trip correctness: %s\n", ok ? "PASS" : "FAIL");

    if (!ok) return 1;

    if (run_failure_rate_test(pk, sk) != 0) {
        printf("Non-zero failure count observed.\n");
    }

    int res = 0;
    res |= run_corruption_case("u", sk, ct, 0, WSIDH_POLY_COMPRESSED_BYTES);
    res |= run_corruption_case("v", sk, ct, WSIDH_POLY_COMPRESSED_BYTES, WSIDH_POLY_COMPRESSED_BYTES);
    res |= run_corruption_case("both", sk, ct, 0, WSIDH_CT_BYTES);

    return res == 0 ? 0 : 1;
}
static int ntt_self_check(void) {
#ifdef WSIDH_USE_AVX2
    return 0;
#endif
    poly p;
    for (int trial = 0; trial < 16; trial++) {
        for (int i = 0; i < WSIDH_N; i++) {
            p.coeffs[i] = (int16_t)(rand() % WSIDH_Q);
        }
        poly reference = p;
        ntt(p.coeffs);
        inv_ntt(p.coeffs);
        poly_canon(&p);
        for (int i = 0; i < WSIDH_N; i++) {
            if (p.coeffs[i] != reference.coeffs[i]) {
                fprintf(stderr, "NTT mismatch at trial=%d idx=%d ref=%d got=%d\n",
                        trial, i, reference.coeffs[i], p.coeffs[i]);
                return -1;
            }
        }
    }
    return 0;
}
