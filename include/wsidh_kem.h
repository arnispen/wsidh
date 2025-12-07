// include/wsidh_kem.h
#ifndef WSIDH_KEM_H
#define WSIDH_KEM_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

/*
 * WSIDH parameter summary (see params.h for authoritative defines)
 *   N = WSIDH_N        polynomial degree
 *   q = WSIDH_Q        modulus for the NTT domain
 *   B_S/B_E            bounds for secrets and noise samples
 *
 * Public/secret/ciphertext sizes all derive from the polynomial size
 * and are exposed here so downstream code (tests, benchmarks, docs)
 * can present the same layout.
 */
#define WSIDH_POLY_BYTES   (2 * WSIDH_N)
#define WSIDH_POLY_COMPRESSED_BYTES ((WSIDH_N * 12) / 8)
#define WSIDH_PK_BYTES     (WSIDH_SEED_BYTES + \
                            2 * WSIDH_POLY_COMPRESSED_BYTES)   // seed_a || b || b_ntt
#define WSIDH_CT_BYTES     (2 * WSIDH_POLY_COMPRESSED_BYTES)   // compressed u || v
#define WSIDH_SS_BYTES     32

#if (2 * WSIDH_BOUND_S + 1) > 16
#error "Secret sampler bound exceeds 4-bit packing capacity"
#endif
#define WSIDH_SK_S_BITS   4
#define WSIDH_SK_S_BYTES  ((WSIDH_N * WSIDH_SK_S_BITS + 7) / 8)
#define WSIDH_SK_SNTT_BYTES WSIDH_POLY_COMPRESSED_BYTES        // compressed NTT(s)
#define WSIDH_SK_Z_BYTES   32
#define WSIDH_PK_HASH_BYTES 32
#define WSIDH_SK_BYTES (WSIDH_SK_S_BYTES + WSIDH_SK_SNTT_BYTES + \
                        WSIDH_PK_BYTES + WSIDH_PK_HASH_BYTES + WSIDH_SK_Z_BYTES)

int wsidh_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int wsidh_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int wsidh_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
void wsidh_set_random_callback(rand_func_t rng);

#endif // WSIDH_KEM_H
