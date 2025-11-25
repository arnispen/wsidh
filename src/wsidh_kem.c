#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wsidh_kem.h"
#include "poly.h"
#include "sha3.h"
#include "ntt.h"
#include "wsidh_profiler.h"
#include "fips202.h"

static void ensure_cached_wave(void);
static void cached_wave_poly(poly *a_out);
static poly cached_wave_time;
static int16_t cached_wave_ntt[WSIDH_N];
static int cached_wave_ready = 0;

/*
 * Secret-key layout (see include/wsidh_kem.h for the exported byte lengths):
 *   sk = s_bytes || s_ntt || pk_bytes || H(pk_bytes) || z
 *   s_bytes      : WSIDH_POLY_BYTES      serialized secret polynomial
 *   s_ntt        : WSIDH_POLY_BYTES      serialized NTT(s)
 *   pk_bytes     : WSIDH_PK_BYTES        compressed public key b(x)
 *   H(pk_bytes)  : WSIDH_PK_HASH_BYTES   convenience hash for documentation/tests
 *   z            : WSIDH_SK_Z_BYTES      random fallback used on FO rejection
 *
 * Ciphertext layout:
 *   ct = u_bytes || v_bytes  (both compressed to 12 bits/coeff)
 *
 * All secret polynomials (s, s_ntt) use raw 16-bit-per-coefficient encoding,
 * whereas public-facing polynomials (b, u, v) are 12-bit compressed to save
 * bandwidth.
 */

#define SK_S_OFFSET          0
#define SK_SNTT_OFFSET       (SK_S_OFFSET + WSIDH_SK_POLY_BYTES)
#define SK_PK_OFFSET         (SK_SNTT_OFFSET + WSIDH_SK_SNTT_BYTES)
#define SK_PK_HASH_OFFSET    (SK_PK_OFFSET + WSIDH_PK_BYTES)
#define SK_Z_OFFSET          (SK_PK_HASH_OFFSET + WSIDH_PK_HASH_BYTES)

#if (WSIDH_SK_BYTES != (WSIDH_SK_POLY_BYTES + WSIDH_SK_SNTT_BYTES + \
                        WSIDH_PK_BYTES + WSIDH_PK_HASH_BYTES + WSIDH_SK_Z_BYTES))
#error "WSIDH_SK_BYTES layout mismatch"
#endif

#if (WSIDH_SS_BYTES * 8 != WSIDH_N)
#error "WSIDH_SS_BYTES must match WSIDH_N/8 for current bit packing"
#endif

/* ============================================================
   RNG plumbing
   ============================================================ */
static void default_rng(uint8_t *out, size_t outlen) {
    static FILE *urandom = NULL;
    if (!urandom) {
        urandom = fopen("/dev/urandom", "rb");
    }
    if (urandom) {
        fread(out, 1, outlen, urandom);
        return;
    }
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* ============================================================
   Serialization helpers
   ============================================================ */
static void poly_to_bytes(uint8_t *out, const poly *p) {
    for (int i = 0; i < WSIDH_N; i++) {
        uint16_t t = (uint16_t)p->coeffs[i];
        out[2 * i]     = (uint8_t)(t & 0xFF);
        out[2 * i + 1] = (uint8_t)(t >> 8);
    }
}

static void poly_from_bytes(poly *p, const uint8_t *in) {
    for (int i = 0; i < WSIDH_N; i++) {
        uint16_t t = (uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8);
        p->coeffs[i] = (int16_t)t;
    }
}

static void poly_compress12(uint8_t *out, const poly *p) {
    poly tmp = *p;
    poly_canon(&tmp);
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j += 3) {
        uint16_t t0 = (uint16_t)tmp.coeffs[i];
        uint16_t t1 = (uint16_t)tmp.coeffs[i + 1];
        out[j] = (uint8_t)(t0 & 0xFF);
        out[j + 1] = (uint8_t)(((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4));
        out[j + 2] = (uint8_t)(t1 >> 4);
    }
}

static void poly_decompress12(poly *p, const uint8_t *in) {
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j += 3) {
        uint16_t t0 = (uint16_t)in[j] | (((uint16_t)in[j + 1] & 0x0F) << 8);
        uint16_t t1 = (uint16_t)(in[j + 1] >> 4) | ((uint16_t)in[j + 2] << 4);
        p->coeffs[i] = (int16_t)t0;
        p->coeffs[i + 1] = (int16_t)t1;
    }
}

static void load_pk(const uint8_t *pk,
                    poly *a,
                    poly *b,
                    poly *a_ntt,
                    poly *b_ntt) {
    cached_wave_poly(a);
    poly_decompress12(b, pk);
    if (a_ntt) {
        ensure_cached_wave();
        for (int i = 0; i < WSIDH_N; i++) {
            a_ntt->coeffs[i] = cached_wave_ntt[i];
        }
    }
    if (b_ntt) {
        *b_ntt = *b;
        ntt(b_ntt->coeffs);
    }
}

static void store_pk(uint8_t *pk, const poly *a, const poly *b) {
    (void)a;
    poly_compress12(pk, b);
}

static void load_ct(const uint8_t *ct, poly *u, poly *v) {
    poly_decompress12(u, ct);
    poly_decompress12(v, ct + WSIDH_POLY_COMPRESSED_BYTES);
}

static void store_ct(uint8_t *ct, const poly *u, const poly *v) {
    poly_compress12(ct, u);
    poly_compress12(ct + WSIDH_POLY_COMPRESSED_BYTES, v);
}

static void poly_ntt_from_poly(int16_t out[WSIDH_N], const poly *in) {
    for (int i = 0; i < WSIDH_N; i++) {
        out[i] = in->coeffs[i];
    }
    int16_t *vecs[1] = {out};
    ntt_batch(vecs, 1);
}

static void poly_mul_from_ntt_arrays(poly *out,
                                     const int16_t a_ntt[WSIDH_N],
                                     const int16_t b_ntt[WSIDH_N]) {
    int16_t result_ntt[WSIDH_N];
    basemul(result_ntt, a_ntt, b_ntt);
    inv_ntt(result_ntt);
    for (int i = 0; i < WSIDH_N; i++) {
        out->coeffs[i] = result_ntt[i];
    }
    poly_canon(out);
}

static void ensure_cached_wave(void) {
    if (cached_wave_ready) return;
    poly_from_wave(&cached_wave_time);
    poly_canon(&cached_wave_time);
    for (int i = 0; i < WSIDH_N; i++) {
        cached_wave_ntt[i] = cached_wave_time.coeffs[i];
    }
    ntt(cached_wave_ntt);
    cached_wave_ready = 1;
}

static void cached_wave_poly(poly *a_out) {
    ensure_cached_wave();
    *a_out = cached_wave_time;
}

static void poly_mul_with_cached_wave_from_ntt(poly *out,
                                               const int16_t operand_ntt[WSIDH_N]) {
    ensure_cached_wave();
    poly_mul_from_ntt_arrays(out, cached_wave_ntt, operand_ntt);
}

static int poly_is_cached_wave(const poly *candidate) {
    ensure_cached_wave();
    return memcmp(candidate->coeffs,
                  cached_wave_time.coeffs,
                  sizeof(cached_wave_time.coeffs)) == 0;
}

static void poly_mul_with_ntt_array_from_ntt(poly *out,
                                             const int16_t a_ntt[WSIDH_N],
                                             const int16_t operand_ntt[WSIDH_N]) {
    poly_mul_from_ntt_arrays(out, a_ntt, operand_ntt);
}

static void poly_mul_pair_with_ntt_arrays(poly *out0,
                                          const int16_t a0_ntt[WSIDH_N],
                                          poly *out1,
                                          const int16_t a1_ntt[WSIDH_N],
                                          const int16_t operand_ntt[WSIDH_N]) {
    int16_t tmp0[WSIDH_N];
    int16_t tmp1[WSIDH_N];
    basemul(tmp0, a0_ntt, operand_ntt);
    basemul(tmp1, a1_ntt, operand_ntt);
    int16_t *vecs[2] = {tmp0, tmp1};
    inv_ntt_batch(vecs, 2);
    for (int i = 0; i < WSIDH_N; i++) {
        out0->coeffs[i] = tmp0[i];
        out1->coeffs[i] = tmp1[i];
    }
}

/* ============================================================
   Constant-time helpers
   ============================================================ */
static uint32_t poly_diff(const poly *a, const poly *b) {
    uint32_t diff = 0;
    for (int i = 0; i < WSIDH_N; i++) {
        diff |= (uint16_t)(a->coeffs[i] ^ b->coeffs[i]);
    }
    return diff;
}

static inline int32_t wsidh_distance(int32_t x) {
    if (x < 0) x = -x;
    if (x > WSIDH_Q - x) x = WSIDH_Q - x;
    return x;
}

static void ct_select(uint8_t *dst,
                      const uint8_t *good,
                      const uint8_t *bad,
                      size_t len,
                      uint8_t use_bad) {
    uint8_t mask = (uint8_t)(-use_bad);  // 0x00 if success, 0xFF if failure
    for (size_t i = 0; i < len; i++) {
        uint8_t g = good[i];
        uint8_t b = bad[i];
        dst[i] = (uint8_t)((g & ~mask) | (b & mask)); // constant-time select
    }
}

/* ============================================================
   Message encode/decode helpers
   ============================================================ */
static void msg_to_poly(poly *out, const uint8_t *msg) {
    int16_t enc0 = 0;
    int16_t enc1 = WSIDH_Q / 2;
    for (int i = 0; i < WSIDH_N; i++) {
        int byte_idx = i >> 3;
        int bit_idx  = i & 7;
        uint8_t bit = 0;
        if (byte_idx < WSIDH_SS_BYTES) {
            bit = (uint8_t)((msg[byte_idx] >> bit_idx) & 1);
        }
        out->coeffs[i] = bit ? enc1 : enc0;
    }
}

static void poly_to_msg(uint8_t *msg, const poly *p) {
    memset(msg, 0, WSIDH_SS_BYTES);
    int16_t enc0 = 0;
    int16_t enc1 = WSIDH_Q / 2;

    for (int i = 0; i < WSIDH_N; i++) {
        int32_t x = p->coeffs[i];

        int32_t d0 = wsidh_distance(x - enc0);
        int32_t d1 = wsidh_distance(x - enc1);

        int32_t diff = d1 - d0;
        uint8_t bit = (uint8_t)((diff >> 31) & 1); // constant-time comparison

        int byte_idx = i >> 3;
        int bit_idx  = i & 7;
        if (byte_idx < WSIDH_SS_BYTES) {
            msg[byte_idx] |= (uint8_t)(bit << bit_idx);
        }
    }
}

/* ============================================================
   Deterministic expansion helpers (FO coins -> r,e1,e2)
   ============================================================ */
static void shake_seed_stream(shake128incctx *ctx,
                              const uint8_t seed[WSIDH_SEED_BYTES],
                              uint8_t domain_tag) {
    uint8_t input[WSIDH_SEED_BYTES + 1];
    memcpy(input, seed, WSIDH_SEED_BYTES);
    input[WSIDH_SEED_BYTES] = domain_tag;
    shake128_inc_init(ctx);
    shake128_inc_absorb(ctx, input, sizeof(input));
    shake128_inc_finalize(ctx);
}

static void sample_poly_from_ctx(poly *p,
                                 int bound,
                                 shake128incctx *ctx) {
    uint8_t buf[2 * WSIDH_N];
    size_t needed = wsidh_sample_bytes_required(bound);
    shake128_inc_squeeze(buf, needed, ctx);
    wsidh_sample_from_bytes(p, buf, bound);
}

static void sample_pair_from_seed(poly *p0,
                                  int bound0,
                                  poly *p1,
                                  int bound1,
                                  const uint8_t seed[WSIDH_SEED_BYTES],
                                  uint8_t domain_tag) {
    WSIDH_PROFILE_BEGIN(sample_pair_scope, WSIDH_PROFILE_EVENT_SAMPLE_DET);
    shake128incctx ctx;
    shake_seed_stream(&ctx, seed, domain_tag);
    sample_poly_from_ctx(p0, bound0, &ctx);
    sample_poly_from_ctx(p1, bound1, &ctx);
    shake128_inc_ctx_release(&ctx);
    WSIDH_PROFILE_END(sample_pair_scope);
}

static void sample_triple_from_seed(poly *p0,
                                    int bound0,
                                    poly *p1,
                                    int bound1,
                                    poly *p2,
                                    int bound2,
                                    const uint8_t seed[WSIDH_SEED_BYTES],
                                    uint8_t domain_tag) {
    WSIDH_PROFILE_BEGIN(sample_triple_scope, WSIDH_PROFILE_EVENT_SAMPLE_DET);
    shake128incctx ctx;
    shake_seed_stream(&ctx, seed, domain_tag);
    sample_poly_from_ctx(p0, bound0, &ctx);
    sample_poly_from_ctx(p1, bound1, &ctx);
    sample_poly_from_ctx(p2, bound2, &ctx);
    shake128_inc_ctx_release(&ctx);
    WSIDH_PROFILE_END(sample_triple_scope);
}

static void expand_deterministic(poly *r,
                                 poly *e1,
                                 poly *e2,
                                  const uint8_t seed[WSIDH_SEED_BYTES]) {
    sample_triple_from_seed(r, WSIDH_BOUND_S,
                            e1, WSIDH_BOUND_E,
                            e2, WSIDH_BOUND_E,
                            seed, 0x80);
}

static void coins_from_msg(uint8_t *coins,
                           const uint8_t *msg,
                           const uint8_t *pk_hash) {
    sha3_256incctx ctx;
    sha3_256_inc_init(&ctx);
    sha3_256_inc_absorb(&ctx, msg, WSIDH_SS_BYTES);
    sha3_256_inc_absorb(&ctx, pk_hash, WSIDH_PK_HASH_BYTES);
    sha3_256_inc_finalize(coins, &ctx);
}

static void hash_key(uint8_t *out,
                     const uint8_t *secret,
                     size_t secret_len,
                     const uint8_t *ct) {
    uint8_t buf[WSIDH_CT_BYTES + WSIDH_SS_BYTES];
    memcpy(buf, secret, secret_len);
    memcpy(buf + secret_len, ct, WSIDH_CT_BYTES);
    wsidh_sha3_256(out, buf, secret_len + WSIDH_CT_BYTES);
}

/* ============================================================
   Core CPA encrypt/decrypt building blocks
   ============================================================ */
static void wsidh_encrypt(poly *u,
                          poly *v,
                          const poly *a,
                          const poly *b,
                          const poly *a_ntt_opt,
                          const poly *b_ntt_opt,
                          const uint8_t *msg,
                          const uint8_t *coins) {
    poly r, e1, e2;
    int16_t r_ntt[WSIDH_N];
    poly tmp_ar, tmp_br;
    poly m_poly;

    expand_deterministic(&r, &e1, &e2, coins);
    poly_ntt_from_poly(r_ntt, &r);

    const int16_t *a_ntt_ptr = NULL;
    const int16_t *b_ntt_ptr = NULL;
    int need_a_fallback = 0;
    int need_b_fallback = 0;

    if (poly_is_cached_wave(a)) {
        a_ntt_ptr = cached_wave_ntt;
    } else if (a_ntt_opt) {
        a_ntt_ptr = a_ntt_opt->coeffs;
    } else {
        need_a_fallback = 1;
    }

    if (b_ntt_opt) {
        b_ntt_ptr = b_ntt_opt->coeffs;
    } else {
        need_b_fallback = 1;
    }

    if (a_ntt_ptr && b_ntt_ptr) {
        poly_mul_pair_with_ntt_arrays(&tmp_ar, a_ntt_ptr,
                                      &tmp_br, b_ntt_ptr,
                                      r_ntt);
    } else {
        if (a_ntt_ptr) {
            poly_mul_with_ntt_array_from_ntt(&tmp_ar, a_ntt_ptr, r_ntt);
        } else if (need_a_fallback) {
            poly_mul_ntt(&tmp_ar, a, &r);
        }

        if (b_ntt_ptr) {
            poly_mul_with_ntt_array_from_ntt(&tmp_br, b_ntt_ptr, r_ntt);
        } else if (need_b_fallback) {
            poly_mul_ntt(&tmp_br, b, &r);
        }
    }

    poly_add(u, &tmp_ar, &e1);
    poly_add(v, &tmp_br, &e2);

    msg_to_poly(&m_poly, msg);
    poly_add(v, v, &m_poly);

    poly_canon(u);
    poly_canon(v);
}

static void wsidh_decrypt(poly *out,
                          const poly *u,
                          const poly *v,
                          const poly *s,
                          const int16_t *s_ntt_opt) {
    poly us, diff;
    if (s_ntt_opt) {
        int16_t u_ntt[WSIDH_N];
        poly_ntt_from_poly(u_ntt, u);
        poly_mul_from_ntt_arrays(&us, s_ntt_opt, u_ntt);
    } else {
        poly_mul_ntt(&us, u, s);
    }
    poly_sub(&diff, v, &us);
    poly_canon(&diff);
    *out = diff;
}

/* ============================================================
   Public API
   ============================================================ */
int wsidh_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    WSIDH_PROFILE_BEGIN(keygen_scope, WSIDH_PROFILE_EVENT_KEYGEN);
    poly a, b, s, e, tmp;
    poly s_ntt_poly;
    int16_t s_ntt_arr[WSIDH_N];
    rand_func_t rng = default_rng;
    uint8_t noise_seed[WSIDH_SEED_BYTES];

    cached_wave_poly(&a);

    rng(noise_seed, sizeof(noise_seed));
    sample_pair_from_seed(&s, WSIDH_BOUND_S,
                          &e, WSIDH_BOUND_E,
                          noise_seed, 0x50);

    poly_ntt_from_poly(s_ntt_arr, &s);
    for (int i = 0; i < WSIDH_N; i++) {
        s_ntt_poly.coeffs[i] = s_ntt_arr[i];
    }

    poly_mul_with_cached_wave_from_ntt(&tmp, s_ntt_arr);
    poly_add(&b, &tmp, &e);
    poly_canon(&b);

    store_pk(pk, &a, &b);
    poly_to_bytes(sk + SK_S_OFFSET, &s);
    poly_to_bytes(sk + SK_SNTT_OFFSET, &s_ntt_poly);
    memcpy(sk + SK_PK_OFFSET, pk, WSIDH_PK_BYTES);

    wsidh_sha3_256(sk + SK_PK_HASH_OFFSET, pk, WSIDH_PK_BYTES);
    rng(sk + SK_Z_OFFSET, WSIDH_SK_Z_BYTES);

    WSIDH_PROFILE_END(keygen_scope);
    return 0;
}

int wsidh_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    WSIDH_PROFILE_BEGIN(enc_scope, WSIDH_PROFILE_EVENT_ENCAPS);
    poly a, b, u, v, a_ntt_poly, b_ntt_poly;
    uint8_t msg[WSIDH_SS_BYTES];
    uint8_t coins[WSIDH_SEED_BYTES];
    uint8_t pk_hash_local[WSIDH_PK_HASH_BYTES];
    rand_func_t rng = default_rng;

    if (!pk || !ct || !ss) {
        return -1;
    }

    load_pk(pk, &a, &b, &a_ntt_poly, &b_ntt_poly);
    wsidh_sha3_256(pk_hash_local, pk, WSIDH_PK_BYTES);

    rng(msg, sizeof(msg));
    coins_from_msg(coins, msg, pk_hash_local);

    wsidh_encrypt(&u, &v, &a, &b, &a_ntt_poly, &b_ntt_poly, msg, coins);
    store_ct(ct, &u, &v);

    hash_key(ss, msg, sizeof(msg), ct);
    WSIDH_PROFILE_END(enc_scope);
    return 0;
}

int wsidh_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    WSIDH_PROFILE_BEGIN(dec_scope, WSIDH_PROFILE_EVENT_DECAPS);
    if (!ct || !ss || !sk) {
        return -1;
    }

    poly u, v, s, diff_poly, s_ntt_poly;
    int16_t s_ntt_arr[WSIDH_N];
    poly a_re, b_re, u_re, v_re, a_ntt_re, b_ntt_re;
    uint8_t msg_prime[WSIDH_SS_BYTES];
    uint8_t coins[WSIDH_SEED_BYTES];

    load_ct(ct, &u, &v);
    poly_from_bytes(&s, sk + SK_S_OFFSET);
    poly_from_bytes(&s_ntt_poly, sk + SK_SNTT_OFFSET);
    for (int i = 0; i < WSIDH_N; i++) {
        s_ntt_arr[i] = s_ntt_poly.coeffs[i];
    }

    const uint8_t *pk_cached = sk + SK_PK_OFFSET;
    load_pk(pk_cached, &a_re, &b_re, &a_ntt_re, &b_ntt_re);

    wsidh_decrypt(&diff_poly, &u, &v, &s, s_ntt_arr);
    poly_to_msg(msg_prime, &diff_poly);

    const uint8_t *pk_hash_cached = sk + SK_PK_HASH_OFFSET;
    coins_from_msg(coins, msg_prime, pk_hash_cached);
    wsidh_encrypt(&u_re, &v_re, &a_re, &b_re, &a_ntt_re, &b_ntt_re, msg_prime, coins);

    uint32_t diff = poly_diff(&u, &u_re);
    diff |= poly_diff(&v, &v_re);
    uint8_t fail = (uint8_t)(diff != 0);

    uint8_t good_key[WSIDH_SS_BYTES];
    uint8_t bad_key[WSIDH_SS_BYTES];

    hash_key(good_key, msg_prime, sizeof(msg_prime), ct);
    hash_key(bad_key, sk + SK_Z_OFFSET, WSIDH_SK_Z_BYTES, ct);

    ct_select(ss, good_key, bad_key, WSIDH_SS_BYTES, fail);

    WSIDH_PROFILE_END(dec_scope);
    return 0;
}
