#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdalign.h>

#include "wsidh_kem.h"
#include "poly.h"
#include "sha3.h"
#include "ntt.h"
#include "wsidh_profiler.h"
#include "fips202.h"
#ifdef WSIDH_USE_AVX2
#include "wsidh_avx2_paths.h"
#include WSIDH_AVX2_HEADER(fips202x4.h)
#endif

#define WSIDH_MAX_HASH_INPUT (WSIDH_CT_BYTES + WSIDH_SK_Z_BYTES + WSIDH_SS_BYTES + 4)
#define WSIDH_COINS_DOMAIN 0x5A
#define WSIDH_KDF_DOMAIN_GOOD 0xA0
#define WSIDH_KDF_DOMAIN_BAD  0xA1
#define WSIDH_KDF_DOMAIN_DUMMY0 0x7C
#define WSIDH_KDF_DOMAIN_DUMMY1 0xA3
#define WSIDH_A_SEED_DOMAIN 0xB7
#ifdef WSIDH_USE_AVX2
#define WSIDH_MAX_SAMPLE_BYTES \
    ((((2 * WSIDH_N) + SHAKE128_RATE - 1) / SHAKE128_RATE) * SHAKE128_RATE)
#endif

/*
 * Secret-key layout (see include/wsidh_kem.h for the exported byte lengths):
 *   sk = s_bytes || s_ntt || pk_bytes || H(pk_bytes) || z
 *   s_bytes      : packed 4-bit coefficients of secret s (two coeffs per byte)
 *   s_ntt        : WSIDH_POLY_COMPRESSED_BYTES    12-bit packed NTT(s)
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
#define SK_SNTT_OFFSET       (SK_S_OFFSET + WSIDH_SK_S_BYTES)
#define SK_PK_OFFSET         (SK_SNTT_OFFSET + WSIDH_SK_SNTT_BYTES)
#define SK_PK_HASH_OFFSET    (SK_PK_OFFSET + WSIDH_PK_BYTES)
#define SK_Z_OFFSET          (SK_PK_HASH_OFFSET + WSIDH_PK_HASH_BYTES)

#define PK_ASEED_OFFSET      0
#define PK_B_OFFSET          (PK_ASEED_OFFSET + WSIDH_SEED_BYTES)
#define PK_BNTT_OFFSET       (PK_B_OFFSET + WSIDH_POLY_COMPRESSED_BYTES)

#if (PK_BNTT_OFFSET + WSIDH_POLY_COMPRESSED_BYTES != WSIDH_PK_BYTES)
#error "PK layout mismatch"
#endif

#if (WSIDH_SK_BYTES != (WSIDH_SK_S_BYTES + WSIDH_SK_SNTT_BYTES + \
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

static rand_func_t g_wsidh_rng = default_rng;

void wsidh_set_random_callback(rand_func_t rng) {
    g_wsidh_rng = rng ? rng : default_rng;
}

static inline rand_func_t wsidh_get_rng(void) {
    return g_wsidh_rng ? g_wsidh_rng : default_rng;
}

/* ============================================================
   Serialization helpers
   ============================================================ */
static void poly_ntt_from_poly(int16_t out[WSIDH_N], const poly *in);

static void poly_to_bytes(uint8_t *out, const poly *p) {
    WSIDH_PROFILE_BEGIN(poly_to_bytes_scope, WSIDH_PROFILE_EVENT_SERIALIZE);
    for (int i = 0; i < WSIDH_N; i++) {
        uint16_t t = (uint16_t)p->coeffs[i];
        out[2 * i]     = (uint8_t)(t & 0xFF);
        out[2 * i + 1] = (uint8_t)(t >> 8);
    }
    WSIDH_PROFILE_END(poly_to_bytes_scope);
}

static void poly_from_bytes(poly *p, const uint8_t *in) {
    WSIDH_PROFILE_BEGIN(poly_from_bytes_scope, WSIDH_PROFILE_EVENT_DESERIALIZE);
    for (int i = 0; i < WSIDH_N; i++) {
        uint16_t t = (uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8);
        p->coeffs[i] = (int16_t)t;
    }
    WSIDH_PROFILE_END(poly_from_bytes_scope);
}

static void poly_compress12(uint8_t *out, const poly *p) {
    WSIDH_PROFILE_BEGIN(poly_compress_scope, WSIDH_PROFILE_EVENT_COMPRESS);
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j += 3) {
        uint16_t t0 = (uint16_t)p->coeffs[i];
        uint16_t t1 = (uint16_t)p->coeffs[i + 1];
        out[j] = (uint8_t)(t0 & 0xFF);
        out[j + 1] = (uint8_t)(((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4));
        out[j + 2] = (uint8_t)(t1 >> 4);
    }
    WSIDH_PROFILE_END(poly_compress_scope);
}

static void poly_decompress12(poly *p, const uint8_t *in) {
    WSIDH_PROFILE_BEGIN(poly_decompress_scope, WSIDH_PROFILE_EVENT_DECOMPRESS);
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j += 3) {
        uint16_t t0 = (uint16_t)in[j] | (((uint16_t)in[j + 1] & 0x0F) << 8);
        uint16_t t1 = (uint16_t)(in[j + 1] >> 4) | ((uint16_t)in[j + 2] << 4);
        p->coeffs[i] = (int16_t)t0;
        p->coeffs[i + 1] = (int16_t)t1;
    }
    WSIDH_PROFILE_END(poly_decompress_scope);
}

#define WSIDH_SK_SMALL_BIAS (1 << (WSIDH_SK_S_BITS - 1))

static void poly_small_pack(uint8_t *out, const poly *p) {
    WSIDH_PROFILE_BEGIN(poly_small_pack_scope, WSIDH_PROFILE_EVENT_PACK);
#ifdef WSIDH_USE_AVX2
    const __m128i bias = _mm_set1_epi16(WSIDH_SK_SMALL_BIAS);
    const __m128i zero = _mm_setzero_si128();
    const __m128i maxv = _mm_set1_epi16(15);
    const __m128i keep_low8 = _mm_set_epi64x(0, -1ll);
    const __m128i mask_nibble = _mm_set1_epi8(0x0F);
    const __m128i perm_even = _mm_setr_epi8(0, 2, 4, 6,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80);
    const __m128i perm_odd  = _mm_setr_epi8(1, 3, 5, 7,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80,
                                            (char)0x80, (char)0x80, (char)0x80, (char)0x80);
    for (int i = 0, j = 0; i < WSIDH_N; i += 8, j += 4) {
        __m128i coeffs = _mm_load_si128((const __m128i *)&p->coeffs[i]);
        coeffs = _mm_add_epi16(coeffs, bias);
        coeffs = _mm_max_epi16(coeffs, zero);
        coeffs = _mm_min_epi16(coeffs, maxv);

        __m128i bytes = _mm_packus_epi16(coeffs, coeffs);
        bytes = _mm_and_si128(bytes, keep_low8);
        bytes = _mm_and_si128(bytes, mask_nibble);

        __m128i even = _mm_shuffle_epi8(bytes, perm_even);
        __m128i odd = _mm_shuffle_epi8(bytes, perm_odd);
        odd = _mm_slli_epi16(odd, 4);
        __m128i packed = _mm_or_si128(even, odd);
        uint32_t chunk = (uint32_t)_mm_cvtsi128_si32(packed);
        memcpy(out + j, &chunk, sizeof(uint32_t));
    }
#else
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j++) {
        int v0 = p->coeffs[i] + WSIDH_SK_SMALL_BIAS;
        int v1 = p->coeffs[i + 1] + WSIDH_SK_SMALL_BIAS;
        if (v0 < 0) v0 = 0;
        if (v0 > 15) v0 = 15;
        if (v1 < 0) v1 = 0;
        if (v1 > 15) v1 = 15;
        out[j] = (uint8_t)((uint8_t)v0 | ((uint8_t)v1 << 4));
    }
#endif
    WSIDH_PROFILE_END(poly_small_pack_scope);
}

static void poly_small_unpack(poly *p, const uint8_t *in) {
    WSIDH_PROFILE_BEGIN(poly_small_unpack_scope, WSIDH_PROFILE_EVENT_UNPACK);
#ifdef WSIDH_USE_AVX2
    const __m128i bias = _mm_set1_epi16(WSIDH_SK_SMALL_BIAS);
    const __m128i mask = _mm_set1_epi16(0x000F);
    const __m128i zero = _mm_setzero_si128();
    for (int i = 0, j = 0; i < WSIDH_N; i += 8, j += 4) {
        uint32_t word = wsidh_load32_little(in + j);
        __m128i bytes = _mm_cvtsi32_si128((int)word);
        bytes = _mm_unpacklo_epi8(bytes, zero);
        __m128i lo = _mm_and_si128(bytes, mask);
        __m128i hi = _mm_and_si128(_mm_srli_epi16(bytes, 4), mask);
        __m128i chunk0 = _mm_unpacklo_epi16(lo, hi);
        __m128i chunk1 = _mm_unpackhi_epi16(lo, hi);
        chunk0 = _mm_sub_epi16(chunk0, bias);
        chunk1 = _mm_sub_epi16(chunk1, bias);
        _mm_store_si128((__m128i *)&p->coeffs[i], chunk0);
        _mm_store_si128((__m128i *)&p->coeffs[i + 4], chunk1);
    }
#else
    for (int i = 0, j = 0; i < WSIDH_N; i += 2, j++) {
        uint8_t byte = in[j];
        int c0 = (int)(byte & 0x0F) - WSIDH_SK_SMALL_BIAS;
        int c1 = (int)(byte >> 4) - WSIDH_SK_SMALL_BIAS;
        p->coeffs[i] = (int16_t)c0;
        p->coeffs[i + 1] = (int16_t)c1;
    }
#endif
    WSIDH_PROFILE_END(poly_small_unpack_scope);
}

#ifndef WSIDH_DISABLE_PK_HASH_CACHE
typedef struct {
    uint8_t pk[WSIDH_PK_BYTES];
    uint8_t hash[WSIDH_PK_HASH_BYTES];
    atomic_flag lock;
    int valid;
} wsidh_pk_hash_cache_t;

static wsidh_pk_hash_cache_t g_pk_hash_cache = {
    .lock = ATOMIC_FLAG_INIT,
    .valid = 0,
};

static void wsidh_hash_pk_cached(uint8_t *out, const uint8_t *pk) {
    if (!out || !pk) return;
    while (atomic_flag_test_and_set_explicit(&g_pk_hash_cache.lock, memory_order_acquire)) {
        ; // spin
    }
    if (g_pk_hash_cache.valid &&
        memcmp(g_pk_hash_cache.pk, pk, WSIDH_PK_BYTES) == 0) {
        memcpy(out, g_pk_hash_cache.hash, WSIDH_PK_HASH_BYTES);
        atomic_flag_clear_explicit(&g_pk_hash_cache.lock, memory_order_release);
        return;
    }
    wsidh_sha3_256(out, pk, WSIDH_PK_BYTES);
    memcpy(g_pk_hash_cache.pk, pk, WSIDH_PK_BYTES);
    memcpy(g_pk_hash_cache.hash, out, WSIDH_PK_HASH_BYTES);
    g_pk_hash_cache.valid = 1;
    atomic_flag_clear_explicit(&g_pk_hash_cache.lock, memory_order_release);
}
#else
static void wsidh_hash_pk_cached(uint8_t *out, const uint8_t *pk) {
    wsidh_sha3_256(out, pk, WSIDH_PK_BYTES);
}
#endif

typedef struct {
    uint8_t seed[WSIDH_SEED_BYTES];
    poly a_time;
    alignas(32) int16_t a_ntt[WSIDH_N];
    atomic_flag lock;
    int valid;
} wsidh_a_cache_t;

static wsidh_a_cache_t g_wsidh_a_cache = {
    .lock = ATOMIC_FLAG_INIT,
    .valid = 0,
};

static void wsidh_expand_a_from_seed(poly *a_time,
                                     int16_t a_ntt_out[WSIDH_N],
                                     const uint8_t seed[WSIDH_SEED_BYTES],
                                     uint8_t domain_sep) {
    if (!seed) return;
    alignas(32) int16_t local_ntt[WSIDH_N];
    int16_t *target_ntt = a_ntt_out ? a_ntt_out : local_ntt;
    poly_sample_uniform_ntt_from_seed(target_ntt, seed, domain_sep);
    const int16_t *wave_mask = wsidh_wave_ntt_mask();
    if (wave_mask) {
        for (int i = 0; i < WSIDH_N; i++) {
            int32_t val = (int32_t)target_ntt[i] +
                          (int32_t)WSIDH_WAVE_LAMBDA * wave_mask[i];
            target_ntt[i] = wsidh_mod_q(val);
        }
    }
    if (a_time) {
        alignas(32) int16_t tmp_time[WSIDH_N];
        memcpy(tmp_time, target_ntt, sizeof(tmp_time));
        inv_ntt(tmp_time);
        for (int i = 0; i < WSIDH_N; i++) {
            a_time->coeffs[i] = tmp_time[i];
        }
        poly_canon(a_time);
    }
}

static void wsidh_load_a_cached(poly *a_out,
                                poly *a_ntt_out,
                                const uint8_t *seed) {
    if (!seed || (!a_out && !a_ntt_out)) {
        return;
    }
    while (atomic_flag_test_and_set_explicit(&g_wsidh_a_cache.lock,
                                             memory_order_acquire)) {
        ;
    }
    if (!g_wsidh_a_cache.valid ||
        memcmp(g_wsidh_a_cache.seed, seed, WSIDH_SEED_BYTES) != 0) {
        wsidh_expand_a_from_seed(&g_wsidh_a_cache.a_time,
                                 g_wsidh_a_cache.a_ntt,
                                 seed,
                                 WSIDH_A_SEED_DOMAIN);
        memcpy(g_wsidh_a_cache.seed, seed, WSIDH_SEED_BYTES);
        g_wsidh_a_cache.valid = 1;
    }
    if (a_out) {
        *a_out = g_wsidh_a_cache.a_time;
    }
    if (a_ntt_out) {
        for (int i = 0; i < WSIDH_N; i++) {
            a_ntt_out->coeffs[i] = g_wsidh_a_cache.a_ntt[i];
        }
    }
    atomic_flag_clear_explicit(&g_wsidh_a_cache.lock, memory_order_release);
}

static void load_pk(const uint8_t *pk,
                    poly *a,
                    poly *b,
                    poly *a_ntt,
                    poly *b_ntt,
                    const uint8_t *pk_hash_opt) {
    WSIDH_PROFILE_BEGIN(load_pk_scope, WSIDH_PROFILE_EVENT_DESERIALIZE);
    (void)pk_hash_opt;
    if (!pk) {
        WSIDH_PROFILE_END(load_pk_scope);
        return;
    }

    if (a || a_ntt) {
        wsidh_load_a_cached(a ? a : NULL,
                            a_ntt ? a_ntt : NULL,
                            pk + PK_ASEED_OFFSET);
    }

    if (b) {
        poly_decompress12(b, pk + PK_B_OFFSET);
    }
    if (b_ntt) {
        poly_decompress12(b_ntt, pk + PK_BNTT_OFFSET);
    }
    WSIDH_PROFILE_END(load_pk_scope);
}

static void store_pk(uint8_t *pk,
                     const uint8_t *a_seed,
                     const poly *b,
                     const poly *b_ntt) {
    WSIDH_PROFILE_BEGIN(store_pk_scope, WSIDH_PROFILE_EVENT_SERIALIZE);
    if (a_seed) {
        memcpy(pk + PK_ASEED_OFFSET, a_seed, WSIDH_SEED_BYTES);
    }
    poly canonical_b = *b;
    poly_canon(&canonical_b);
    poly_compress12(pk + PK_B_OFFSET, &canonical_b);
    poly canonical_ntt = *b_ntt;
    poly_canon(&canonical_ntt);
    poly_compress12(pk + PK_BNTT_OFFSET, &canonical_ntt);
    WSIDH_PROFILE_END(store_pk_scope);
}

static void load_ct(const uint8_t *ct, poly *u, poly *v) {
    WSIDH_PROFILE_BEGIN(load_ct_scope, WSIDH_PROFILE_EVENT_DESERIALIZE);
    poly_decompress12(u, ct);
    poly_decompress12(v, ct + WSIDH_POLY_COMPRESSED_BYTES);
    WSIDH_PROFILE_END(load_ct_scope);
}

static void store_ct(uint8_t *ct, const poly *u, const poly *v) {
    WSIDH_PROFILE_BEGIN(store_ct_scope, WSIDH_PROFILE_EVENT_SERIALIZE);
    poly_compress12(ct, u);
    poly_compress12(ct + WSIDH_POLY_COMPRESSED_BYTES, v);
    WSIDH_PROFILE_END(store_ct_scope);
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
    alignas(32) int16_t result_ntt[WSIDH_N];
    basemul(result_ntt, a_ntt, b_ntt);
    inv_ntt(result_ntt);
    for (int i = 0; i < WSIDH_N; i++) {
        out->coeffs[i] = result_ntt[i];
    }
    poly_canon(out);
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
    alignas(32) int16_t tmp0[WSIDH_N];
    alignas(32) int16_t tmp1[WSIDH_N];
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
    WSIDH_PROFILE_BEGIN(poly_diff_scope, WSIDH_PROFILE_EVENT_CT_COMPARE);
#ifdef WSIDH_USE_AVX2
    __m256i acc = _mm256_setzero_si256();
    for (int i = 0; i < WSIDH_N; i += 16) {
        __m256i va = _mm256_load_si256((const __m256i *)&a->coeffs[i]);
        __m256i vb = _mm256_load_si256((const __m256i *)&b->coeffs[i]);
        acc = _mm256_or_si256(acc, _mm256_xor_si256(va, vb));
    }
    __m128i acc128 = _mm_or_si128(_mm256_castsi256_si128(acc),
                                  _mm256_extracti128_si256(acc, 1));
    uint32_t diff = (uint32_t)!_mm_testz_si128(acc128, acc128);
#else
    uint32_t diff = 0;
    for (int i = 0; i < WSIDH_N; i++) {
        diff |= (uint16_t)(a->coeffs[i] ^ b->coeffs[i]);
    }
#endif
    WSIDH_PROFILE_END(poly_diff_scope);
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
    WSIDH_PROFILE_BEGIN(ct_select_scope, WSIDH_PROFILE_EVENT_CT_COMPARE);
    uint8_t mask = (uint8_t)(-use_bad);  // 0x00 if success, 0xFF if failure
#ifdef WSIDH_USE_AVX2
    __m256i mask_vec = _mm256_set1_epi8((char)mask);
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i vg = _mm256_loadu_si256((const __m256i *)(good + i));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(bad + i));
        __m256i blended = _mm256_blendv_epi8(vg, vb, mask_vec);
        _mm256_storeu_si256((__m256i *)(dst + i), blended);
    }
    for (; i < len; i++) {
        uint8_t g = good[i];
        uint8_t b = bad[i];
        dst[i] = (uint8_t)((g & ~mask) | (b & mask));
    }
#else
    for (size_t i = 0; i < len; i++) {
        uint8_t g = good[i];
        uint8_t b = bad[i];
        dst[i] = (uint8_t)((g & ~mask) | (b & mask));
    }
#endif
    WSIDH_PROFILE_END(ct_select_scope);
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
#ifdef WSIDH_USE_AVX2
static void sample_multi_from_seed_x4(poly **polys,
                                      const int *bounds,
                                      size_t count,
                                      const uint8_t seed[WSIDH_SEED_BYTES],
                                      uint8_t domain_tag) {
    if (!polys || !bounds || count == 0 || count > 3) {
        return;
    }
    uint8_t lane_inputs[4][WSIDH_SEED_BYTES + 2];
    for (size_t lane = 0; lane < 4; lane++) {
        memcpy(lane_inputs[lane], seed, WSIDH_SEED_BYTES);
        lane_inputs[lane][WSIDH_SEED_BYTES] = domain_tag;
        lane_inputs[lane][WSIDH_SEED_BYTES + 1] = (uint8_t)lane;
    }

    keccakx4_state state;
    WSIDH_PROFILE_BEGIN(shake128x4_absorb_scope, WSIDH_PROFILE_EVENT_SHAKE128X4);
    PQCLEAN_MLKEM512_AVX2_shake128x4_absorb_once(&state,
            lane_inputs[0], lane_inputs[1],
            lane_inputs[2], lane_inputs[3],
            sizeof lane_inputs[0]);
    WSIDH_PROFILE_END(shake128x4_absorb_scope);

    size_t lane_need[4] = {0};
    size_t max_need = 0;
    for (size_t lane = 0; lane < count; lane++) {
        lane_need[lane] = wsidh_sample_bytes_required(bounds[lane]);
        if (lane_need[lane] > max_need) {
            max_need = lane_need[lane];
        }
    }
    size_t blocks = (max_need + SHAKE128_RATE - 1) / SHAKE128_RATE;
    if (blocks == 0) {
        blocks = 1;
    }

    uint8_t lane_buf[4][WSIDH_MAX_SAMPLE_BYTES];
    memset(lane_buf, 0, sizeof(lane_buf));
    WSIDH_PROFILE_BEGIN(shake128x4_squeeze_scope, WSIDH_PROFILE_EVENT_SHAKE128X4);
    PQCLEAN_MLKEM512_AVX2_shake128x4_squeezeblocks(
        lane_buf[0], lane_buf[1], lane_buf[2], lane_buf[3],
        blocks, &state);
    WSIDH_PROFILE_END(shake128x4_squeeze_scope);

    for (size_t lane = 0; lane < count; lane++) {
        wsidh_sample_from_bytes(polys[lane],
                                lane_buf[lane],
                                bounds[lane]);
    }
}
#endif

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
#ifdef WSIDH_USE_AVX2
    poly *polys[2] = {p0, p1};
    int bounds[2] = {bound0, bound1};
    sample_multi_from_seed_x4(polys, bounds, 2, seed, domain_tag);
#else
    shake128incctx ctx;
    shake_seed_stream(&ctx, seed, domain_tag);
    sample_poly_from_ctx(p0, bound0, &ctx);
    sample_poly_from_ctx(p1, bound1, &ctx);
    shake128_inc_ctx_release(&ctx);
#endif
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
#ifdef WSIDH_USE_AVX2
    poly *polys[3] = {p0, p1, p2};
    int bounds[3] = {bound0, bound1, bound2};
    sample_multi_from_seed_x4(polys, bounds, 3, seed, domain_tag);
#else
    shake128incctx ctx;
    shake_seed_stream(&ctx, seed, domain_tag);
    sample_poly_from_ctx(p0, bound0, &ctx);
    sample_poly_from_ctx(p1, bound1, &ctx);
    sample_poly_from_ctx(p2, bound2, &ctx);
    shake128_inc_ctx_release(&ctx);
#endif
    WSIDH_PROFILE_END(sample_triple_scope);
}

static void expand_deterministic(poly *r,
                                 poly *e1,
                                 poly *e2,
                                  const uint8_t seed[WSIDH_SEED_BYTES]) {
    const wsidh_params_t *params = wsidh_params_active();
    int bound_s = params ? params->bound_s : WSIDH_BOUND_S;
    int bound_e = params ? params->bound_e : WSIDH_BOUND_E;
    sample_triple_from_seed(r, bound_s,
                            e1, bound_e,
                            e2, bound_e,
                            seed, 0x80);
}

static void coins_from_msg(uint8_t *coins,
                           const uint8_t *msg,
                           const uint8_t *pk_hash) {
    if (!coins || !msg || !pk_hash) return;
    shake256incctx ctx;
    WSIDH_PROFILE_BEGIN(coins_scope, WSIDH_PROFILE_EVENT_SHAKE256);
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, msg, WSIDH_SS_BYTES);
    shake256_inc_absorb(&ctx, pk_hash, WSIDH_PK_HASH_BYTES);
    uint8_t domain = WSIDH_COINS_DOMAIN;
    shake256_inc_absorb(&ctx, &domain, 1);
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(coins, WSIDH_SEED_BYTES, &ctx);
    shake256_inc_ctx_release(&ctx);
    WSIDH_PROFILE_END(coins_scope);
}

static void hash_key_from_parts(uint8_t *out,
                                const uint8_t *ct,
                                const uint8_t *secret,
                                size_t secret_len,
                                uint8_t domain_tag) {
    if (!secret || !ct || !out) return;
    const size_t max_len = WSIDH_MAX_HASH_INPUT;
    size_t copy_secret = secret_len > max_len ? max_len : secret_len;
    size_t remaining = (copy_secret < max_len) ? (max_len - copy_secret) : 0;
    size_t copy_ct = WSIDH_CT_BYTES > remaining ? remaining : WSIDH_CT_BYTES;

    shake256incctx ctx;
    WSIDH_PROFILE_BEGIN(kdf_scope, WSIDH_PROFILE_EVENT_SHAKE256);
    shake256_inc_init(&ctx);
    if (copy_secret) {
        shake256_inc_absorb(&ctx, secret, copy_secret);
    }
    if (copy_ct) {
        shake256_inc_absorb(&ctx, ct, copy_ct);
    }
    shake256_inc_absorb(&ctx, &domain_tag, 1);
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, WSIDH_SS_BYTES, &ctx);
    shake256_inc_ctx_release(&ctx);
    WSIDH_PROFILE_END(kdf_scope);
}

static void hash_key_dual(uint8_t *good_out,
                          uint8_t *bad_out,
                          const uint8_t *ct,
                          const uint8_t *good_secret,
                          size_t good_len,
                          const uint8_t *bad_secret,
                          size_t bad_len) {
#ifdef WSIDH_USE_AVX2
    if (good_secret && bad_secret &&
        good_len == bad_len &&
        good_len + WSIDH_CT_BYTES + 1 <= WSIDH_MAX_HASH_INPUT) {
        WSIDH_PROFILE_BEGIN(hash_dual_scope, WSIDH_PROFILE_EVENT_SHAKE256X4);
        size_t lane_len = good_len + WSIDH_CT_BYTES + 1;
        uint8_t lane_inputs[4][WSIDH_MAX_HASH_INPUT];
        memset(lane_inputs, 0, sizeof(lane_inputs));

        size_t offset = 0;
        memcpy(lane_inputs[0], good_secret, good_len);
        offset = good_len;
        memcpy(lane_inputs[0] + offset, ct, WSIDH_CT_BYTES);
        offset += WSIDH_CT_BYTES;
        lane_inputs[0][offset] = WSIDH_KDF_DOMAIN_GOOD;

        offset = 0;
        memcpy(lane_inputs[1], bad_secret, bad_len);
        offset = bad_len;
        memcpy(lane_inputs[1] + offset, ct, WSIDH_CT_BYTES);
        offset += WSIDH_CT_BYTES;
        lane_inputs[1][offset] = WSIDH_KDF_DOMAIN_BAD;

        memcpy(lane_inputs[2], lane_inputs[1], lane_len);
        lane_inputs[2][lane_len - 1] = WSIDH_KDF_DOMAIN_DUMMY0;
        memcpy(lane_inputs[3], lane_inputs[1], lane_len);
        lane_inputs[3][lane_len - 1] = WSIDH_KDF_DOMAIN_DUMMY1;

        uint8_t dummy2[WSIDH_SS_BYTES];
        uint8_t dummy3[WSIDH_SS_BYTES];

        PQCLEAN_MLKEM512_AVX2_shake256x4(good_out,
                                         bad_out,
                                         dummy2,
                                         dummy3,
                                         WSIDH_SS_BYTES,
                                         lane_inputs[0],
                                         lane_inputs[1],
                                         lane_inputs[2],
                                         lane_inputs[3],
                                         lane_len);
        WSIDH_PROFILE_END(hash_dual_scope);
        return;
    }
#endif
    hash_key_from_parts(good_out, ct, good_secret, good_len, WSIDH_KDF_DOMAIN_GOOD);
    hash_key_from_parts(bad_out, ct, bad_secret, bad_len, WSIDH_KDF_DOMAIN_BAD);
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
    alignas(32) int16_t r_ntt[WSIDH_N];
    poly tmp_ar, tmp_br;
    poly m_poly;

    expand_deterministic(&r, &e1, &e2, coins);
    poly_ntt_from_poly(r_ntt, &r);

    const int16_t *a_ntt_ptr = NULL;
    const int16_t *b_ntt_ptr = NULL;
    int need_a_fallback = 0;
    int need_b_fallback = 0;

    if (a_ntt_opt) {
        a_ntt_ptr = a_ntt_opt->coeffs;
    } else if (a) {
        need_a_fallback = 1;
    }

    if (b_ntt_opt) {
        b_ntt_ptr = b_ntt_opt->coeffs;
    } else if (b) {
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
        alignas(32) int16_t u_ntt[WSIDH_N];
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
    poly b, s, e;
    poly b_ntt_poly;
    poly s_ntt_poly;
    alignas(32) int16_t a_ntt_arr[WSIDH_N];
    alignas(32) int16_t s_ntt_arr[WSIDH_N];
    alignas(32) int16_t e_ntt_arr[WSIDH_N];
    alignas(32) int16_t b_ntt_arr[WSIDH_N];
    alignas(32) int16_t b_time_arr[WSIDH_N];
    rand_func_t rng = wsidh_get_rng();
    uint8_t noise_seed[WSIDH_SEED_BYTES];
    uint8_t a_seed[WSIDH_SEED_BYTES];

    rng(a_seed, sizeof(a_seed));
    wsidh_expand_a_from_seed(NULL, a_ntt_arr, a_seed, WSIDH_A_SEED_DOMAIN);

    rng(noise_seed, sizeof(noise_seed));
    const wsidh_params_t *params = wsidh_params_active();
    int bound_s = params ? params->bound_s : WSIDH_BOUND_S;
    int bound_e = params ? params->bound_e : WSIDH_BOUND_E;
    sample_pair_from_seed(&s, bound_s,
                          &e, bound_e,
                          noise_seed, 0x50);

    for (int i = 0; i < WSIDH_N; i++) {
        s_ntt_arr[i] = s.coeffs[i];
        e_ntt_arr[i] = e.coeffs[i];
    }
    int16_t *ntt_vecs[2] = {s_ntt_arr, e_ntt_arr};
    ntt_batch(ntt_vecs, 2);
    for (int i = 0; i < WSIDH_N; i++) {
        s_ntt_poly.coeffs[i] = s_ntt_arr[i];
    }

    basemul(b_ntt_arr, a_ntt_arr, s_ntt_arr);
    for (int i = 0; i < WSIDH_N; i++) {
        int32_t sum = (int32_t)b_ntt_arr[i] + e_ntt_arr[i];
        if (sum >= WSIDH_Q) sum -= WSIDH_Q;
        if (sum < 0) sum += WSIDH_Q;
        b_ntt_arr[i] = (int16_t)sum;
    }

    memcpy(b_time_arr, b_ntt_arr, sizeof(b_ntt_arr));
    inv_ntt(b_time_arr);
    for (int i = 0; i < WSIDH_N; i++) {
        b.coeffs[i] = b_time_arr[i];
    }
    poly_canon(&b);
    for (int i = 0; i < WSIDH_N; i++) {
        b_ntt_poly.coeffs[i] = b_ntt_arr[i];
    }
    poly_canon(&b_ntt_poly);

    store_pk(pk, a_seed, &b, &b_ntt_poly);
    poly_small_pack(sk + SK_S_OFFSET, &s);
    poly_canon(&s_ntt_poly);
    poly_compress12(sk + SK_SNTT_OFFSET, &s_ntt_poly);
    memcpy(sk + SK_PK_OFFSET, pk, WSIDH_PK_BYTES);

    wsidh_sha3_256(sk + SK_PK_HASH_OFFSET, pk, WSIDH_PK_BYTES);
    rng(sk + SK_Z_OFFSET, WSIDH_SK_Z_BYTES);

    WSIDH_PROFILE_END(keygen_scope);
    return 0;
}

int wsidh_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    WSIDH_PROFILE_BEGIN(enc_scope, WSIDH_PROFILE_EVENT_ENCAPS);
    poly b, u, v, a_ntt_poly, b_ntt_poly;
    uint8_t msg[WSIDH_SS_BYTES];
    uint8_t coins[WSIDH_SEED_BYTES];
    uint8_t pk_hash_local[WSIDH_PK_HASH_BYTES];
    rand_func_t rng = wsidh_get_rng();

    if (!pk || !ct || !ss) {
        return -1;
    }

    wsidh_hash_pk_cached(pk_hash_local, pk);
    load_pk(pk, NULL, &b, &a_ntt_poly, &b_ntt_poly, pk_hash_local);

    rng(msg, sizeof(msg));
    coins_from_msg(coins, msg, pk_hash_local);

    wsidh_encrypt(&u, &v, NULL, &b, &a_ntt_poly, &b_ntt_poly, msg, coins);
    store_ct(ct, &u, &v);

    hash_key_from_parts(ss, ct, msg, sizeof(msg), WSIDH_KDF_DOMAIN_GOOD);
    WSIDH_PROFILE_END(enc_scope);
    return 0;
}

int wsidh_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    WSIDH_PROFILE_BEGIN(dec_scope, WSIDH_PROFILE_EVENT_DECAPS);
    if (!ct || !ss || !sk) {
        return -1;
    }

    poly u, v, s, diff_poly, s_ntt_poly;
    alignas(32) int16_t s_ntt_arr[WSIDH_N];
    poly b_re, u_re, v_re, a_ntt_re, b_ntt_re;
    uint8_t msg_prime[WSIDH_SS_BYTES];
    uint8_t coins[WSIDH_SEED_BYTES];

    load_ct(ct, &u, &v);
    poly_small_unpack(&s, sk + SK_S_OFFSET);
    poly_decompress12(&s_ntt_poly, sk + SK_SNTT_OFFSET);
    for (int i = 0; i < WSIDH_N; i++) {
        s_ntt_arr[i] = s_ntt_poly.coeffs[i];
    }

    const uint8_t *pk_cached = sk + SK_PK_OFFSET;
    const uint8_t *pk_hash_cached = sk + SK_PK_HASH_OFFSET;
    load_pk(pk_cached, NULL, &b_re, &a_ntt_re, &b_ntt_re, pk_hash_cached);

    wsidh_decrypt(&diff_poly, &u, &v, &s, s_ntt_arr);
    poly_to_msg(msg_prime, &diff_poly);

    coins_from_msg(coins, msg_prime, pk_hash_cached);
    WSIDH_PROFILE_BEGIN(fo_reenc_scope, WSIDH_PROFILE_EVENT_FO_REENC);
    wsidh_encrypt(&u_re, &v_re, NULL, &b_re, &a_ntt_re, &b_ntt_re, msg_prime, coins);
    WSIDH_PROFILE_END(fo_reenc_scope);

    uint32_t diff = poly_diff(&u, &u_re);
    diff |= poly_diff(&v, &v_re);
    uint8_t fail = (uint8_t)(diff != 0);

    uint8_t good_key[WSIDH_SS_BYTES];
    uint8_t bad_key[WSIDH_SS_BYTES];

    hash_key_dual(good_key, bad_key, ct,
                  msg_prime, sizeof(msg_prime),
                  sk + SK_Z_OFFSET, WSIDH_SK_Z_BYTES);

    ct_select(ss, good_key, bad_key, WSIDH_SS_BYTES, fail);

    WSIDH_PROFILE_END(dec_scope);
    return 0;
}
