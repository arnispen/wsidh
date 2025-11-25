#include <stdint.h>
#include <string.h>
#include "ntt.h"
#include "params.h"
#ifdef WSIDH_USE_AVX2
#include "wsidh_avx2.h"
#endif

// We assume:
//   WSIDH_Q = 12289
//   WSIDH_N = 256
//
// We use a primitive N-th root of unity modulo q:
//   omega = 8340  (order 256 mod 12289)
//   omega_inv = 1696  (multiplicative inverse of omega mod q)
//   n_inv = 12241  (inverse of 256 mod q)

static inline int16_t barrett_reduce(int32_t a) {
    const int32_t v = ((1u << 26) + (WSIDH_Q / 2)) / WSIDH_Q;
    int32_t t = ((int64_t)v * a) >> 26;
    t *= WSIDH_Q;
    a -= t;
    if (a < 0) a += WSIDH_Q;
    if (a >= WSIDH_Q) a -= WSIDH_Q;
    return (int16_t)a;
}

static inline int16_t mod_add(int16_t a, int16_t b) {
    int32_t t = (int32_t)a + b;
    if (t >= WSIDH_Q) t -= WSIDH_Q;
    return (int16_t)t;
}

static inline int16_t mod_sub(int16_t a, int16_t b) {
    int32_t t = (int32_t)a - b;
    if (t < 0) t += WSIDH_Q;
    return (int16_t)t;
}

static int16_t mod_pow(int16_t base, int32_t exp) {
    int32_t res = 1;
    int32_t b = base;
    while (exp > 0) {
        if (exp & 1) {
            res = (res * b) % WSIDH_Q;
        }
        b = (b * b) % WSIDH_Q;
        exp >>= 1;
    }
    return (int16_t)res;
}

static int twiddle_initialized = 0;
static int16_t wlen_fwd[16];
static int16_t wlen_inv[16];
static int stage_count = 0;

static void ntt_init(void) {
    if (twiddle_initialized) return;
    const int16_t omega = 8340;
    const int16_t omega_inv = 1696;

    int stage = 0;
    for (int len = 2; len <= WSIDH_N; len <<= 1) {
        wlen_fwd[stage] = mod_pow(omega, WSIDH_N / len);
        wlen_inv[stage] = mod_pow(omega_inv, WSIDH_N / len);
        stage++;
    }
    stage_count = stage;
    twiddle_initialized = 1;
}

// ---- bit-reversal permutation ----

static void bitreverse(int16_t a[WSIDH_N]) {
    int n = WSIDH_N;
    int j = 0;
    for (int i = 1; i < n; i++) {
        int bit = n >> 1;
        while (j & bit) {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if (i < j) {
            int16_t tmp = a[i];
            a[i] = a[j];
            a[j] = tmp;
        }
    }
}

// ---- forward NTT ----

static void ntt_apply(int16_t *vecs[], size_t count) {
    if (!vecs || count == 0) {
        return;
    }
    ntt_init();
    for (size_t idx = 0; idx < count; idx++) {
        bitreverse(vecs[idx]);
    }

    int len = 2;
    for (int stage = 0; stage < stage_count; stage++) {
        int half = len >> 1;
        int16_t wlen = wlen_fwd[stage];
        for (int i = 0; i < WSIDH_N; i += len) {
            int16_t w = 1;
            for (int j = 0; j < half; j++) {
                int idx1 = i + j;
                int idx2 = idx1 + half;
                for (size_t vec = 0; vec < count; vec++) {
                    int16_t *a = vecs[vec];
                    int16_t u = a[idx1];
                    int16_t v = barrett_reduce((int32_t)a[idx2] * w);
                    a[idx1] = mod_add(u, v);
                    a[idx2] = mod_sub(u, v);
                }
                w = barrett_reduce((int32_t)w * wlen);
            }
        }
        len <<= 1;
    }
}

#ifdef WSIDH_USE_AVX2
void ntt(int16_t a[WSIDH_N]) {
    wsidh_avx2_ntt(a);
}

void inv_ntt(int16_t a[WSIDH_N]) {
    wsidh_avx2_invntt(a);
}

void ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) return;
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            wsidh_avx2_ntt(vecs[i]);
        }
    }
}

void inv_ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) return;
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            wsidh_avx2_invntt(vecs[i]);
        }
    }
}

void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]) {
    wsidh_avx2_basemul(r, a, b);
}
#else

void ntt(int16_t a[WSIDH_N]) {
    int16_t *vecs[1] = {a};
    ntt_apply(vecs, 1);
}

void ntt_batch(int16_t *vecs[], size_t count) {
    ntt_apply(vecs, count);
}

// ---- inverse NTT ----

static void inv_ntt_apply(int16_t *vecs[], size_t count) {
    if (!vecs || count == 0) {
        return;
    }
    ntt_init();
    for (size_t idx = 0; idx < count; idx++) {
        bitreverse(vecs[idx]);
    }

    const int16_t n_inv = 12241;  // inverse of N mod q
    int len = 2;

    for (int stage = 0; stage < stage_count; stage++) {
        int half = len >> 1;
        int16_t wlen = wlen_inv[stage];
        for (int i = 0; i < WSIDH_N; i += len) {
            int16_t w = 1;
            for (int j = 0; j < half; j++) {
                int idx1 = i + j;
                int idx2 = idx1 + half;
                for (size_t vec = 0; vec < count; vec++) {
                    int16_t *a = vecs[vec];
                    int16_t u = a[idx1];
                    int16_t v = barrett_reduce((int32_t)a[idx2] * w);
                    a[idx1] = mod_add(u, v);
                    a[idx2] = mod_sub(u, v);
                }
                w = barrett_reduce((int32_t)w * wlen);
            }
        }
        len <<= 1;
    }

    for (size_t vec = 0; vec < count; vec++) {
        int16_t *a = vecs[vec];
        for (int i = 0; i < WSIDH_N; i++) {
            a[i] = barrett_reduce((int32_t)a[i] * n_inv);
        }
    }
}

void inv_ntt(int16_t a[WSIDH_N]) {
    int16_t *vecs[1] = {a};
    inv_ntt_apply(vecs, 1);
}

void inv_ntt_batch(int16_t *vecs[], size_t count) {
    inv_ntt_apply(vecs, count);
}

// ---- pointwise multiplication in NTT domain ----

void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]) {
    for (int i = 0; i < WSIDH_N; i++) {
        r[i] = barrett_reduce((int32_t)a[i] * b[i]);
    }
}
#endif
