#include <stdint.h>
#include <string.h>
#include "ntt.h"
#include "params.h"
#include "wsidh_profiler.h"
#ifdef WSIDH_USE_AVX2
#include "wsidh_avx2.h"
#endif

static inline int16_t barrett_reduce(const wsidh_params_t *params, int32_t a) {
    const int32_t q = params->Q;
    int32_t t = ((int64_t)params->barrett_v * a) >> 26;
    t *= q;
    a -= t;
    if (a < 0) a += q;
    if (a >= q) a -= q;
    return (int16_t)a;
}

static inline int16_t mod_add(const wsidh_params_t *params, int16_t a, int16_t b) {
    int32_t t = (int32_t)a + b;
    if (t >= params->Q) t -= params->Q;
    return (int16_t)t;
}

static inline int16_t mod_sub(const wsidh_params_t *params, int16_t a, int16_t b) {
    int32_t t = (int32_t)a - b;
    if (t < 0) t += params->Q;
    return (int16_t)t;
}

// ---- bit-reversal permutation ----

static void bitreverse(const wsidh_params_t *params, int16_t a[WSIDH_N]) {
    int n = params->N;
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
    const wsidh_params_t *params = wsidh_params_active();
    if (!params || !vecs || count == 0) {
        return;
    }
    for (size_t idx = 0; idx < count; idx++) {
        bitreverse(params, vecs[idx]);
    }

    int len = 2;
    int stages = (int)params->stage_count;
    for (int stage = 0; stage < stages; stage++) {
        int half = len >> 1;
        int16_t wlen = params->zetas[stage];
        for (int i = 0; i < WSIDH_N; i += len) {
            int16_t w = 1;
            for (int j = 0; j < half; j++) {
                int idx1 = i + j;
                int idx2 = idx1 + half;
                for (size_t vec = 0; vec < count; vec++) {
                    int16_t *a = vecs[vec];
                    int16_t u = a[idx1];
                    int16_t v = barrett_reduce(params, (int32_t)a[idx2] * w);
                    a[idx1] = mod_add(params, u, v);
                    a[idx2] = mod_sub(params, u, v);
                }
                w = barrett_reduce(params, (int32_t)w * wlen);
            }
        }
        len <<= 1;
    }
}

#ifdef WSIDH_USE_AVX2
void ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(ntt_single_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
    wsidh_avx2_ntt(a);
    WSIDH_PROFILE_END(ntt_single_scope);
}

void inv_ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(invntt_single_scope, WSIDH_PROFILE_EVENT_NTT_INV);
    wsidh_avx2_invntt(a);
    WSIDH_PROFILE_END(invntt_single_scope);
}

void ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) return;
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            WSIDH_PROFILE_BEGIN(ntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
            wsidh_avx2_ntt(vecs[i]);
            WSIDH_PROFILE_END(ntt_batch_scope);
        }
    }
}

void inv_ntt_batch(int16_t *vecs[], size_t count) {
    if (!vecs) return;
    for (size_t i = 0; i < count; i++) {
        if (vecs[i]) {
            WSIDH_PROFILE_BEGIN(invntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_INV);
            wsidh_avx2_invntt(vecs[i]);
            WSIDH_PROFILE_END(invntt_batch_scope);
        }
    }
}

void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(basemul_scope, WSIDH_PROFILE_EVENT_POINTWISE_MUL);
    wsidh_avx2_basemul(r, a, b);
    WSIDH_PROFILE_END(basemul_scope);
}
#else

void ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(ntt_single_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
    int16_t *vecs[1] = {a};
    ntt_apply(vecs, 1);
    WSIDH_PROFILE_END(ntt_single_scope);
}

void ntt_batch(int16_t *vecs[], size_t count) {
    WSIDH_PROFILE_BEGIN(ntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_FWD);
    ntt_apply(vecs, count);
    WSIDH_PROFILE_END(ntt_batch_scope);
}

// ---- inverse NTT ----

static void inv_ntt_apply(int16_t *vecs[], size_t count) {
    const wsidh_params_t *params = wsidh_params_active();
    if (!params || !vecs || count == 0) {
        return;
    }
    for (size_t idx = 0; idx < count; idx++) {
        bitreverse(params, vecs[idx]);
    }

    int len = 2;

    int stages = (int)params->stage_count;
    for (int stage = 0; stage < stages; stage++) {
        int half = len >> 1;
        int16_t wlen = params->zetas_inv[stage];
        for (int i = 0; i < WSIDH_N; i += len) {
            int16_t w = 1;
            for (int j = 0; j < half; j++) {
                int idx1 = i + j;
                int idx2 = idx1 + half;
                for (size_t vec = 0; vec < count; vec++) {
                    int16_t *a = vecs[vec];
                    int16_t u = a[idx1];
                    int16_t v = barrett_reduce(params, (int32_t)a[idx2] * w);
                    a[idx1] = mod_add(params, u, v);
                    a[idx2] = mod_sub(params, u, v);
                }
                w = barrett_reduce(params, (int32_t)w * wlen);
            }
        }
        len <<= 1;
    }

    for (size_t vec = 0; vec < count; vec++) {
        int16_t *a = vecs[vec];
        for (int i = 0; i < WSIDH_N; i++) {
            a[i] = barrett_reduce(params, (int32_t)a[i] * params->n_inv);
        }
    }
}

void inv_ntt(int16_t a[WSIDH_N]) {
    WSIDH_PROFILE_BEGIN(invntt_single_scope, WSIDH_PROFILE_EVENT_NTT_INV);
    int16_t *vecs[1] = {a};
    inv_ntt_apply(vecs, 1);
    WSIDH_PROFILE_END(invntt_single_scope);
}

void inv_ntt_batch(int16_t *vecs[], size_t count) {
    WSIDH_PROFILE_BEGIN(invntt_batch_scope, WSIDH_PROFILE_EVENT_NTT_INV);
    inv_ntt_apply(vecs, count);
    WSIDH_PROFILE_END(invntt_batch_scope);
}

// ---- pointwise multiplication in NTT domain ----

void basemul(int16_t r[WSIDH_N],
             const int16_t a[WSIDH_N],
             const int16_t b[WSIDH_N]) {
    const wsidh_params_t *params = wsidh_params_active();
    if (!params) return;
    WSIDH_PROFILE_BEGIN(basemul_scope, WSIDH_PROFILE_EVENT_POINTWISE_MUL);
    for (int i = 0; i < WSIDH_N; i++) {
        r[i] = barrett_reduce(params, (int32_t)a[i] * b[i]);
    }
    WSIDH_PROFILE_END(basemul_scope);
}
#endif
