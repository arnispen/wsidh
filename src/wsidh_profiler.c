#include "wsidh_profiler.h"

#ifdef WSIDH_ENABLE_PROFILE

#include <stdio.h>

typedef struct {
    uint64_t cycles;
    uint64_t calls;
} wsidh_profile_counter;

static wsidh_profile_counter g_profile_counters[WSIDH_PROFILE_EVENT_COUNT];

static const char *event_names[WSIDH_PROFILE_EVENT_COUNT] = {
    [WSIDH_PROFILE_EVENT_KEYGEN] = "keygen",
    [WSIDH_PROFILE_EVENT_ENCAPS] = "encaps",
    [WSIDH_PROFILE_EVENT_DECAPS] = "decaps",
    [WSIDH_PROFILE_EVENT_POLY_SAMPLE_UNIFORM] = "poly_sample_uniform",
    [WSIDH_PROFILE_EVENT_POLY_MUL_NTT] = "poly_mul_ntt",
    [WSIDH_PROFILE_EVENT_SAMPLE_SMALL] = "poly_sample_small",
    [WSIDH_PROFILE_EVENT_SAMPLE_DET] = "poly_sample_deterministic",
    [WSIDH_PROFILE_EVENT_SHA3_256] = "sha3_256",
    [WSIDH_PROFILE_EVENT_SHAKE128] = "shake128",
    [WSIDH_PROFILE_EVENT_SHAKE256] = "shake256",
    [WSIDH_PROFILE_EVENT_SHAKE128X4] = "shake128x4",
    [WSIDH_PROFILE_EVENT_SHAKE256X4] = "shake256x4",
    [WSIDH_PROFILE_EVENT_NTT_FWD] = "ntt_forward",
    [WSIDH_PROFILE_EVENT_NTT_INV] = "ntt_inverse",
    [WSIDH_PROFILE_EVENT_POINTWISE_MUL] = "pointwise_mul",
    [WSIDH_PROFILE_EVENT_COMPRESS] = "compress",
    [WSIDH_PROFILE_EVENT_DECOMPRESS] = "decompress",
    [WSIDH_PROFILE_EVENT_PACK] = "pack",
    [WSIDH_PROFILE_EVENT_UNPACK] = "unpack",
    [WSIDH_PROFILE_EVENT_SERIALIZE] = "serialize",
    [WSIDH_PROFILE_EVENT_DESERIALIZE] = "deserialize",
    [WSIDH_PROFILE_EVENT_FO_REENC] = "fo_reencrypt",
    [WSIDH_PROFILE_EVENT_CT_COMPARE] = "ct_compare",
};

uint64_t wsidh_profile_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64)
    unsigned hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
#else
    return 0;
#endif
}

void wsidh_profile_reset(void) {
    for (int i = 0; i < WSIDH_PROFILE_EVENT_COUNT; i++) {
        g_profile_counters[i].cycles = 0;
        g_profile_counters[i].calls = 0;
    }
}

void wsidh_profile_add(wsidh_profile_event event, uint64_t cycles) {
    if (event >= WSIDH_PROFILE_EVENT_COUNT) return;
    g_profile_counters[event].cycles += cycles;
    g_profile_counters[event].calls += 1;
}

void wsidh_profile_dump(const char *phase, size_t divisor) {
    if (!phase) phase = "WSIDH profile";
    printf("=== %s ===\n", phase);
    for (int i = 0; i < WSIDH_PROFILE_EVENT_COUNT; i++) {
        const wsidh_profile_counter *c = &g_profile_counters[i];
        if (c->calls == 0 || !event_names[i]) continue;
        double per_call = (double)c->cycles / (double)c->calls;
        double per_op = divisor ? ((double)c->cycles / (double)divisor) : c->cycles;
        printf("  %-24s total_cycles=%12llu calls=%8llu avg/call=%10.2f avg/op=%10.2f\n",
               event_names[i],
               (unsigned long long)c->cycles,
               (unsigned long long)c->calls,
               per_call,
               per_op);
    }
    printf("\n");
}

#endif
