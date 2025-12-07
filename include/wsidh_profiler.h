#ifndef WSIDH_PROFILER_H
#define WSIDH_PROFILER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    WSIDH_PROFILE_EVENT_KEYGEN = 0,
    WSIDH_PROFILE_EVENT_ENCAPS,
    WSIDH_PROFILE_EVENT_DECAPS,
    WSIDH_PROFILE_EVENT_POLY_SAMPLE_UNIFORM,
    WSIDH_PROFILE_EVENT_POLY_MUL_NTT,
    WSIDH_PROFILE_EVENT_SAMPLE_SMALL,
    WSIDH_PROFILE_EVENT_SAMPLE_DET,
    WSIDH_PROFILE_EVENT_SHA3_256,
    WSIDH_PROFILE_EVENT_SHAKE128,
    WSIDH_PROFILE_EVENT_SHAKE256,
    WSIDH_PROFILE_EVENT_SHAKE128X4,
    WSIDH_PROFILE_EVENT_SHAKE256X4,
    WSIDH_PROFILE_EVENT_NTT_FWD,
    WSIDH_PROFILE_EVENT_NTT_INV,
    WSIDH_PROFILE_EVENT_POINTWISE_MUL,
    WSIDH_PROFILE_EVENT_COMPRESS,
    WSIDH_PROFILE_EVENT_DECOMPRESS,
    WSIDH_PROFILE_EVENT_PACK,
    WSIDH_PROFILE_EVENT_UNPACK,
    WSIDH_PROFILE_EVENT_SERIALIZE,
    WSIDH_PROFILE_EVENT_DESERIALIZE,
    WSIDH_PROFILE_EVENT_FO_REENC,
    WSIDH_PROFILE_EVENT_CT_COMPARE,
    WSIDH_PROFILE_EVENT_COUNT
} wsidh_profile_event;

#ifdef WSIDH_ENABLE_PROFILE

void wsidh_profile_reset(void);
void wsidh_profile_add(wsidh_profile_event event, uint64_t cycles);
void wsidh_profile_dump(const char *phase, size_t divisor);
uint64_t wsidh_profile_rdtsc(void);

#define WSIDH_PROFILE_BEGIN(tag, event) \
    uint64_t __wsidh_profile_start_##tag = wsidh_profile_rdtsc(); \
    const wsidh_profile_event __wsidh_profile_event_##tag = (event)

#define WSIDH_PROFILE_END(tag) \
    wsidh_profile_add(__wsidh_profile_event_##tag, \
                      wsidh_profile_rdtsc() - __wsidh_profile_start_##tag)

#else

static inline void wsidh_profile_reset(void) {}
static inline void wsidh_profile_add(wsidh_profile_event event, uint64_t cycles) {
    (void)event;
    (void)cycles;
}
static inline void wsidh_profile_dump(const char *phase, size_t divisor) {
    (void)phase;
    (void)divisor;
}
static inline uint64_t wsidh_profile_rdtsc(void) { return 0; }

#define WSIDH_PROFILE_BEGIN(tag, event) (void)0
#define WSIDH_PROFILE_END(tag) (void)0

#endif

#endif
