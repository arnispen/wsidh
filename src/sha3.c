#include "sha3.h"
#include "wsidh_profiler.h"
#include "fips202.h"

void wsidh_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen) {
    WSIDH_PROFILE_BEGIN(sha3_scope, WSIDH_PROFILE_EVENT_SHA3);
    sha3_256(out, in, inlen);
    WSIDH_PROFILE_END(sha3_scope);
}

void wsidh_shake128(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen) {
    WSIDH_PROFILE_BEGIN(shake_scope, WSIDH_PROFILE_EVENT_SHA3);
    shake128(out, outlen, in, inlen);
    WSIDH_PROFILE_END(shake_scope);
}
