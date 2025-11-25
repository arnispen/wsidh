// sha3.h — real SHA3-256 interface
#ifndef WSIDH_SHA3_H
#define WSIDH_SHA3_H

#include <stdint.h>
#include <stddef.h>

void wsidh_sha3_256(uint8_t *out, const uint8_t *in, size_t inlen);
void wsidh_shake128(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen);

#endif
