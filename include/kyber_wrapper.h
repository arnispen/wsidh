#ifndef KYBER_WRAPPER_H
#define KYBER_WRAPPER_H

#include <stdint.h>

int kyber512_keypair(uint8_t *pk, uint8_t *sk);
int kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* KYBER_WRAPPER_H */
