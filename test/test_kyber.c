#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kyber_wrapper.h"
#include "../third_party/PQClean/crypto_kem/kyber512/clean/api.h"

#define KYBER_TRIALS 10000

int main(void) {
    uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    uint8_t ss_dec[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    for (size_t trial = 0; trial < KYBER_TRIALS; trial++) {
        if (kyber512_keypair(pk, sk) != 0) {
            fprintf(stderr, "Kyber512 keypair failed at trial %zu\n", trial);
            return 1;
        }
        if (kyber512_enc(ct, ss_enc, pk) != 0) {
            fprintf(stderr, "Kyber512 encaps failed at trial %zu\n", trial);
            return 1;
        }
        if (kyber512_dec(ss_dec, ct, sk) != 0) {
            fprintf(stderr, "Kyber512 decaps failed at trial %zu\n", trial);
            return 1;
        }
        if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0) {
            fprintf(stderr, "Kyber512 shared secret mismatch at trial %zu\n", trial);
            return 1;
        }
    }
    printf("Kyber512 %d-trial encaps/decaps test: PASS\n", KYBER_TRIALS);
    return 0;
}
