#include "wsidh_config.h"
#include "kyber_wrapper.h"

#ifdef WSIDH_USE_AVX2
#include "../third_party/PQClean/crypto_kem/kyber512/avx2/api.h"
#else
#include "../third_party/PQClean/crypto_kem/kyber512/clean/api.h"
#endif

int kyber512_keypair(uint8_t *pk, uint8_t *sk) {
#ifdef WSIDH_USE_AVX2
    return PQCLEAN_MLKEM512_AVX2_crypto_kem_keypair(pk, sk);
#else
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
#endif
}

int kyber512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
#ifdef WSIDH_USE_AVX2
    return PQCLEAN_MLKEM512_AVX2_crypto_kem_enc(ct, ss, pk);
#else
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
#endif
}

int kyber512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
#ifdef WSIDH_USE_AVX2
    return PQCLEAN_MLKEM512_AVX2_crypto_kem_dec(ss, ct, sk);
#else
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
#endif
}
