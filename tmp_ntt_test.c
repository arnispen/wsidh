#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "third_party/PQClean/crypto_kem/kyber512/avx2/poly.h"
#include "third_party/PQClean/crypto_kem/kyber512/avx2/polyvec.h"
#include "third_party/PQClean/crypto_kem/kyber512/avx2/reduce.h"
#include "third_party/PQClean/crypto_kem/kyber512/avx2/ntt.h"

int main() {
    poly p;
    for (int i = 0; i < 256; i++) {
        p.coeffs[i] = rand() % 3329;
    }
    poly q = p;
    PQCLEAN_MLKEM512_AVX2_poly_ntt(&p);
    PQCLEAN_MLKEM512_AVX2_poly_invntt_tomont(&p);
    PQCLEAN_MLKEM512_AVX2_poly_reduce(&p);
    int ok = 1;
    for (int i = 0; i < 256; i++) {
        if (p.coeffs[i] != q.coeffs[i]) {
            ok = 0;
            printf("mismatch at %d %d %d\n", i, q.coeffs[i], p.coeffs[i]);
            break;
        }
    }
    printf("ok=%d\n", ok);
    return ok ? 0 : 1;
}
