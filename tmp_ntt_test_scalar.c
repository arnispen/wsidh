#include <stdio.h>
#include <stdlib.h>
#include "third_party/PQClean/crypto_kem/kyber512/clean/poly.h"

int main(){
  poly p;
  for(int i=0;i<256;i++) p.coeffs[i]=rand()%3329;
  poly q=p;
  PQCLEAN_MLKEM512_CLEAN_poly_ntt(&p);
  PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&p);
  PQCLEAN_MLKEM512_CLEAN_poly_reduce(&p);
  for(int i=0;i<256;i++) if(p.coeffs[i]!=q.coeffs[i]){printf("mismatch %d %d %d\n",i,q.coeffs[i],p.coeffs[i]);return 1;}
  printf("ok\n");
  return 0;
}
