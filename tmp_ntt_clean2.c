#include <stdio.h>
#include <stdlib.h>
#include "third_party/PQClean/crypto_kem/kyber512/clean/poly.h"

int main(){
  poly p;
  for(int i=0;i<256;i++) p.coeffs[i]=rand()%3329;
  poly q=p;
  PQCLEAN_MLKEM512_CLEAN_poly_ntt(&p);
  PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&p);
  for(int i=0;i<256;i++){
    int32_t val = p.coeffs[i];
    val = (val * 169) % 3329;
    if(val<0) val+=3329;
    p.coeffs[i]=val;
  }
  PQCLEAN_MLKEM512_CLEAN_poly_reduce(&p);
  int ok=1;
  for(int i=0;i<256;i++){
    if(p.coeffs[i]!=q.coeffs[i]){printf("mismatch %d %d %d\n",i,q.coeffs[i],p.coeffs[i]);ok=0;break;}
  }
  printf("ok=%d\n",ok);
  return ok?0:1;
}
