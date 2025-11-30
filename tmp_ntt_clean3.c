#include <stdio.h>
#include <stdlib.h>
#include "third_party/PQClean/crypto_kem/kyber512/clean/poly.h"

static int16_t canon(int16_t x){
  int32_t v=x;
  v%=3329;
  if(v<0) v+=3329;
  return (int16_t)v;
}

int main(){
  poly p;
  for(int i=0;i<256;i++) p.coeffs[i]=rand()%3329;
  poly q=p;
  PQCLEAN_MLKEM512_CLEAN_poly_ntt(&p);
  PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&p);
  for(int i=0;i<256;i++){
    int32_t v = p.coeffs[i];
    v = (v * 169) % 3329;
    if(v<0) v+=3329;
    p.coeffs[i]=v;
  }
  for(int i=0;i<256;i++) p.coeffs[i]=canon(p.coeffs[i]);
  for(int i=0;i<256;i++) q.coeffs[i]=canon(q.coeffs[i]);
  int ok=1;
  for(int i=0;i<256;i++) if(p.coeffs[i]!=q.coeffs[i]){printf("mismatch %d %d %d\n",i,q.coeffs[i],p.coeffs[i]);ok=0;break;}
  printf("ok=%d\n",ok);
  return ok?0:1;
}
