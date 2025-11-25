// include/wsidh_avx2_paths.h
#ifndef WSIDH_AVX2_PATHS_H
#define WSIDH_AVX2_PATHS_H

#ifdef WSIDH_USE_AVX2

#ifndef WSIDH_AVX2_BASE
#define WSIDH_AVX2_BASE ../PQClean-master/crypto_kem/ml-kem-512/avx2
#endif

#define WSIDH_AVX2_STRINGIZE_IMPL(x) #x
#define WSIDH_AVX2_STRINGIZE(x) WSIDH_AVX2_STRINGIZE_IMPL(x)
#define WSIDH_AVX2_HEADER(name) WSIDH_AVX2_STRINGIZE(WSIDH_AVX2_BASE/name)

#endif /* WSIDH_USE_AVX2 */

#endif /* WSIDH_AVX2_PATHS_H */
