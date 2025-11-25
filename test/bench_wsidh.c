#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/wsidh_kem.h"
#include "../include/poly.h"
#include "../include/sha3.h"
#include "../include/wsidh_profiler.h"
#include "../include/wsidh_variants.h"

typedef struct {
    double avg_cycles;
    double avg_ns;
} bench_result_t;

typedef struct {
    const char *name;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    size_t ss_len;
    bench_result_t keygen;
    bench_result_t enc;
    bench_result_t dec;
} kem_stats_t;

static int summary_mode = 0;
static int variants_mode = 0;
static int variants_only_mode = 0;
static int variant_child_mode = 0;

static void print_combined_table(const char *title,
                                 const kem_stats_t *wsidh_rows,
                                 size_t wsidh_count,
                                 const kem_stats_t *other_rows,
                                 size_t other_count);

#ifdef WSIDH_ENABLE_KYBER
static const int wsidh_builds_with_kyber = 1;
#else
static const int wsidh_builds_with_kyber = 0;
#endif

#ifdef WSIDH_USE_AVX2
static const int wsidh_builds_with_avx2 = 1;
#else
static const int wsidh_builds_with_avx2 = 0;
#endif

static inline uint64_t rdtsc(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386)
    unsigned hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
#else
    return 0;
#endif
}

static inline uint64_t timespec_diff_ns(const struct timespec *end,
                                        const struct timespec *start) {
    uint64_t sec = (uint64_t)(end->tv_sec - start->tv_sec);
    int64_t nsec = end->tv_nsec - start->tv_nsec;
    if (nsec < 0) {
        sec--;
        nsec += 1000000000L;
    }
    return sec * 1000000000ULL + (uint64_t)nsec;
}

static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

static void bench_wsidh(size_t trials, bench_result_t *keygen,
                        bench_result_t *enc, bench_result_t *dec,
                        int quiet) {
    uint8_t pk[WSIDH_PK_BYTES];
    uint8_t sk[WSIDH_SK_BYTES];
    uint8_t ct[WSIDH_CT_BYTES];
    uint8_t ss[WSIDH_SS_BYTES];

    uint64_t cyc_acc = 0;
    uint64_t ns_acc = 0;
    struct timespec ts1, ts2;

    wsidh_profile_reset();
    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        wsidh_crypto_kem_keypair(pk, sk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    keygen->avg_cycles = (double)cyc_acc / (double)trials;
    keygen->avg_ns = (double)ns_acc / (double)trials;
    if (!quiet) {
        wsidh_profile_dump("WSIDH keygen breakdown", trials);
    }

    cyc_acc = 0;
    ns_acc = 0;

    wsidh_profile_reset();
    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        wsidh_crypto_kem_enc(ct, ss, pk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    enc->avg_cycles = (double)cyc_acc / (double)trials;
    enc->avg_ns = (double)ns_acc / (double)trials;
    if (!quiet) {
        wsidh_profile_dump("WSIDH encaps breakdown", trials);
    }

    cyc_acc = 0;
    ns_acc = 0;

    wsidh_profile_reset();
    for (size_t i = 0; i < trials; i++) {
        wsidh_crypto_kem_enc(ct, ss, pk);
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        wsidh_crypto_kem_dec(ss, ct, sk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    dec->avg_cycles = (double)cyc_acc / (double)trials;
    dec->avg_ns = (double)ns_acc / (double)trials;
    if (!quiet) {
        wsidh_profile_dump("WSIDH decaps breakdown", trials);
    }
}

static void microbench_poly_mul_ntt(size_t trials) {
    poly a, b, c;
    for (int i = 0; i < WSIDH_N; i++) {
        a.coeffs[i] = (int16_t)(rand() % WSIDH_Q);
        b.coeffs[i] = (int16_t)(rand() % WSIDH_Q);
    }

    uint64_t cyc_acc = 0;
    uint64_t ns_acc = 0;
    struct timespec ts1, ts2;

    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        poly_mul_ntt(&c, &a, &b);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }

    printf("[micro] poly_mul_ntt: cycles=%.2f ns=%.2f\n",
           (double)cyc_acc / trials, (double)ns_acc / trials);
}

static void rng_stub(uint8_t *out, size_t len) {
    random_bytes(out, len);
}

static void microbench_sampling(size_t trials) {
    poly p;
    uint64_t cyc_acc = 0, ns_acc = 0;
    struct timespec ts1, ts2;

    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        poly_sample_small(&p, rng_stub, WSIDH_BOUND_S);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    printf("[micro] poly_sample_small: cycles=%.2f ns=%.2f\n",
           (double)cyc_acc / trials, (double)ns_acc / trials);

    uint8_t seed[WSIDH_SEED_BYTES];
    random_bytes(seed, sizeof(seed));
    cyc_acc = ns_acc = 0;
    for (size_t i = 0; i < trials; i++) {
        seed[0] ^= (uint8_t)i;
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        poly_sample_small_from_seed(&p, seed, WSIDH_BOUND_S, 0xAA);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    printf("[micro] poly_sample_small_from_seed: cycles=%.2f ns=%.2f\n",
           (double)cyc_acc / trials, (double)ns_acc / trials);
}

static void microbench_sha3(size_t trials) {
    uint8_t input[64];
    uint8_t output[32];
    random_bytes(input, sizeof(input));

    uint64_t cyc_acc = 0;
    uint64_t ns_acc = 0;
    struct timespec ts1, ts2;

    for (size_t i = 0; i < trials; i++) {
        input[0] ^= (uint8_t)i;
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        wsidh_sha3_256(output, input, sizeof(input));
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }

    printf("[micro] sha3_256(64B): cycles=%.2f ns=%.2f\n",
           (double)cyc_acc / trials, (double)ns_acc / trials);
}

#ifndef WSIDH_ENABLE_KYBER
typedef struct {
    const char *name;
    double keygen_cycles;
    double encaps_cycles;
    double decaps_cycles;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    size_t ss_len;
} kyber_placeholder_t;

static const kyber_placeholder_t kyber_reference_numbers[] = {
    {"Kyber512 (ref)", 20000.0, 28000.0, 38000.0, 800, 1632, 768, 32},
    {"Kyber768 (ref)", 30000.0, 40000.0, 55000.0, 1184, 2400, 1088, 32},
    {"Kyber1024 (ref)", 40000.0, 55000.0, 70000.0, 1568, 3168, 1568, 32},
};
#endif

#ifdef WSIDH_ENABLE_KYBER
#if defined(WSIDH_USE_AVX2)
#include "../third_party/PQClean/crypto_kem/kyber512/avx2/api.h"
#include "../third_party/PQClean/crypto_kem/kyber768/avx2/api.h"
#include "../third_party/PQClean/crypto_kem/kyber1024/avx2/api.h"
#define KYBER512_NAME "Kyber512-AVX2"
#define KYBER768_NAME "Kyber768-AVX2"
#define KYBER1024_NAME "Kyber1024-AVX2"
#define KYBER512_PUBLICKEYBYTES PQCLEAN_MLKEM512_AVX2_CRYPTO_PUBLICKEYBYTES
#define KYBER512_SECRETKEYBYTES PQCLEAN_MLKEM512_AVX2_CRYPTO_SECRETKEYBYTES
#define KYBER512_CIPHERTEXTBYTES PQCLEAN_MLKEM512_AVX2_CRYPTO_CIPHERTEXTBYTES
#define KYBER512_BYTES PQCLEAN_MLKEM512_AVX2_CRYPTO_BYTES
#define KYBER768_PUBLICKEYBYTES PQCLEAN_MLKEM768_AVX2_CRYPTO_PUBLICKEYBYTES
#define KYBER768_SECRETKEYBYTES PQCLEAN_MLKEM768_AVX2_CRYPTO_SECRETKEYBYTES
#define KYBER768_CIPHERTEXTBYTES PQCLEAN_MLKEM768_AVX2_CRYPTO_CIPHERTEXTBYTES
#define KYBER768_BYTES PQCLEAN_MLKEM768_AVX2_CRYPTO_BYTES
#define KYBER1024_PUBLICKEYBYTES PQCLEAN_MLKEM1024_AVX2_CRYPTO_PUBLICKEYBYTES
#define KYBER1024_SECRETKEYBYTES PQCLEAN_MLKEM1024_AVX2_CRYPTO_SECRETKEYBYTES
#define KYBER1024_CIPHERTEXTBYTES PQCLEAN_MLKEM1024_AVX2_CRYPTO_CIPHERTEXTBYTES
#define KYBER1024_BYTES PQCLEAN_MLKEM1024_AVX2_CRYPTO_BYTES
#define kyber512_crypto_kem_keypair PQCLEAN_MLKEM512_AVX2_crypto_kem_keypair
#define kyber512_crypto_kem_enc PQCLEAN_MLKEM512_AVX2_crypto_kem_enc
#define kyber512_crypto_kem_dec PQCLEAN_MLKEM512_AVX2_crypto_kem_dec
#define kyber768_crypto_kem_keypair PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair
#define kyber768_crypto_kem_enc PQCLEAN_MLKEM768_AVX2_crypto_kem_enc
#define kyber768_crypto_kem_dec PQCLEAN_MLKEM768_AVX2_crypto_kem_dec
#define kyber1024_crypto_kem_keypair PQCLEAN_MLKEM1024_AVX2_crypto_kem_keypair
#define kyber1024_crypto_kem_enc PQCLEAN_MLKEM1024_AVX2_crypto_kem_enc
#define kyber1024_crypto_kem_dec PQCLEAN_MLKEM1024_AVX2_crypto_kem_dec
#else
#include "../third_party/PQClean/crypto_kem/kyber512/clean/api.h"
#include "../third_party/PQClean/crypto_kem/kyber768/clean/api.h"
#include "../third_party/PQClean/crypto_kem/kyber1024/clean/api.h"
#define KYBER512_NAME "Kyber512"
#define KYBER768_NAME "Kyber768"
#define KYBER1024_NAME "Kyber1024"
#define KYBER512_PUBLICKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define KYBER512_SECRETKEYBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define KYBER512_CIPHERTEXTBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define KYBER512_BYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#define KYBER768_PUBLICKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define KYBER768_SECRETKEYBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define KYBER768_CIPHERTEXTBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define KYBER768_BYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
#define KYBER1024_PUBLICKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#define KYBER1024_SECRETKEYBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
#define KYBER1024_CIPHERTEXTBYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define KYBER1024_BYTES PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
#define kyber512_crypto_kem_keypair PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
#define kyber512_crypto_kem_enc PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
#define kyber512_crypto_kem_dec PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
#define kyber768_crypto_kem_keypair PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair
#define kyber768_crypto_kem_enc PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc
#define kyber768_crypto_kem_dec PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec
#define kyber1024_crypto_kem_keypair PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair
#define kyber1024_crypto_kem_enc PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc
#define kyber1024_crypto_kem_dec PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec
#endif

typedef struct {
    const char *name;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    size_t ss_len;
    int (*keypair)(uint8_t *, uint8_t *);
    int (*enc)(uint8_t *, uint8_t *, const uint8_t *);
    int (*dec)(uint8_t *, const uint8_t *, const uint8_t *);
} kyber_target_t;

static void bench_kyber_target(const kyber_target_t *target,
                               size_t trials,
                               kem_stats_t *out_stats) {
    uint8_t *pk = malloc(target->pk_len);
    uint8_t *sk = malloc(target->sk_len);
    uint8_t *ct = malloc(target->ct_len);
    uint8_t *ss = malloc(target->ss_len);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "Allocation failure for %s\n", target->name);
        goto cleanup;
    }

    bench_result_t keygen = {0}, enc = {0}, dec = {0};
    uint64_t cyc_acc = 0, ns_acc = 0;
    struct timespec ts1, ts2;

    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        target->keypair(pk, sk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    keygen.avg_cycles = (double)cyc_acc / (double)trials;
    keygen.avg_ns = (double)ns_acc / (double)trials;

    cyc_acc = ns_acc = 0;
    target->keypair(pk, sk);

    for (size_t i = 0; i < trials; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        target->enc(ct, ss, pk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    enc.avg_cycles = (double)cyc_acc / (double)trials;
    enc.avg_ns = (double)ns_acc / (double)trials;

    cyc_acc = ns_acc = 0;

    for (size_t i = 0; i < trials; i++) {
        target->enc(ct, ss, pk);
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        uint64_t c1 = rdtsc();
        target->dec(ss, ct, sk);
        uint64_t c2 = rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &ts2);
        cyc_acc += (c2 - c1);
        ns_acc += timespec_diff_ns(&ts2, &ts1);
    }
    dec.avg_cycles = (double)cyc_acc / (double)trials;
    dec.avg_ns = (double)ns_acc / (double)trials;

    printf("--- %s ---\n", target->name);
    printf("pk=%zu sk=%zu ct=%zu ss=%zu\n",
           target->pk_len, target->sk_len, target->ct_len, target->ss_len);
    printf("keypair: cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           keygen.avg_cycles, keygen.avg_ns, 1e9 / keygen.avg_ns);
    printf("encaps : cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           enc.avg_cycles, enc.avg_ns, 1e9 / enc.avg_ns);
    printf("decaps : cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           dec.avg_cycles, dec.avg_ns, 1e9 / dec.avg_ns);

    if (out_stats) {
        out_stats->name = target->name;
        out_stats->pk_len = target->pk_len;
        out_stats->sk_len = target->sk_len;
        out_stats->ct_len = target->ct_len;
        out_stats->ss_len = target->ss_len;
        out_stats->keygen = keygen;
        out_stats->enc = enc;
        out_stats->dec = dec;
    }

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss);
}
#endif

static int run_variant_script(size_t trials) {
    char cmd[256];
    int len = snprintf(cmd, sizeof(cmd),
                       "./scripts/bench_wsidh_variants.sh %zu",
                       trials);
    if (len < 0 || (size_t)len >= sizeof(cmd)) {
        fprintf(stderr, "Error: trials argument too large\n");
        return 1;
    }
    printf("Launching WSIDH variant sweep via scripts/bench_wsidh_variants.sh (trials=%zu)\n",
           trials);
    const char *child_env = getenv("WSIDH_VARIANT_CHILD");
    setenv("WSIDH_VARIANT_CHILD", "1", 1);
    setenv("WSIDH_BENCH_WITH_KYBER",
           wsidh_builds_with_kyber ? "1" : "0", 1);
    setenv("WSIDH_BENCH_WITH_AVX2",
           wsidh_builds_with_avx2 ? "1" : "0", 1);
    int rc = system(cmd);
    if (child_env) {
        setenv("WSIDH_VARIANT_CHILD", child_env, 1);
    } else {
        unsetenv("WSIDH_VARIANT_CHILD");
    }
    unsetenv("WSIDH_BENCH_WITH_KYBER");
    unsetenv("WSIDH_BENCH_WITH_AVX2");
    if (rc != 0) {
        fprintf(stderr, "Variant sweep failed (exit=%d)\n", rc);
        return rc;
    }
    return 0;
}

int main(int argc, char **argv) {
    size_t trials = 1000;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--summary") == 0) {
            summary_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--variants") == 0) {
            variants_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--variants-only") == 0) {
            variants_mode = 1;
            variants_only_mode = 1;
            continue;
        }
        long custom = strtol(argv[i], NULL, 10);
        if (custom > 0) {
            trials = (size_t)custom;
        }
    }

    variant_child_mode = getenv("WSIDH_VARIANT_CHILD") != NULL;

    if (variants_only_mode) {
        return run_variant_script(trials);
    }

    bench_result_t keygen = {0}, enc = {0}, dec = {0};

    bench_wsidh(trials, &keygen, &enc, &dec, summary_mode);

    if (summary_mode) {
        printf("SUMMARY %s trials=%zu pk=%zu sk=%zu ct=%zu ss=%zu keygen=%.2f encaps=%.2f decaps=%.2f\n",
               wsidh_active_params.name,
               trials,
               (size_t)WSIDH_PK_BYTES,
               (size_t)WSIDH_SK_BYTES,
               (size_t)WSIDH_CT_BYTES,
               (size_t)WSIDH_SS_BYTES,
               keygen.avg_cycles,
               enc.avg_cycles,
               dec.avg_cycles);
        return 0;
    }

    printf("=== WSIDH Benchmark (N=%d, q=%d, trials=%zu) ===\n",
           WSIDH_N, WSIDH_Q, trials);
    printf("pk=%zu sk=%zu ct=%zu ss=%zu\n",
           (size_t)WSIDH_PK_BYTES, (size_t)WSIDH_SK_BYTES,
           (size_t)WSIDH_CT_BYTES, (size_t)WSIDH_SS_BYTES);
    printf("keypair: cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           keygen.avg_cycles, keygen.avg_ns, 1e9 / keygen.avg_ns);
    printf("encaps : cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           enc.avg_cycles, enc.avg_ns, 1e9 / enc.avg_ns);
    printf("decaps : cycles=%.2f  ns=%.2f  ops/sec=%.2f\n",
           dec.avg_cycles, dec.avg_ns, 1e9 / dec.avg_ns);

    size_t micro_trials = trials < 100 ? trials : 100;
    microbench_poly_mul_ntt(micro_trials);
    microbench_sampling(micro_trials);
    microbench_sha3(micro_trials);

    kem_stats_t wsidh_rows[1] = {{
        .name = wsidh_active_params.name,
        .pk_len = WSIDH_PK_BYTES,
        .sk_len = WSIDH_SK_BYTES,
        .ct_len = WSIDH_CT_BYTES,
        .ss_len = WSIDH_SS_BYTES,
        .keygen = keygen,
        .enc = enc,
        .dec = dec,
    }};
#ifdef WSIDH_ENABLE_KYBER
    const kyber_target_t kyber_targets[] = {
        {KYBER512_NAME,
         KYBER512_PUBLICKEYBYTES,
         KYBER512_SECRETKEYBYTES,
         KYBER512_CIPHERTEXTBYTES,
         KYBER512_BYTES,
         kyber512_crypto_kem_keypair,
         kyber512_crypto_kem_enc,
         kyber512_crypto_kem_dec},
        {KYBER768_NAME,
         KYBER768_PUBLICKEYBYTES,
         KYBER768_SECRETKEYBYTES,
         KYBER768_CIPHERTEXTBYTES,
         KYBER768_BYTES,
         kyber768_crypto_kem_keypair,
         kyber768_crypto_kem_enc,
         kyber768_crypto_kem_dec},
        {KYBER1024_NAME,
         KYBER1024_PUBLICKEYBYTES,
         KYBER1024_SECRETKEYBYTES,
         KYBER1024_CIPHERTEXTBYTES,
         KYBER1024_BYTES,
         kyber1024_crypto_kem_keypair,
         kyber1024_crypto_kem_enc,
         kyber1024_crypto_kem_dec},
    };

    kem_stats_t kyber_stats[sizeof(kyber_targets) / sizeof(kyber_targets[0])];
    for (size_t i = 0; i < sizeof(kyber_targets) / sizeof(kyber_targets[0]); i++) {
        bench_kyber_target(&kyber_targets[i], trials, &kyber_stats[i]);
    }
    print_combined_table("KEM Cycle/Size Table",
                         wsidh_rows, 1,
                         kyber_stats,
                         sizeof(kyber_stats) / sizeof(kyber_stats[0]));
#else
    kem_stats_t placeholder_stats[sizeof(kyber_reference_numbers) / sizeof(kyber_reference_numbers[0])];
    for (size_t i = 0; i < sizeof(kyber_reference_numbers) / sizeof(kyber_reference_numbers[0]); i++) {
        placeholder_stats[i].name = kyber_reference_numbers[i].name;
        placeholder_stats[i].pk_len = kyber_reference_numbers[i].pk_len;
        placeholder_stats[i].sk_len = kyber_reference_numbers[i].sk_len;
        placeholder_stats[i].ct_len = kyber_reference_numbers[i].ct_len;
        placeholder_stats[i].ss_len = kyber_reference_numbers[i].ss_len;
        placeholder_stats[i].keygen.avg_cycles = kyber_reference_numbers[i].keygen_cycles;
        placeholder_stats[i].enc.avg_cycles = kyber_reference_numbers[i].encaps_cycles;
        placeholder_stats[i].dec.avg_cycles = kyber_reference_numbers[i].decaps_cycles;
        placeholder_stats[i].keygen.avg_ns = 0.0;
        placeholder_stats[i].enc.avg_ns = 0.0;
        placeholder_stats[i].dec.avg_ns = 0.0;
    }
    print_combined_table("KEM Cycle/Size Table (scalar)",
                         wsidh_rows, 1,
                         placeholder_stats,
                         sizeof(placeholder_stats) / sizeof(placeholder_stats[0]));
#endif

    if (!summary_mode && variants_mode && !variant_child_mode) {
        int vrc = run_variant_script(trials);
        if (vrc != 0) {
            return vrc;
        }
    }

    return 0;
}
static void print_combined_table(const char *title,
                                 const kem_stats_t *wsidh_rows,
                                 size_t wsidh_count,
                                 const kem_stats_t *other_rows,
                                 size_t other_count) {
    if (!title) {
        title = "KEM Cycle/Size Table";
    }
    printf("=== %s ===\n", title);
    printf("%-18s %8s %8s %8s %8s %14s %14s %14s\n",
           "Scheme", "pk(B)", "sk(B)", "ct(B)", "ss(B)",
           "keygen cyc", "encaps cyc", "decaps cyc");
    if (wsidh_rows && wsidh_count > 0) {
        for (size_t i = 0; i < wsidh_count; i++) {
            printf("%-18s %8zu %8zu %8zu %8zu %14.2f %14.2f %14.2f\n",
                   wsidh_rows[i].name,
                   wsidh_rows[i].pk_len, wsidh_rows[i].sk_len,
                   wsidh_rows[i].ct_len, wsidh_rows[i].ss_len,
                   wsidh_rows[i].keygen.avg_cycles,
                   wsidh_rows[i].enc.avg_cycles,
                   wsidh_rows[i].dec.avg_cycles);
        }
    }
    if (other_rows && other_count > 0) {
        for (size_t i = 0; i < other_count; i++) {
            printf("%-18s %8zu %8zu %8zu %8zu %14.2f %14.2f %14.2f\n",
                   other_rows[i].name,
                   other_rows[i].pk_len, other_rows[i].sk_len,
                   other_rows[i].ct_len, other_rows[i].ss_len,
                   other_rows[i].keygen.avg_cycles,
                   other_rows[i].enc.avg_cycles,
                   other_rows[i].dec.avg_cycles);
        }
    }
    printf("\n");
}
