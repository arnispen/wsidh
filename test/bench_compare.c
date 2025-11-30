#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__x86_64__) && !defined(__i386__)
#error "Cycle counter benchmark requires x86 or x86_64."
#endif

#include <cpuid.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include "wsidh_kem.h"
#include "params.h"
#include "kyber_wrapper.h"
#include "../third_party/PQClean/crypto_kem/kyber512/clean/api.h"

#define BENCH_TRIALS 10000
#define CACHE_FLUSH_SIZE (64 * 1024)

typedef int (*kem_keypair_fn)(uint8_t *, uint8_t *);
typedef int (*kem_enc_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*kem_dec_fn)(uint8_t *, const uint8_t *, const uint8_t *);

typedef struct {
    const char *name;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    size_t ss_len;
    kem_keypair_fn keypair;
    kem_enc_fn encaps;
    kem_dec_fn decaps;
} kem_impl_t;

static inline uint64_t rdtsc_begin(void) {
    uint32_t hi, lo;
    __asm__ volatile("cpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx");
    __asm__ volatile("rdtsc\n\t" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void) {
    uint32_t hi, lo;
    __asm__ volatile("rdtscp\n\t" : "=a"(lo), "=d"(hi) :: "%rcx");
    __asm__ volatile("cpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)hi << 32) | lo;
}

static void flush_cache(void) {
    static uint8_t buf[CACHE_FLUSH_SIZE];
    for (size_t i = 0; i < sizeof(buf); i += 64) {
        buf[i]++;
    }
}

static int cmp_u64(const void *a, const void *b) {
    const uint64_t va = *(const uint64_t *)a;
    const uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

typedef struct {
    double avg;
    uint64_t min;
    uint64_t max;
    uint64_t median;
} bench_stats_t;

static void compute_stats(uint64_t *samples, size_t count, bench_stats_t *out) {
    uint64_t *tmp = malloc(count * sizeof(uint64_t));
    if (!tmp) {
        fprintf(stderr, "allocation failure\n");
        exit(1);
    }
    memcpy(tmp, samples, count * sizeof(uint64_t));
    qsort(tmp, count, sizeof(uint64_t), cmp_u64);
    out->median = tmp[count / 2];
    long double total = 0.0L;
    out->min = UINT64_MAX;
    out->max = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t val = samples[i];
        if (val < out->min) out->min = val;
        if (val > out->max) out->max = val;
        total += (long double)val;
    }
    out->avg = (double)(total / (long double)count);
    free(tmp);
}

static void cpu_brand_string(char *out, size_t len) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int regs[4];
    unsigned int max_ext = __get_cpuid_max(0x80000004u, NULL);
    if (max_ext >= 0x80000004u) {
        for (unsigned i = 0; i < 3; i++) {
            __get_cpuid(0x80000002u + i, &regs[0], &regs[1], &regs[2], &regs[3]);
            memcpy(out + (i * 16), regs, 16);
        }
        out[47] = '\0';
        return;
    }
#endif
#if defined(__APPLE__)
    size_t sysctl_len = len;
    if (sysctlbyname("machdep.cpu.brand_string", out, &sysctl_len, NULL, 0) == 0) {
        out[sysctl_len ? sysctl_len - 1 : 0] = '\0';
        return;
    }
#endif
    snprintf(out, len, "unknown");
}

static void print_environment(void) {
    char brand[64] = {0};
    cpu_brand_string(brand, sizeof(brand));
#if defined(__x86_64__) || defined(__i386__)
    __builtin_cpu_init();
    bool host_avx2 = __builtin_cpu_supports("avx2");
#else
    bool host_avx2 = false;
#endif
    printf("=== Benchmark Environment ===\n");
    printf("CPU: %s\n", brand);
#ifdef WSIDH_USE_AVX2
    printf("Build AVX2 optimizations: enabled\n");
#else
    printf("Build AVX2 optimizations: disabled\n");
#endif
    printf("Runtime AVX2 support: %s\n", host_avx2 ? "yes" : "no");
    printf("Compiler: %s\n", __VERSION__);
#ifdef BUILD_FLAGS
    printf("Build flags: %s\n", BUILD_FLAGS);
#endif
    printf("\n");
}

static void benchmark_kem(const kem_impl_t *impl) {
    uint64_t *samples = malloc(sizeof(uint64_t) * BENCH_TRIALS);
    if (!samples) {
        fprintf(stderr, "allocation failure\n");
        exit(1);
    }
    uint8_t *pk = malloc(impl->pk_len);
    uint8_t *sk = malloc(impl->sk_len);
    uint8_t *ct = malloc(impl->ct_len);
    uint8_t *ss = malloc(impl->ss_len);
    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "allocation failure\n");
        exit(1);
    }

    for (size_t i = 0; i < BENCH_TRIALS; i++) {
        flush_cache();
        uint64_t begin = rdtsc_begin();
        if (impl->keypair(pk, sk) != 0) {
            fprintf(stderr, "%s keypair failed\n", impl->name);
            exit(1);
        }
        uint64_t end = rdtsc_end();
        samples[i] = end - begin;
    }
    bench_stats_t stats;
    compute_stats(samples, BENCH_TRIALS, &stats);
    printf("%-8s keygen:  avg=%12.2f  min=%10" PRIu64 "  max=%10" PRIu64
           "  median=%10" PRIu64 "  trials=%d\n",
           impl->name, stats.avg, stats.min, stats.max, stats.median, BENCH_TRIALS);

    if (impl->keypair(pk, sk) != 0) {
        fprintf(stderr, "%s keypair failed (encaps)\n", impl->name);
        exit(1);
    }
    for (size_t i = 0; i < BENCH_TRIALS; i++) {
        flush_cache();
        uint64_t begin = rdtsc_begin();
        if (impl->encaps(ct, ss, pk) != 0) {
            fprintf(stderr, "%s encaps failed\n", impl->name);
            exit(1);
        }
        uint64_t end = rdtsc_end();
        samples[i] = end - begin;
    }
    compute_stats(samples, BENCH_TRIALS, &stats);
    printf("%-8s encaps: avg=%12.2f  min=%10" PRIu64 "  max=%10" PRIu64
           "  median=%10" PRIu64 "  trials=%d\n",
           impl->name, stats.avg, stats.min, stats.max, stats.median, BENCH_TRIALS);

    uint8_t *cts = malloc(impl->ct_len * BENCH_TRIALS);
    uint8_t *ss_enc = malloc(impl->ss_len * BENCH_TRIALS);
    uint8_t *ss_tmp = malloc(impl->ss_len);
    if (!cts || !ss_enc || !ss_tmp) {
        fprintf(stderr, "allocation failure\n");
        exit(1);
    }
    if (impl->keypair(pk, sk) != 0) {
        fprintf(stderr, "%s keypair failed (decaps)\n", impl->name);
        exit(1);
    }
    for (size_t i = 0; i < BENCH_TRIALS; i++) {
        if (impl->encaps(cts + i * impl->ct_len,
                         ss_enc + i * impl->ss_len,
                         pk) != 0) {
            fprintf(stderr, "%s encaps (precompute) failed\n", impl->name);
            exit(1);
        }
    }
    for (size_t i = 0; i < BENCH_TRIALS; i++) {
        flush_cache();
        uint64_t begin = rdtsc_begin();
        if (impl->decaps(ss_tmp,
                         cts + i * impl->ct_len,
                         sk) != 0) {
            fprintf(stderr, "%s decaps failed\n", impl->name);
            exit(1);
        }
        uint64_t end = rdtsc_end();
        samples[i] = end - begin;
        if (memcmp(ss_tmp, ss_enc + i * impl->ss_len, impl->ss_len) != 0) {
            fprintf(stderr, "%s decapsulation mismatch at trial %zu\n", impl->name, i);
            exit(1);
        }
    }
    compute_stats(samples, BENCH_TRIALS, &stats);
    printf("%-8s decaps: avg=%12.2f  min=%10" PRIu64 "  max=%10" PRIu64
           "  median=%10" PRIu64 "  trials=%d\n\n",
           impl->name, stats.avg, stats.min, stats.max, stats.median, BENCH_TRIALS);

    free(samples);
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(cts);
    free(ss_enc);
    free(ss_tmp);
}

int main(void) {
    print_environment();
#if !defined(BENCH_KYBER_ONLY)
    const kem_impl_t wsidh = {
        .name = "WSIDH512",
        .pk_len = WSIDH_PK_BYTES,
        .sk_len = WSIDH_SK_BYTES,
        .ct_len = WSIDH_CT_BYTES,
        .ss_len = WSIDH_SS_BYTES,
        .keypair = wsidh_crypto_kem_keypair,
        .encaps = wsidh_crypto_kem_enc,
        .decaps = wsidh_crypto_kem_dec,
    };
#endif
#if !defined(BENCH_WSIDH_ONLY)
    const kem_impl_t kyber = {
        .name = "Kyber512",
        .pk_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .sk_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ct_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        .ss_len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES,
        .keypair = kyber512_keypair,
        .encaps = kyber512_enc,
        .decaps = kyber512_dec,
    };
#endif
#if defined(BENCH_KYBER_ONLY)
    benchmark_kem(&kyber);
#elif defined(BENCH_WSIDH_ONLY)
    benchmark_kem(&wsidh);
#else
    benchmark_kem(&wsidh);
    benchmark_kem(&kyber);
#endif
    return 0;
}
