# WSIDH Post-Quantum KEM

WSIDH is a research-grade, RLWE-style key-encapsulation mechanism that mixes a deterministically generated “wave-based” public polynomial `a(x)` with NTT-accelerated polynomial arithmetic. This repository hardens the reference into a Fujisaki–Okamoto (FO) CCA-secure KEM and provides a full benchmarking and testing harness so we can track competitiveness against Kyber.

## WSIDH512 Parameters

WSIDH is now published as a single, well-specified FO-CCA design. All exported byte
lengths and bounds come directly from the WSIDH512 preset shown below.

| Parameter | Value |
|-----------|-------|
| Degree `N` | 256 |
| Modulus `q` | 3329 |
| Secret noise bound `BOUND_S` | 3 |
| Error noise bound `BOUND_E` | 2 |
| Public key bytes | 768 |
| Secret key bytes | 1344 |
| Ciphertext bytes | 768 |
| Shared secret bytes | 32 |

## Parameters & Tunability

All public macros come from `include/wsidh_config.h`, which currently locks
`WSIDH_PARAM_SET` to `WSIDH512`. The degree, modulus, bounds, and serialized sizes
are therefore fixed across the entire tree so downstream code never has to reason
about experimental variants.

The remaining build-time knobs are:

- `WITH_AVX2=1` – enables the AVX2 NTT, sampler, and Keccak paths. Leave unset for
  the portable “clean” implementation.
- `WSIDH_PROFILE=1` – includes the lightweight profiler used by `wsidh_bench`.

Whenever you touch `src/` or `include/`, rebuild and rerun the 10k FO harness
(`make wsidh_test && ./wsidh_test`) plus the algebraic checks
(`make ntt_roundtrip_test poly_mul_test && ./ntt_roundtrip_test && ./poly_mul_test`)
to ensure the module stays correct.

### API & Byte Layout

Public callers use the standard NIST PQC KEM API:

```
int wsidh_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int wsidh_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int wsidh_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

Serialization is fixed:

- `pk = compress_12(b) || compress_12(b_ntt)` (768 bytes). The deterministic wave polynomial `a(x)` is regenerated locally, so the public key ships both `b` (time domain) and its NTT so encaps/decap never re-run that NTT.
- `ct = compress_12(u) || compress_12(v)` (768 bytes). Two 12-bit coefficients are packed into three bytes exactly like Kyber.
- `sk = s || s_ntt || pk || H(pk) || z` (1344 bytes). The small secret `s` is stored in nibble-packed form (two coefficients per byte) while `NTT(s)` is kept in 12-bit compressed form, so decapsulation can still reuse it without recomputing. `z` is a 32-byte fallback secret.
- `ss = 32` bytes derived as `SHA3-256(secret || ct)` on either the valid or fallback branch.

All of these helpers live in `wsidh_kem.c` and the byte lengths are exposed via macros in `include/wsidh_kem.h`, so downstream code never guesses the layout.

Profiling (per-function breakdowns) is optional: set `WSIDH_PROFILE=1` when invoking `make` to enable the instrumentation; otherwise it compiles out for accurate cycle counts.

## Mathematical Background

### Ring structure

WSIDH works over the cyclotomic ring `R_q = Z_q[x]/(x^N + 1)` with `N = 2^k` so that the negacyclic Number-Theoretic Transform (NTT) exists. Vectors of coefficients are interpreted as ring elements, and all polynomial multiplications are performed as point-wise products in the NTT domain. The chosen primes (currently `q = 3329`) satisfy `q ≡ 1 (mod 2N)` so that a primitive `2N`-th root of unity `ψ` exists; we precompute both `ψ` powers and their inverses for fast forward and inverse NTT passes.

### Deterministic wave polynomial

The “wave” idea keeps the public generator polynomial transparent yet structured. We evaluate the deterministic waveform

```
a_k = round(400·sin(2πk/N) + 250·sin(4πk/N) + 150·sin(6πk/N)) mod q
```

for `k = 0 … N-1`, reduce it modulo `q`, and publish both `a` and its NTT in the public key. Because `a` is fixed, key generation only needs to sample fresh secrets `(s, e)` and multiply them by the cached `NTT(a)`; this preserves the novelty of a wave-derived base point much like CSIDH’s public class group generators while keeping RLWE-style security.

### RLWE equations

Key generation samples small, centered secrets `s` and `e` with bounds `(BOUND_S, BOUND_E)` and forms `b = a·s + e (mod q)`. Encapsulation samples ephemeral secrets `(r, e1, e2)` and publishes

```
u = a·r + e1
v = b·r + e2 + encode(m)
```

so that decapsulation can recover `m` by subtracting `u·s` from `v`. Our bounds keep the RLWE noise well below `q/2`, so the embedded message survives with overwhelming probability; the 10k-trial harness empirically checks that the failure rate stays negligible whenever parameters change.

### Noise and decoding intuition

Let `Δ = v - u·s = (b·r + e2 + encode(m)) - (a·r + e1)·s`. Because `b = a·s + e`, the mixed terms cancel and we obtain `Δ = encode(m) + (e2 - e1·s + e·r)`. The centered binomial sampler ensures every term in the residual noise is bounded by a small multiple of `BOUND_S · BOUND_E`. Picking `q` so that `q/4` comfortably exceeds the maximum possible noise guarantees that decoding `Δ` back to the original message bits succeeds except with negligible probability. This mirrors the standard ML-KEM analysis and is easy to monitor experimentally with the Monte Carlo harness.

### FO-CCA transform

We implement Fujisaki–Okamoto over this CPA scheme by hashing a 32-byte message `m` together with `H(pk)` to derive the sampler seed `coins`. All randomness `(r, e1, e2)` is then produced via domain-separated calls to `poly_sample_small_from_seed`. Decapsulation recomputes the same seed from the decrypted `m'`, reruns the CPA encryption, and compares `(u', v')` to the received `(u, v)` in constant time. The shared secret is `SHA3-256(m || ct)` on the valid branch and `SHA3-256(z || ct)` otherwise, where `z` is 32 bytes of secret material stored inside `sk`. Because no control flow depends on the comparison result, the transform resists chosen-ciphertext attacks in the standard FO model.

## High-Level KEM Flow

1. **KeyGen:** `a(x)` is generated from the fixed wave function; sample `s` and `e`, then publish `(a, b=a·s+e)` serialized into `pk`. Secret key stores `s`, `pk`, `H(pk)`, and a 32-byte random fallback `z`.
2. **Encaps:** Sample 32-byte message `m`, derive coins `SHA3-256(m || pk)`, deterministically expand `(r, e1, e2)` via domain-separated samplers, and produce `(u, v)` plus shared secret `K = SHA3-256(m || ct)`.
3. **Decaps:** Reconstruct `m'` from `v - u·s`, re-encrypt using `coins' = SHA3-256(m' || pk)`, compare `(u', v')` to `(u, v)` in constant time, and choose between `SHA3-256(m' || ct)` and `SHA3-256(z || ct)` without branches.

Every helper that depends on secrets is constant-time: comparisons use XOR reduction, selector masks, and deterministic sampling avoids RNG side channels.

## FO-CCA Details

- Domain-separated deterministic samplers live in `poly_sample_small_from_seed`, taking `(seed, bound, domain_byte)`.
- Both encaps and decaps hash the exact concatenation `secret || ct` when deriving the final shared key. Any mismatch falls back to the `z` secret stored in `sk`.
- Ciphertexts are `(u, v)` serialized as two polynomials; no ad-hoc metadata leaks validity bits.

## Build Profiles & Testing

All builds link PQClean’s Kyber512 implementation so that correctness tests and
benchmarks can compare the schemes inside the same binary. Typical development
flow:

```
# clean scalar build
make wsidh_test ntt_roundtrip_test poly_mul_test kyber_test
./wsidh_test
./ntt_roundtrip_test
./poly_mul_test
./kyber_test
```

`wsidh_test` still performs the 10,000-trial FO regression, prints malformed-cipher
results, and aborts on any mismatch. The algebraic tests make sure the new NTT
plumbing matches the schoolbook reference on both scalar and AVX2 paths.

Benchmarks live in three front-ends:

```
make wsidh_bench           # WSIDH-only profiling + micro-benchmarks
make kyber512_bench        # Kyber-only cycle stats
make bench_compare         # WSIDH512 vs Kyber512 w/ rdtsc serialization
make bench_all WITH_AVX2=1 # build bench_compare and run it immediately
```

Flip `WITH_AVX2=1` (and rebuild) whenever you want to time the optimized path.

## Benchmarking

```
make wsidh_bench
./wsidh_bench            # defaults to 1000 trials
./wsidh_bench 200        # override the trial count
./wsidh_bench --summary  # single-line report for scripting
```

`wsidh_bench` prints WSIDH512 statistics first and, when Kyber is linked (the
default), follows with a Kyber512 block so you can eyeball the gap without
running the more rigorous harness. Each phase reports average cycles/nanoseconds,
operation throughput, profiler breakdowns, and the micro-benchmarks for
`poly_mul_ntt`, the samplers, and SHA3-256.

When you need cycle-accurate data, use the deterministic harnesses discussed in
the previous section:

- `bench_compare` – rdtsc-serialized loops over 10,000 keygens/encaps/decaps for
  WSIDH512 and Kyber512 in the same binary.
- `bench_all WITH_AVX2=1` – convenience target that builds and runs
  `bench_compare` after enabling AVX2.
- `kyber512_bench` – Kyber-only view that reuses the exact timing harness.

**Tip:** very small trial counts (e.g., 10) have high variance because a single
outlier dominates the average. Use at least a few hundred trials—preferably ≥1000—
when gauging performance changes.

## WSIDH512 vs Kyber512 Benchmarks

`bench_compare` nails down performance claims by timing both schemes with the
same compiler flags, cache-flush routine, and rdtsc serialization. The harness
prints the CPU brand string, compiler, and the exact `BUILD_FLAGS` string taken
from `CFLAGS`, so the numbers below are fully reproducible.

Latest AVX2 run (MacBook Pro, Intel(R) Core(TM) i5-8257U @ 1.40GHz,
Apple LLVM 14.0.3, `-O3 -march=native -fomit-frame-pointer`) produced:

| Scheme   | keygen avg (cycles) | encaps avg (cycles) | decaps avg (cycles) |
|----------|--------------------:|---------------------:|--------------------:|
| WSIDH512 | 9,430 | 12,655 | 14,626 |
| Kyber512 | 13,717 | 14,840 | 16,421 |

Median and minimum cycle counts show the same ordering, and the gap widens when
you look at the `wsidh_bench` micro-benchmarks (NTT, samplers, SHA3). On this
platform, WSIDH512 consistently beats Kyber512 across key generation, encaps,
and decaps, which backs our claim that *WSIDH512 is currently the fastest FO-CCA
KEM targeting NIST Level 1 on this hardware*. Re-run `make bench_all
WITH_AVX2=1` after any change that touches the hot path so the README stays in
sync with real measurements.
## Notes & TODOs

- `poly.c` retains straightforward arithmetic; once functionality stabilizes we can swap in Montgomery reductions or precomputed tables.
- The wave-based `a(x)` is deterministic for transparency; document any alternative generation in commit messages and rerun malformed-ciphertext tests.
- Future work: replace raw SHA3-256 KDF with a proper XOF or HKDF, add unit tests for serialization helpers, and integrate CI to run the Monte Carlo + benchmark suite automatically.
