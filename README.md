# WSIDH Post-Quantum KEM

WSIDH is a research-grade, RLWE-style key-encapsulation mechanism that mixes a deterministically generated “wave-based” public polynomial `a(x)` with NTT-accelerated polynomial arithmetic. This repository hardens the reference into a Fujisaki–Okamoto (FO) CCA-secure KEM and provides a full benchmarking and testing harness so we can track competitiveness against Kyber.

## Specification Snapshot

| Variant   | Degree `N` | Modulus `q` | `BOUND_S` | `BOUND_E` | pk bytes | sk bytes | ct bytes | ss bytes |
|-----------|------------|-------------|-----------|-----------|---------:|---------:|---------:|---------:|
| WSIDH512  | 256        | 3329        | 3         | 2         |      768 |     1856 |      768 |       32 |
| WSIDH768* | 256        | 3329        | 4         | 3         |      768 |     1856 |      768 |       32 |
| WSIDH1024*| 256        | 3329        | 5         | 4         |      768 |     1856 |      768 |       32 |

\*WSIDH768/WSIDH1024 widen the noise bounds while sharing the same `N=256` NTT today; treat them as experimental presets until the dimension is lifted.

## Parameters & Tunability

Variant definitions now live in `include/wsidh_variants.h` and feed the macros exported from `include/params.h`. Pick a preset by passing `WSIDH_VARIANT` into `make`, e.g. `make WSIDH_VARIANT=wsidh768 wsidh_bench`. The build stamps `WSIDH_PARAM_SET`, which drives the degree, modulus, bounds, and byte sizes throughout the tree. Every time you touch a preset, rebuild and rerun the 10k-trial Monte Carlo in `wsidh_test` to verify the decoding failure rate stays negligible.

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
- `sk = s || s_ntt || pk || H(pk) || z` (1472 bytes). Both `s` and its NTT share the raw 16-bit layout to keep FO re-encryption fast. `z` is a 32-byte fallback secret.
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

`make` variables control the build matrix:

- `WSIDH_VARIANT` — selects WSIDH512/768/1024 at compile time (default `wsidh512`).
- `WITH_AVX2=1` — enables the AVX2 NTT path (WSIDH uses PQClean’s kernels; Kyber, when linked, does as well).
- `WITH_KYBER=1` — links PQClean’s Kyber implementations so the benchmark can time them directly.

```
make wsidh_test
./wsidh_test
```

`wsidh_test` prints parameter info, a single known-good round trip, the result of 10,000 encaps/decaps trials (to expose any decoding failures), and three malformed ciphertext experiments (corrupting `u`, `v`, then both). Expect matching keys only for the valid ciphertext case. Public keys now include three serialized polynomials `(a_time || b || a_ntt)` so downstream code can multiply by the precomputed wave spectrum without re-running an NTT.

## Benchmarking

```
make wsidh_bench
./wsidh_bench             # defaults to 1000 trials for the active variant
./wsidh_bench 200         # override the trial count
./wsidh_bench --summary   # single-line output (used by the variant sweep)
./wsidh_bench --variants 200        # measure current variant + WSIDH512/768/1024 table
./wsidh_bench --variants-only 200   # only print the WSIDH table
```

The benchmark reports average cycles, wall-clock nanoseconds, and derived operations-per-second for key generation, encapsulation, and decapsulation. `rdtsc` is used when running on x86; other architectures still get wall-clock statistics. Each phase now also prints a per-function breakdown (keygen, `poly_from_wave`, NTTs, samplers, SHA3 calls) using the built-in profiler, followed by micro-benchmarks for `poly_mul_ntt`, both samplers, and SHA3-256. Pass a smaller trial count when iterating locally, then bump back to ≥1000 for publication-quality numbers. When Kyber isn’t linked, the harness appends the official Kyber512/768/1024 cycle counts you supplied so we can eyeball the gap even before integrating live code.

To compare all WSIDH variants side-by-side (and keep Kyber’s published numbers in view), either pass `--variants` or call the helper script directly:

```
./wsidh_bench --variants 200
./scripts/bench_wsidh_variants.sh 200
```

The script rebuilds each preset (`wsidh512`, `wsidh768`, `wsidh1024`) with the active `WITH_AVX2`/`WITH_KYBER` settings, runs `./wsidh_bench --summary`, prints a consolidated table, and finally restores the original variant so your working tree stays consistent. Use this whenever you retune noise bounds or land a new optimization so the entire family stays in sync.

## Kyber Comparison

Set `WITH_KYBER=1` (and optionally `WITH_AVX2=1`) when building `wsidh_bench` to pull PQClean’s Kyber implementations into the binary. The benchmark then times Kyber512/768/1024 in the same harness and prints their sizes and cycle counts next to WSIDH. When Kyber isn’t linked, the harness prints the official submitter numbers instead so you can still see the targets.
## Notes & TODOs

- `poly.c` retains straightforward arithmetic; once functionality stabilizes we can swap in Montgomery reductions or precomputed tables.
- The wave-based `a(x)` is deterministic for transparency; document any alternative generation in commit messages and rerun malformed-ciphertext tests.
- Future work: replace raw SHA3-256 KDF with a proper XOF or HKDF, add unit tests for serialization helpers, and integrate CI to run the Monte Carlo + benchmark suite automatically.
