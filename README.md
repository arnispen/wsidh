# WSIDH Post-Quantum KEM

WSIDH is a research-grade, RLWE-style key-encapsulation mechanism that mixes a deterministically generated “wave-based” public polynomial `a(x)` with NTT-accelerated polynomial arithmetic. This repository hardens the reference into a Fujisaki–Okamoto (FO) CCA-secure KEM and provides a full benchmarking and testing harness so we can track competitiveness against Kyber.

## Parameters & Tunability

Variant definitions now live in `include/wsidh_variants.h` and feed the classic macros exported from `include/params.h`. Three presets match Kyber’s 512/768/1024 structure:

- `WSIDH512` (default) keeps `N=256`, `q=3329`, `BOUND_S=3`, `BOUND_E=2`.
- `WSIDH768` / `WSIDH1024` currently reuse the same NTT (still `N=256`, `q=3329`) but widen the noise bounds (documented as experimental until the NTT generalizes past 256 points). Each entry is tracked in `wsidh_known_variants`.
- `WSIDH_SEED_BYTES = 32` keeps deterministic samplers SHA3-friendly for every preset.

Select a preset by passing `WSIDH_VARIANT` into `make`, e.g. `make WSIDH_VARIANT=wsidh768 wsidh_bench`. Under the hood the build stamps `WSIDH_PARAM_SET` so all serialization constants stay self-consistent. Every time you tweak a parameter set, rebuild and rerun the 10k trial in `wsidh_test` to confirm the empirical failure rate is still negligible.

### Serialization & Bandwidth

A fresh keypair now serializes as:

- `pk = compress_12(b)` → `384` bytes
- `sk = s || s_ntt || pk || H(pk) || z` → `1472` bytes
- `ct = compress_12(u) || compress_12(v)` → `768` bytes
- `ss = 32` bytes

We reuse Kyber’s trick of packing two coefficients (each < 4096) into three bytes, so every public polynomial costs 12 bits per coefficient. Because the wave polynomial `a(x)` is deterministic, the public key only needs `b(x)`; the receiver regenerates `a(x)` (and its cached NTT) locally. The new layout therefore beats Kyber512 on every bandwidth metric while keeping the FO transform untouched.

## Mathematical Background

### Ring structure

WSIDH works over the cyclotomic ring `R_q = Z_q[x]/(x^N + 1)` with `N = 2^k` so that the negacyclic Number-Theoretic Transform (NTT) exists. Vectors of coefficients are interpreted as ring elements, and all polynomial multiplications are performed as point-wise products in the NTT domain. The chosen primes (currently `q = 12289`) satisfy `q ≡ 1 (mod 2N)` so that a primitive `2N`-th root of unity `ψ` exists; we precompute both `ψ` powers and their inverses for fast forward and inverse NTT passes.

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

## Building & Testing

```
make wsidh_test
./wsidh_test
```

`wsidh_test` prints parameter info, a single known-good round trip, the result of 10,000 encaps/decaps trials (to expose any decoding failures), and three malformed ciphertext experiments (corrupting `u`, `v`, then both). Expect matching keys only for the valid ciphertext case. Public keys now include three serialized polynomials `(a_time || b || a_ntt)` so downstream code can multiply by the precomputed wave spectrum without re-running an NTT.

## Benchmarking

```
make wsidh_bench
./wsidh_bench        # defaults to 1000 trials
./wsidh_bench 50     # override trial count when iterating quickly
./wsidh_bench --summary   # single-line machine-readable output (used by scripts)
```

The benchmark reports average cycles, wall-clock nanoseconds, and derived operations-per-second for key generation, encapsulation, and decapsulation. `rdtsc` is used when running on x86; other architectures still get wall-clock statistics. Each phase now also prints a per-function breakdown (keygen, `poly_from_wave`, NTTs, samplers, SHA3 calls) using the built-in profiler, followed by micro-benchmarks for `poly_mul_ntt`, both samplers, and SHA3-256. Pass a smaller trial count when iterating locally, then bump back to ≥1000 for publication-quality numbers. When Kyber isn’t linked, the harness appends the official Kyber512/768/1024 cycle counts you supplied so we can eyeball the gap even before integrating live code.

To compare all WSIDH variants side-by-side (and keep Kyber’s published numbers in view), use the helper script:

```
./scripts/bench_wsidh_variants.sh 200   # trial count optional (defaults to 1000)
./wsidh_bench --variants 200            # same sweep via the new built-in driver
```

The script rebuilds each preset (`wsidh512`, `wsidh768`, `wsidh1024`) with the correct `WSIDH_VARIANT`, runs `./wsidh_bench --summary`, and prints a single table juxtaposed with Kyber’s cycle counts. Use this whenever you retune noise bounds or swap in a new low-level optimization so the entire family stays in sync.

## Kyber Comparison (optional)

Drop a Kyber implementation under `third_party/kyber/` (PQClean layouts work well), export symbols such as `kyber512_crypto_kem_keypair`, and run:

```
# WSIDH-only build (no Kyber linked yet)
make wsidh_vs_kyber
./wsidh_vs_kyber

# Once you've dropped a Kyber library somewhere (e.g. third_party/kyber/libkyber_ref.a)
make wsidh_vs_kyber WITH_KYBER=1 KYBER_LIBS="third_party/kyber/libkyber_ref.a"
./wsidh_vs_kyber
```

When `WITH_KYBER=1` and `KYBER_LIBS` points to the appropriate static library (or list of objects), the build defines `WSIDH_ENABLE_KYBER` so Kyber512/768/1024 share the identical timing harness. Otherwise the binary still builds but prints a reminder that Kyber comparison is disabled.

## Notes & TODOs

- `poly.c` retains straightforward arithmetic; once functionality stabilizes we can swap in Montgomery reductions or precomputed tables.
- The wave-based `a(x)` is deterministic for transparency; document any alternative generation in commit messages and rerun malformed-ciphertext tests.
- Future work: replace raw SHA3-256 KDF with a proper XOF or HKDF, add unit tests for serialization helpers, and integrate CI to run the Monte Carlo + benchmark suite automatically.
