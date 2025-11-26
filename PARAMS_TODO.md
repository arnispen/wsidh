# WSIDH Multi-Parameter TODO

This branch intentionally ships **only** the historic `N=256, q=3329` WSIDH
parameters. Everything else lives behind scaffolding so we can safely expand in
another project/branch once the heavy math work is complete.

To support CNTR-style parameter families (WSIDH512/768/1024), we still need:

1. **Parameter derivation tooling**
   - Python/Sage scripts that, given `(N, q)`, search for primes with
     `q ≡ 1 (mod 2N)`, find primitive `2N`-th roots, and emit Montgomery /
     Barrett constants.
   - Deterministic generation of the “wave” polynomial `a(x)` at each `N`.
   - Automated checks that new twiddle tables round-trip through forward+inverse
     NTT with zero mismatches.

2. **Noise / failure-rate analysis**
   - Simulators that sample `r, e1, e2` under proposed bounds, run the FO KEM
     10^6+ times, and estimate decapsulation failure probability.
   - Scripts that sweep bounds to find the smallest values meeting both security
     and correctness goals.

3. **Serialization planning**
   - Decide per-variant pk/sk/ct packing widths (10/11/12-bit) and confirm
     SHAKE input layouts stay constant.
   - Update the `wsidh_param_info_t` table with size deltas before exposing any
     new variants to the CLI.

4. **Integration hooks**
   - For each new variant we will need a dedicated `params_<N>.c` file holding
     the wave table and twiddle factors, plus tests that log
     `WSIDH_PARAMS_<N>` at startup.
   - Build/test glue that refuses to link until the matching params module is
     added (see `include/params_*.h` stubs).

Until those tools and proofs exist, **do not** attempt to “fake” WSIDH512/768/1024.
Compiling with `WSIDH_VARIANT=wsidh768` currently only changes the noise bounds
used by the sole N=256 implementation so CI remains honest about what is
actually evaluated.
