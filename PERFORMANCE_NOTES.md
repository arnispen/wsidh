# WSIDH Performance Notes

This document summarizes the tangible hotspot work completed in this pass.

## Instrumentation
- Added cycle counters for every major component (NTT/INTT, pointwise mul,
  SHAKE128/256/x4, CBD sampler, compression/packing, FO re-encrypt, ct_compare,
  serialization and deserialization).
- `wsidh_bench` now prints keygen/encap/decap breakdowns using the
  instrumentation instead of opaque totals.

## Polynomial / NTT
- All stack and global polynomial buffers are now 32-byte aligned, ensuring the
  AVX2 butterflies and basemul kernels always hit aligned loads/stores.
- Forward/inverse NTT wrappers (scalar and AVX2) are profiled individually.
- Pointwise multiplication is measured and the AVX2 path is now wrapped so the
  profiler can attribute the work correctly.

## Sampling / SHAKE
- Deterministic samplers continue to use the PQClean SHAKE128x4 pipelines but
  now contribute to the profiler via the new SHAKE128x4 event. The per-call CBD
  cost shows up explicitly for both random and deterministic samplers.

## Compression / Packing
- Every compression/decompression and pack/unpack routine feeds the new
  `compress`, `decompress`, `pack`, and `unpack` counters, making it obvious how
  much time serialization burns relative to the NTT pipeline.

## FO-CCA Helpers
- Constant-time comparison (`poly_diff`, `ct_select`) were rewritten to use
  AVX2 xor/blend instructions and now report through the `ct_compare` counter.
- The FO re-encrypt path in decapsulation is timed separately so regressions in
  the Fujisaki–Okamoto check are easy to spot.

## Remaining Work
- The TODO list still calls for deeper SHAKE batching, AVX2 packing logic, and
  an optional AVX512 backend. Those require larger structural changes and are
  left for the next tuning round.
