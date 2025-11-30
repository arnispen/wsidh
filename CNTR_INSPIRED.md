# CNTR-Inspired Compact Mode (Experimental)

This branch experiments with a CNTR-style optimisation on top of WSIDH’s wave-based RLWE KEM. The goals were:

- Reduce ciphertext bandwidth by storing a single compressed polynomial `u` plus small deltas instead of the full `(u, v)`.
- Adopt a hybrid RLWE/NTRU noise profile (narrower bounds) and lazy modular reduction to lower cycle counts.
- Keep the standard FO-CCA transform intact while exposing a `WSIDH_COMPACT=1` build mode for research.

## What Changed

1. **Compact ciphertext encoding**  
   - `ct = compress(u) || delta || meta` where `delta[i] = center(v[i] - u[i])` is stored as a signed byte and `meta = {flags, checksum}` records whether any coefficient was clamped and an 8-bit XOR checksum of the delta stream.  
   - Decryption reconstructs `v` deterministically, checks the checksum, and then runs the usual FO check. Any mismatch (including metadata flips) is detected by the FO re-encrypt comparison because `store_ct()` re-serialises into the exact compact layout before comparison.  
   - The compact payload currently consumes `384 + 256 + 2 = 642` bytes; the remaining bytes of the 768-byte ciphertext are zero padded.
2. **Hybrid sampler + lazy reduction**  
   - In compact mode we resample secrets/noise from tighter bounds (±2 / ±1) to mimic an NTRU-like noise profile.  
   - The add/sub helpers avoid per-operation `% q` in this mode; instead the caller canonicalises right before serialisation or decoding.
3. **FO compare on serialised bytes**  
   - Re-encryption serialises into the same compact format so comparisons stay constant-time regardless of representation.
4. **Build switch**  
   - Use `WSIDH_COMPACT=1 make wsidh_bench` (optionally with `WITH_AVX2=1`) to enable the new mode. Standard builds are unchanged.

## Trade-offs & Status

- This is *experimental*: we have not derived new failure bounds or a formal proof for the altered encoding/noise profile.
- The signed-byte delta implicitly assumes `v - u` stays within ±127; extreme noise samples will clamp silently.
- Security is still RLWE/FO-based, but compact mode should be treated as a prototype until a full analysis is written.

## Next Steps / Open Questions

- Quantify empirical failure rates under the new bounds (run 10 k+ FO trials).
- Analyse the probability of delta overflow and whether wider metadata (5–6 bits) is justified.
- Explore more aggressive lazy-reduction (e.g., 64-bit accumulators) and CNTR-style encoding with message-aware deltas.

Until the above are addressed, compact mode is “research-only” and should not be used in production.
