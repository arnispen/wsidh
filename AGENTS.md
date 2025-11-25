# Repository Guidelines

## Project Structure & Module Organization
WSIDH's constant-time C core lives in `src/` (ntt.c, poly.c, sha3.c, wsidh_kem.c) with matching headers in `include/`. Tunable prime, degree, and noise bounds sit in `include/params.h`; restrict edits there so math stays centralized. Deterministic drivers are under `test/` and produce the root-level binaries `wsidh_test` (correctness) and `wsidh_bench` (cycle counts). Experimental notebooks and Python glue belong in `python/` (activate `python/venv/bin/activate` before running `wsidh.ipynb`) or the standalone `visualise.ipynb`. Generated objects (`*.o`, binaries) should stay ignored or rebuilt, never checked in.

## Build, Test, and Development Commands
- `make` (or `make all`): builds `wsidh_test` and `wsidh_bench` with `gcc -O2 -Wall -Wextra -Iinclude`.
- `make wsidh_test` / `./wsidh_test`: compile and run the deterministic KEM regression that prints the shared key and PASS/FAIL banner.
- `make wsidh_bench` / `./wsidh_bench`: build and execute the rdtsc-based microbenchmark over 1,000 trials.
- `make clean`: remove intermediates so you can recompile with fresh parameters.
Use separate terminal tabs for long benchmarks so measurements stay uncontaminated.

## Coding Style & Naming Conventions
Follow the existing 4-space indent, brace-on-same-line layout, and `snake_case` identifiers (`wsidh_`, `poly_`, `sha3_`). Keep module APIs in `include/` and mark file-local helpers `static`. Favor fixed-width integers, `const` pointers for read-only inputs, and early `return` for error paths. Any entropy interface should accept a `rand_func_t` parameter and fall back to the provided `default_rng`. Document math-heavy sections with short banner comments similar to the current `============================================================` blocks.

## Testing Guidelines
Extend or mirror `test/test_wsidh.c` for new test cases; keep filenames `test/<feature>_*.c` and expose any extra internals through explicit debug wrappers (see `wsidh_encaps_debug` and `wsidh_decaps_debug`). Always run `./wsidh_test` after touching `src/` or `include/`, and capture the printed `WSIDH KEM test: SUCCESS` line in PR notes. For performance-sensitive changes, attach averaged cycle counts from `./wsidh_bench`. Where deterministic vectors are needed, inject a local RNG stub via the `rand_func_t` hook rather than seeding `rand()` globally.

## Commit & Pull Request Guidelines
The canonical Git history uses short, module-prefixed, imperative subjects (e.g., `poly: tighten Barrett reduction`) followed by a wrapped body that explains the rationale and risks. Replicate that style and end the body with a `Test:` stanza such as `Test: make wsidh_test wsidh_bench`. PRs should link the driving issue, summarize the architectural impact, paste relevant benchmark/test output, and include notebook screenshots only when UI artifacts change. Flag any parameter tweaks or RNG adjustments explicitly so reviewers can re-run side-channel checks.
