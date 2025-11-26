#!/usr/bin/env python3
"""
Temporary helper to explore CNTR-style parameter sets.

Given N and q (with 2N | q-1), this script computes:
  * wave_table: deterministic "wave-based" polynomial coefficients mod q
  * psi, psi_inv: a primitive 2N-th root of unity and its inverse
  * omega_fwd / omega_inv per stage (radix-2 NTT)
  * n_inv: modular inverse of N mod q

Outputs a JSON blob that can be pasted into the repo or inspected manually.
"""

import argparse
import json
import math
from typing import List, Dict


def factorize(n: int) -> Dict[int, int]:
    """Naive trial division, sufficient for the small q-1 we handle."""
    factors: Dict[int, int] = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def find_generator(mod: int) -> int:
    """Find a primitive root modulo mod (mod should be prime)."""
    phi = mod - 1
    factors = factorize(phi)
    for g in range(2, mod):
        ok = True
        for p in factors:
            if pow(g, phi // p, mod) == 1:
                ok = False
                break
        if ok:
            return g
    raise RuntimeError("no generator found")


def compute_stage_wlen(psi: int, n: int, q: int) -> List[List[int]]:
    """Compute radix-2 stage twiddle factors for forward/inverse NTT."""
    stages: List[List[int]] = []
    length = 2
    while length <= n:
        step = (q - 1) // length
        wlen = pow(psi, step, q)
        stages.append([wlen, pow(wlen, q - 2, q)])
        length <<= 1
    return stages


def generate_wave_table(n: int, q: int) -> List[int]:
    table = []
    for k in range(n):
        val = (
            400.0 * math.sin(2.0 * math.pi * k / n)
            + 250.0 * math.sin(4.0 * math.pi * k / n)
            + 150.0 * math.sin(6.0 * math.pi * k / n)
        )
        coeff = int(round(val)) % q
        table.append(coeff)
    return table


def main():
    parser = argparse.ArgumentParser(description="Generate CNTR-style parameter helpers.")
    parser.add_argument("--n", type=int, required=True, help="Polynomial degree")
    parser.add_argument("--q", type=int, required=True, help="Modulus (prime)")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to write JSON (defaults to stdout)",
    )
    args = parser.parse_args()

    n = args.n
    q = args.q

    if (q - 1) % (2 * n) != 0:
        raise ValueError("q-1 must be divisible by 2N for an NTT-friendly root")

    generator = find_generator(q)
    psi = pow(generator, (q - 1) // (2 * n), q)
    psi_inv = pow(psi, q - 2, q)
    n_inv = pow(n, q - 2, q)
    wave_table = generate_wave_table(n, q)

    stage_wlens = compute_stage_wlen(psi * psi % q, n, q)
    omega_fwd = [w[0] for w in stage_wlens]
    omega_inv = [w[1] for w in stage_wlens]

    data = {
        "n": n,
        "q": q,
        "wave_table": wave_table,
        "psi": psi,
        "psi_inv": psi_inv,
        "n_inv": n_inv,
        "omega_fwd": omega_fwd,
        "omega_inv": omega_inv,
        "generator": generator,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
