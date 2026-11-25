#!/usr/bin/env python3
"""Synthetic scaling witness fixtures and paired low-priority host entry point."""

import math
from pathlib import Path
import secrets
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "protocol"))
from circom_crypto import FIELD_P, OBUKeyPair, poseidon

def build_grid_graph(n: int) -> tuple[list[list[int]], list[int], list[list[int]], list[list[int]]]:
    """Deterministic 2D grid graph with N vertices (Chebyshev-1 3x3 neighborhood, matching Rome 396 topology)."""
    cols = {8: 4, 16: 4, 32: 8, 64: 8}[n]
    rows = n // cols
    assert rows * cols == n
    edges = []
    out_offsets = [0]
    for u in range(n):
        uy, ux = divmod(u, cols)
        nbrs = []
        for vy in range(max(0, uy - 1), min(rows, uy + 2)):
            for vx in range(max(0, ux - 1), min(cols, ux + 2)):
                nbrs.append(vy * cols + vx)
        for v in sorted(nbrs):
            edges.append([u, v])
        out_offsets.append(len(edges))
    # Spatial rates matching Rome-like center/ring heterogeneity
    cx, cy = (cols - 1) / 2.0, (rows - 1) / 2.0
    r_exact, r_hi = [], []
    for i in range(8):
        ex_row, hi_row = [], []
        for u in range(n):
            uy, ux = divmod(u, cols)
            dist = math.hypot(ux - cx, uy - cy)
            base = max(4, int(round(36 - 4.0 * dist))) + (2 if i % 2 == 0 else 0)
            ex_row.append(base)
            hi_row.append(base + 6)
        r_exact.append(ex_row)
        r_hi.append(hi_row)
    return edges, out_offsets, r_exact, r_hi


def build_scale_witness(n: int, edges: list[list[int]], out_offsets: list[int], r_exact: list[list[int]], r_hi: list[list[int]], profile_tag: int) -> dict:
    slots = 8
    short_cap = 64
    key = OBUKeyPair(secrets.token_bytes(32))
    sid = 8_000_000 + n
    entry = 0
    key_salt = secrets.randbelow(FIELD_P)
    pk_commit = key.pk_commit(key_salt)
    identity = poseidon([207001, sid, profile_tag, entry, pk_commit])
    header = poseidon([207003, identity, slots])

    # Walk along legal edges for 8 steps
    path = [entry]
    for i in range(slots):
        u = path[-1]
        nbrs = [edges[e][1] for e in range(out_offsets[u], out_offsets[u + 1])]
        path.append(nbrs[min(len(nbrs) - 1, (i + 1) % len(nbrs))])
    dists = [20 + (i * 3) for i in range(slots)]

    def dp_upper(pins: dict[int, tuple[int, int, int]]) -> dict:
        phi = np.zeros((slots + 1, n), dtype=np.int64)
        live = np.zeros((slots + 1, n), dtype=np.int64)
        live[slots, :] = 1
        choice = np.full((slots, n), -1, dtype=np.int64)
        for i in reversed(range(slots)):
            if i in pins:
                a, b, d = pins[i]
                if live[i + 1, b]:
                    live[i, a] = 1
                    phi[i, a] = phi[i + 1, b] + d * r_exact[i][a]
                    choice[i, a] = b
            else:
                for u in range(n):
                    best = -1
                    best_v = -1
                    for e in range(out_offsets[u], out_offsets[u + 1]):
                        v = edges[e][1]
                        if live[i + 1, v]:
                            val = int(phi[i + 1, v]) + short_cap * r_hi[i][u]
                            if val > best:
                                best = val
                                best_v = v
                    if best_v >= 0:
                        live[i, u] = 1
                        phi[i, u] = best
                        choice[i, u] = best_v
        mpath = [entry]
        for i in range(slots):
            mpath.append(int(choice[i, mpath[-1]]))
        return {"maximum": mpath, "phi": phi.tolist(), "live": live.tolist(), "upper": int(phi[0, entry])}

    d0 = dp_upper({})["upper"]
    # Update step: 4 elapsed slots, open slots 0..2
    pins = {i: (path[i], path[i + 1], dists[i]) for i in range(3)}
    cert = dp_upper(pins)
    upper = cert["upper"]
    refund_delta = d0 - upper
    old_salt = secrets.randbelow(FIELD_P)
    new_salt = secrets.randbelow(FIELD_P)
    prev_state = poseidon([207002, identity, 0, 0, 0, d0, 0, old_salt])
    next_state = poseidon([207002, identity, 1, 0b111, 4, upper, refund_delta, new_salt])

    digest = header
    past_arr, fault_arr, sealed_arr, opened_arr, meas_arr, ls_arr = [], [], [], [], [], []
    for i in range(slots):
        p = 1 if i < 4 else 0
        o = 1 if i < 3 else 0
        ls = secrets.randbelow(FIELD_P)
        leaf = poseidon([207010 + i, identity, path[i], path[i + 1], dists[i], ls]) if p else 0
        digest = poseidon([digest, p, 0, leaf])
        past_arr.append(p)
        fault_arr.append(0)
        sealed_arr.append(leaf)
        opened_arr.append(o)
        meas_arr.append(dists[i] if o else 0)
        ls_arr.append(ls if o else 0)
    sig = key.sign_field(digest)

    return {
        "relTag": 1, "sid": sid, "revision": 0, "profile": profile_tag, "entry": entry,
        "pkCommit": pk_commit, "deposit": d0, "infraMask": 0,
        "prevState": prev_state, "nextState": next_state, "refundDelta": refund_delta, "charge": 0,
        "Ax": key.Ax, "Ay": key.Ay, "keySalt": key_salt, "R8x": sig.R8x, "R8y": sig.R8y, "S": sig.S,
        "oldMask": 0, "oldCount": 0, "oldUpper": d0, "oldRefund": 0, "oldSalt": old_salt, "newSalt": new_salt,
        "past": past_arr, "fault": fault_arr, "sealed": sealed_arr, "opened": opened_arr,
        "measured": meas_arr, "leafSalt": ls_arr,
        "maximum": cert["maximum"], "phi": cert["phi"], "live": cert["live"], "upper": upper,
    }


if __name__ == "__main__":
    from measure_host import main
    main()
