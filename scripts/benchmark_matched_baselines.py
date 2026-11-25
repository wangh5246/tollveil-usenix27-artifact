#!/usr/bin/env python3
"""Measure authenticated settlement over 16 slots under four explicit trust models."""

import argparse
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from statistics import median
from struct import Struct
import sys
import tempfile
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))

from gap_model import GAP, VERTICES, endpoints, fees, whole_bounds
from gap_nozk_baselines import Source, lookup, verify


WIRE_EVIDENCE = Struct("<32sQIBB")


def coupled_caps(route: tuple) -> list:
    """Intersect pinned edge facts with a complete graph and only terminal anchors."""
    n = len(route) - 1
    matrices = {}
    for start in range(n):
        product = fees(start % GAP)
        matrices[start, start+1] = product
        for end in range(start+2, n+1):
            edge = fees((end-1) % GAP)
            product = np.max(product[:, :, None] + edge[None, :, :], axis=1)
            matrices[start, end] = product
    costs = [int(fees(k % GAP)[route[k], route[k+1]]) for k in range(n)]

    def cap(mask):
        total, start = 0, 0
        while mask:
            bit = mask & -mask
            k = bit.bit_length() - 1
            if k > start:
                total += int(matrices[start, k][route[start], route[k]])
            total += costs[k]
            start = k+1
            mask ^= bit
        if start < n:
            total += int(matrices[start, n][route[start], route[n]])
        return total

    return [cap(mask) for mask in range(1 << n)]


def apply(db, deposit, old_refund, admit, wire, terminal):
    db.execute("BEGIN IMMEDIATE")
    try:
        remembered, returned = db.execute("SELECT deposit,returned FROM escrow").fetchone()
        if (remembered, returned) != (deposit, old_refund):
            raise ValueError("Wrong predecessor")
        upper = admit(wire)
        delta = remembered - upper - returned
        if not 0 <= delta <= deposit:
            raise ValueError("Unsafe release")
        db.execute("UPDATE escrow SET returned=returned+?, charge=?, closed=?",
                   (delta, upper if terminal else 0, int(terminal)))
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return upper


def trials(n, key, deposit, initial_cap, make, admit, expected, terminal_mask):
    update_client, update_charger, close_client, close_charger = [], [], [], []
    update_lens, close_lens = [], []
    with tempfile.TemporaryDirectory(prefix="tollveil-baseline-ledger-") as tmp:
        with closing(sqlite3.connect(Path(tmp) / "ledger.db", isolation_level=None)) as db:
            db.execute("CREATE TABLE escrow(deposit INTEGER,returned INTEGER,charge INTEGER,closed INTEGER)")
            for _ in range(n):
                db.execute("DELETE FROM escrow")
                db.execute("INSERT INTO escrow VALUES (?,0,0,0)", (deposit,))
                previous_refund = 0
                for mask, close, client, charger, sizes in (
                    (key, False, update_client, update_charger, update_lens),
                    (terminal_mask, True, close_client, close_charger, close_lens),
                ):
                    start = perf_counter()
                    wire = make(mask)
                    client.append((perf_counter() - start) * 1000)
                    sizes.append(len(wire))
                    start = perf_counter()
                    value = apply(db, deposit, previous_refund, lambda blob: admit(mask, blob), wire, close)
                    charger.append((perf_counter() - start) * 1000)
                    if value != expected(mask):
                        raise RuntimeError("Comparator accepted a different amount")
                    previous_refund = deposit - value
                returned, charged, closed = db.execute("SELECT returned,charge,closed FROM escrow").fetchone()
                if returned + charged != deposit or closed != 1:
                    raise RuntimeError("Comparator close failed conservation")
    return {
        "trials": n, "update_wire_bytes": median(update_lens), "close_wire_bytes": median(close_lens),
        "client_update_ms": median(update_client), "charger_update_ms": median(update_charger),
        "client_close_ms": median(close_client), "charger_close_ms": median(close_charger),
        "initial_upper": initial_cap, "update_upper": expected(key), "close_charge": expected(terminal_mask),
    }


def benchmark(ntrials: int, storage: Path) -> dict:
    source = Source.enroll(16)
    public = source.key.public_key()
    n, m = len(source.routes)*GAP, len(source.routes)
    full = (1 << n)-1
    slot = 2*GAP + 1
    update = 1 << slot
    initial = whole_bounds(source.routes, 0)[1]
    records = {}

    def anchored(mask):
        return whole_bounds(source.routes, mask)[1]

    def online_admit(mask, wire):
        return verify(public, wire, source.policy, source.sid, mask)[1]

    def plaintext(mask):
        edges = b"".join(WIRE_EVIDENCE.pack(source.policy, source.sid, k,
            source.routes[k//GAP][k%GAP], source.routes[k//GAP][k%GAP+1]) for k in range(n) if mask & (1 << k))
        return edges + source.key.sign(edges)

    def admit_plaintext(mask, wire):
        edges, signature = wire[:-64], wire[-64:]
        public.verify(signature, edges)
        if len(edges) != WIRE_EVIDENCE.size * mask.bit_count():
            raise ValueError("Wrong evidence count")
        evidence: list[dict] = [{} for _ in range(m)]
        for policy, sid, k, a, b in WIRE_EVIDENCE.iter_unpack(edges):
            if (policy, sid) != (source.policy, source.sid) or not 0 <= k < n:
                raise ValueError("Wrong evidence scope")
            if not mask & (1 << k) or k % GAP in evidence[k//GAP]:
                raise ValueError("Wrong opening")
            evidence[k//GAP][k%GAP] = a, b
        total = 0
        for pins in evidence:
            current = np.full(VERTICES, -1000000, dtype=np.int64)
            current[0] = 0
            for k in range(GAP):
                if k in pins:
                    a,b = pins[k]
                    nxt = np.full_like(current, -1000000)
                    nxt[b] = current[a] + fees(k)[a,b]
                else:
                    nxt = np.max(current[:, None] + fees(k), axis=0)
                current = nxt
            total += int(current[0])
        return total

    records["plaintext"] = trials(ntrials, update, initial, initial, plaintext, admit_plaintext, anchored, full)
    records["online_trusted"] = trials(ntrials, update, initial, initial, source.online, online_admit, anchored, full)
    for variant in records.values():
        variant.update({"scope": "four anchored gaps", "pretrip_bytes": 0, "pretrip_ms": None, "catalog_rows": 0})

    factored = storage / "factored.bin"
    start = perf_counter()
    with factored.open("xb") as table:
        for gap, route in enumerate(source.routes):
            for mask in range(1 << GAP):
                upper = endpoints(route, mask, maximize=True)
                table.write(source.sign((gap << GAP) | mask, upper, upper))
    factored_ms = (perf_counter() - start) * 1000

    def local_entries(mask):
        return [(gap << GAP) | ((mask >> (gap*GAP)) & 15) for gap in range(m)]

    def local_wire(mask):
        return b"".join(lookup(factored, key, m*(1 << GAP)) for key in local_entries(mask))

    row_bytes = len(source.sign(0, 0, 0))

    def local_verify(mask, wire):
        if len(wire) != len(source.routes)*row_bytes:
            raise ValueError("Factored catalog response has wrong length")
        return sum(verify(public, wire[j*row_bytes:(j+1)*row_bytes], source.policy, source.sid, key)[1]
                   for j,key in enumerate(local_entries(mask)))

    records["offline_factored"] = trials(ntrials, update, initial, initial, local_wire, local_verify, anchored, full) | {
        "scope": "four anchored gaps", "pretrip_bytes": factored.stat().st_size,
        "pretrip_ms": factored_ms, "catalog_rows": m*(1 << GAP),
    }
    if factored.stat().st_size != records["offline_factored"]["catalog_rows"] * row_bytes:
        raise RuntimeError("Factored catalog failed to materialize")

    coupled = storage / "coupled.bin"
    route = source.routes[0] + tuple(vertex for gap in source.routes[1:] for vertex in gap[1:])
    coupled_source = Source(source.routes, source.sid, sha256(source.policy + b"single coupled corridor").digest(), source.key)
    start = perf_counter()
    bounds = coupled_caps(route)
    with coupled.open("xb") as table:
        for mask, upper in enumerate(bounds):
            table.write(coupled_source.sign(mask, upper, upper))
    coupled_ms = (perf_counter() - start) * 1000

    def coupled_wire(mask):
        return lookup(coupled, mask, 1 << n)

    def coupled_verify(mask, wire):
        return verify(public, wire, coupled_source.policy, source.sid, mask)[1]

    records["offline_coupled"] = trials(ntrials, update, bounds[0], bounds[0], coupled_wire, coupled_verify, bounds.__getitem__, full) | {
        "scope": "single coupled corridor with terminal anchors", "pretrip_bytes": coupled.stat().st_size,
        "pretrip_ms": coupled_ms, "catalog_rows": 1 << n,
    }
    if coupled.stat().st_size != records["offline_coupled"]["catalog_rows"] * row_bytes or bounds[0] <= initial:
        raise RuntimeError("Coupled catalog reduction dropped the inter-gap coupling")
    return {"slots": n, "gap_slots": GAP, "gaps": m, "update_opened_slot": slot,
            "case": "one authenticated opening, safe release, exact synthetic terminal close",
            "wire": "snapshot for each update or close, signature and application fields",
            "receipt": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=30)
    args = parser.parse_args()
    if args.trials < 1 or args.out.exists():
        parser.error("Require a positive trial count and fresh output path")
    with tempfile.TemporaryDirectory(prefix="tollveil-signed-catalog-") as path:
        report = benchmark(args.trials, Path(path))
    with args.out.open("x") as file:
        file.write(json.dumps(report, indent=2) + "\n")
    print("Matched signed comparators measured with 64 factored rows and 65,536 coupled rows")


if __name__ == "__main__":
    main()
