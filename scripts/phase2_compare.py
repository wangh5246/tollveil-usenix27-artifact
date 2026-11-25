"""Local-only Phase 2 certificate checks against independent forward DP."""

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import re

import numpy as np

from phase2_profiles import ROAD, ROOT, rome_long, synthetic_openings, synthetic_profile
from potential_certificate import FIELD_P, PUBLIC, backward, field_input, poseidon, witness

WORK = Path(__file__).resolve().parents[1]
NODE = "/opt/homebrew/bin/node"
ROME_TRAJECTORIES = Path(os.environ.get("TOLLVEIL_ROME_PREPARED",
                                      ROOT / "experiments/rome_tsip_ready_1000u.jsonl"))
ROME_SUMMARY = Path(os.environ.get("TOLLVEIL_ROME_ELIGIBILITY",
                                  ROOT / "outputs/waybill-revision/2026-11-16/r8-remediation-suite/r8_rome_per_route_summary.jsonl"))


class WitnessChecker:
    def __init__(self, build: Path, name: str) -> None:
        wasm = build / f"{name}_js"
        self.proc = subprocess.Popen(
            [NODE, WORK / "scripts/check_potential_witnesses.cjs",
             wasm / "witness_calculator.js", wasm / f"{name}.wasm", str(len(PUBLIC))],
            text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def query(self, data: dict) -> dict:
        self.proc.stdin.write(json.dumps(field_input(data)) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def close(self) -> None:
        self.proc.stdin.close()
        if self.proc.wait(timeout=15):
            raise RuntimeError("calculator terminated with error")


def exhaustive_small(profile, entry: int, opened: dict) -> tuple[int, int]:
    def walk(i: int, a: int, low: int, high: int):
        if i == profile.slots:
            if a in profile.exits:
                yield low, high
            return
        t = profile.tariff[i]
        for b in profile.rows[a]:
            if i in opened:
                u, v, d = opened[i]
                if (a, b) == (u, v):
                    fee = d * t.exact_rate[a]
                    yield from walk(i + 1, b, low + fee, high + fee)
            else:
                yield from walk(i + 1, b,
                                low + t.low_distance * t.low_rate[a],
                                high + t.high_distance * t.high_rate[a])

    fees = list(walk(0, entry, 0, 0))
    return min(x for x, _ in fees), max(y for _, y in fees)


def synthetic() -> dict:
    profile = synthetic_profile()
    checker = WitnessChecker(WORK / "circuits/phase2/build_synthetic_r2", "synthetic")
    counts = Counter()
    try:
        for i, (entry, edges, order) in enumerate(synthetic_openings(profile), start=1):
            opened = {}
            for j in range(profile.slots + 1):
                expected = exhaustive_small(profile, entry, opened)
                data = witness(profile, i, entry, opened)
                response = checker.query(data)
                if response.get("public") != [str(data[k]) for k in PUBLIC]:
                    raise ValueError(f"valid synthetic witness rejected at case {i}, prefix {j}")
                if (data["lower"], data["upper"]) != expected:
                    raise ValueError(f"independent bounds differ at case {i}, prefix {j}")
                counts["prefixes_equal"] += 1
                if j < profile.slots:
                    at = order[j]
                    opened[at] = edges[at]
            counts["cases"] += 1

        data = witness(profile, 999, 0, {})
        probes = {
            "understated_upper": {"upper": data["upper"] - 1},
            "overstated_lower": {"lower": data["lower"] + 1},
            "illegal_midpath": {"maximum": [0, 4, *data["maximum"][2:]]},
            "unused_vertex_index": {"minimum": [0, 7, *data["minimum"][2:]]},
            "nonboolean_open": {"open": [2, 0, 0, 0]},
            "wrong_summary": {"summary": data["summary"] + 1},
            "wrong_evidence": {"evidence": data["evidence"] + 1},
            "wrapped_unsigned_lower": {"lower": FIELD_P - 1},
        }
        hub = deepcopy(data["upperHub"])
        hub[0][0] -= 1 << (profile.slack_bits + 1)
        probes["negative_upper_slack"] = {"upperHub": hub}
        hub = deepcopy(data["lowerHub"])
        hub[0][0] -= 1 << profile.slack_bits
        probes["oversized_positive_lower_slack"] = {"lowerHub": hub}
        opened = witness(profile, 1000, 0, {0: (0, 1, 3)})
        responses = {name: checker.query(data | patch).get("rejected") is True
                     for name, patch in probes.items()}
        responses["above_distance_cap"] = checker.query(opened | {"measured": [8, 0, 0, 0]}).get("rejected") is True
        responses["below_distance_floor"] = checker.query(opened | {"measured": [0, 0, 0, 0]}).get("rejected") is True
        responses["field_negative_distance"] = checker.query(opened | {"measured": [FIELD_P - 1, 0, 0, 0]}).get("rejected") is True
        return {"cases": dict(counts), "distinct_compiled_graphs": 1, "negative_cases": responses}
    finally:
        checker.close()


def rome_records():
    """Split complete source IDs before evaluating any held-out geometry."""
    with ROME_TRAJECTORIES.open() as f:
        raw = [json.loads(line) for line in f if line.strip()]
    with ROME_SUMMARY.open() as f:
        blocks = [json.loads(line) for line in f if line.strip()]
    sources = {}
    for b in blocks:
        match = re.fullmatch(r"rome:(\d+)-\d+:chunk\d+", b["source_user_id"])
        if match is None:
            raise ValueError("unrecognized Rome provenance; cannot split by taxi")
        sources[b["source_user_id"]] = match[1]
    ranked = sorted(set(sources.values()),
                    key=lambda i: sha256(f"tollveil-v15/rome/split/v1/{i}".encode()).digest())
    cut = len(ranked) // 2
    train_ids = set(ranked[:cut])
    holdout_ids = set(ranked[cut:2 * cut])
    reserve_ids = set(ranked[2 * cut:])
    if train_ids & holdout_ids:
        raise ValueError("taxi-ID split overlap")
    if any(raw[b["raw_idx"]]["source_user_id"] != b["source_user_id"] for b in blocks):
        raise ValueError("independent raw and summary identities disagree")

    def select(ids: set[str]):
        for b in blocks:
            if sources[b["source_user_id"]] in ids:
                coords = raw[b["raw_idx"]]["windows"][:9]
                cells = tuple(
                    20 * min(19, max(0, int(float(w["y_m"]) // 500)))
                    + min(19, max(0, int(float(w["x_m"]) // 500)))
                    for w in coords
                )
                yield cells, b["d_true"], b["d_tilde"]

    return select(train_ids), select(holdout_ids), {
        "source_id_counts": [len(train_ids), len(holdout_ids)],
        "calibration_blocks": sum(sources[b["source_user_id"]] in train_ids for b in blocks),
        "holdout_blocks": sum(sources[b["source_user_id"]] in holdout_ids for b in blocks),
        "reserved_source_ids": len(reserve_ids),
        "reserved_blocks": sum(sources[b["source_user_id"]] in reserve_ids for b in blocks),
        "identity_overlap": 0,
        "held_out_population": "856 eligible frozen r8 Rome blocks, partitioned by source taxi ID",
    }


def heldout(evaluate_wasm: bool) -> dict:
    profile, cells = rome_long()
    pos = {cell: i for i, cell in enumerate(cells)}
    roads = np.load(ROAD)[np.ix_(cells, cells)]
    finite = np.isfinite(roads)
    if roads[finite].max() > 621:
        raise ValueError("cannot omit the R8 road-distance cutoff")
    coords = np.array([(c // 20, c % 20) for c in cells], dtype=np.int64)
    offset = np.maximum(abs(coords[:, None] - coords[None, :]) - 1, 0)
    distance_squared = (offset ** 2).sum(2) * 500 ** 2
    @lru_cache(maxsize=None)
    def pairs(d: int | None):
        if d is None:
            return np.where(finite)
        return np.where(finite & (distance_squared <= ((d + 1) * 10 + 100) ** 2))

    exact_rates = [np.array(t.exact_rate, dtype=np.int64) for t in profile.tariff]
    low_rates = [np.array(t.low_rate, dtype=np.int64) for t in profile.tariff]
    high_rates = [np.array(t.high_rate, dtype=np.int64) for t in profile.tariff]

    def solve(steps: list, path: list[int], true_dist: list[int], noisy_dist: list[int], prefix: int, long: bool):
        min_inf, max_inf = 10 ** 12, -(10 ** 12)
        lo = np.full(profile.n, min_inf)
        hi = np.full(profile.n, max_inf)
        lo[path[0]] = hi[path[0]] = 0
        for i, edge in enumerate(steps):
            min_next = np.full_like(lo, min_inf)
            max_next = np.full_like(hi, max_inf)
            if i < prefix:
                a, b = path[i:i + 2]
                fee = true_dist[i] * exact_rates[i][a]
                min_next[b] = lo[a] + fee
                max_next[b] = hi[a] + fee
            else:
                a, b = edge
                d_lo = 0 if long else max(0, noisy_dist[i] - 1)
                d_hi = profile.tariff[i].high_distance if long else noisy_dist[i] + 1
                np.minimum.at(min_next, b, lo[a] + d_lo * low_rates[i][a])
                np.maximum.at(max_next, b, hi[a] + d_hi * high_rates[i][a])
            lo, hi = min_next, max_next
        return int(lo.min()), int(hi.max())

    _, test, stats = rome_records()
    full_pairs = [pairs(None)] * profile.slots
    counts = Counter()
    max_excess = 0
    initial_by_entry = defaultdict(set)
    checker = WitnessChecker(WORK / "circuits/phase2/build_rome396_long_r2", "rome396_long") if evaluate_wasm else None
    try:
        for j, (block, true_dist, noisy_dist) in enumerate(test):
            path = [pos[c] for c in block]
            slots = [pairs(d) for d in noisy_dist]
            for i, (a, b) in enumerate(zip(path[:-1], path[1:], strict=True)):
                expected_distance = (noisy_dist[i] + 1) * 10 + 100
                counts["retained_real_edges"] += int(finite[a, b] and distance_squared[a, b] <= expected_distance ** 2)
                counts["real_edges"] += 1
            opened = {}
            for prefix in range(profile.slots + 1):
                target = solve(slots, path, true_dist, noisy_dist, prefix, long=False)
                actual = tuple(backward(profile, path[0], opened, high)[0] for high in (False, True))
                counts["prefixes"] += 1
                counts["long_vs_intended_equal"] += int(actual == target)
                if prefix == 0:
                    initial_by_entry[path[0]].add(target[1])
                    max_excess = max(max_excess, actual[1] - target[1])
                if j < 12:
                    # Independent dense forward DP to cross-check the long
                    # candidate on a fixed bounded sample; no row data saved.
                    long_expected = solve(full_pairs, path, true_dist, noisy_dist, prefix, long=True)
                    counts["sample_long_forward_checks"] += 1
                    counts["sample_long_forward_equal"] += int(actual == long_expected)
                if checker is not None:
                    data = witness(profile, 10000 + j, path[0], opened)
                    response = checker.query(data)
                    counts["wasm_public_matches"] += int(response.get("public") == [str(data[k]) for k in PUBLIC])
                if prefix < profile.slots:
                    opened[prefix] = (path[prefix], path[prefix + 1], true_dist[prefix])
    finally:
        if checker is not None:
            checker.close()
    return stats | {
        "counts": dict(counts), "max_initial_cap_excess_vs_intended": max_excess,
        "vertices": profile.n, "finite_pairs": int(finite.sum()),
        "groups": len(profile.groups()[1]), "distance_bins_public": False,
        "distinct_public_entries": len(initial_by_entry),
        "same_entry_different_hindsight_caps": sum(len(caps) > 1 for caps in initial_by_entry.values()),
        "long_profile_geometry": "every finite ordered pair at the fixed 1500-unit distance cap",
        "reference_geometry": "finite ordered pair intersected with exact per-slot rectangle distance budget",
    }


def probe_full_size() -> dict:
    profile, _ = rome_long()
    entry = next(v for v, row in enumerate(profile.rows) if 0 < len(row) < profile.n)
    data = witness(profile, 900010, entry, {})
    checker = WitnessChecker(WORK / "circuits/phase2/build_rome396_long_r2", "rome396_long")
    scope = poseidon([204201, data["session"], data["profile"], data["entry"]])

    def bounds(lower: int, upper: int) -> dict:
        summary = poseidon([204203, scope, data["evidence"], lower, upper, data["summarySalt"]])
        return {"lower": lower, "upper": upper, "summary": summary}

    illegal = next(v for v in range(profile.n) if v not in profile.rows[entry])
    bad_hub = deepcopy(data["upperHub"])
    bad_hub[1][0] -= 1 << (profile.slack_bits + 1)
    probes = {
        "understated_upper_with_recomputed_summary": bounds(data["lower"], data["upper"] - 1),
        "overstated_lower_with_recomputed_summary": bounds(data["lower"] + 1, data["upper"]),
        "illegal_in_range_path": {"maximum": [entry, illegal, *data["maximum"][2:]]},
        "negative_hub_slack": {"upperHub": bad_hub},
        "field_wrapped_amount_with_recomputed_summary": bounds(FIELD_P - 1, data["upper"]),
    }
    try:
        positive = checker.query(data).get("public") == [str(data[k]) for k in PUBLIC]
        rejected = {name: checker.query(data | patch).get("rejected") is True for name, patch in probes.items()}
    finally:
        checker.close()
    return {"vertices": profile.n, "positive": positive, "negative_cases": rejected}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=("synthetic", "heldout", "heldout-wasm", "probe396"))
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    if args.check == "synthetic":
        result = synthetic()
    elif args.check == "probe396":
        result = probe_full_size()
    else:
        result = heldout(args.check == "heldout-wasm")
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
