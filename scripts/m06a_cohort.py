#!/usr/bin/env python3
"""Reconstruct the Taiwan chronological holdout locally from the pinned archive."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from compile_circuits import sha256
from run_phase6_m06a import PUBLIC, SLOTS, TARIFF_JSON, build_northern_corridor_and_trips, forward_dp_check, trip_clock


ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "datasets/tdcs_m06a/source_pins.json"
START, CUT, END = ("2019-08-30 08:00:00", "2019-08-30 08:30:00", "2019-08-30 09:00:00")
HOLDOUT_SIZE = 2000


def rank(index: int, scope: str) -> bytes:
    return hashlib.sha256(f"tollveil/m06a/{scope}/20190830/{index}".encode()).digest()


def select(source: Path, tariff: Path):
    pin = json.loads(PIN.read_text())
    if sha256(source) != pin["archive_sha256"] or sha256(tariff) != pin["tariff_sha256"]:
        raise ValueError("Taiwan archive or tariff bytes differ from their pins")
    calibration = []
    graph, eligible = build_northern_corridor_and_trips(
        source, tariff, calibrate=(START, CUT), test=(CUT, END), calibration_rows=calibration,
    )
    if len(eligible) < HOLDOUT_SIZE:
        raise ValueError(f"Only {len(eligible)} trips match the frozen calibration topology")
    selected = sorted(eligible, key=lambda row: rank(row["row_idx"], "holdout"))[:HOLDOUT_SIZE]
    selected.sort(key=lambda row: row["row_idx"])
    if any(not START <= row["first_detected"] < CUT for row in calibration) or any(
        not CUT <= row["first_detected"] < END for row in selected
    ):
        raise ValueError("Unexpected first detection in chronological split")
    if {row["row_idx"] for row in calibration} & {row["row_idx"] for row in selected}:
        raise ValueError("Calibration and test rows overlap")
    proof_rows = []
    for cls, count in ((0, 24), (1, 6), (2, 6)):
        ranked = sorted((row for row in selected if row["veh_class"] == cls),
                        key=lambda row: rank(row["row_idx"], "proof-cohort"))
        if len(ranked) < count:
            raise ValueError(f"Too few holdout rows in vehicle class {cls}")
        proof_rows += ranked[:count]
    proof_rows.sort(key=lambda row: row["row_idx"])
    return graph, calibration, selected, proof_rows, len(eligible)


def csv_and_hash(source: Path, selected: list[dict], output: Path | None) -> str:
    indices = {row["row_idx"] for row in selected}
    digest = hashlib.sha256()
    count = 0
    stream = output.open("xb") if output else None
    try:
        with source.open("rb") as raw:
            for index, line in enumerate(raw):
                if index in indices:
                    digest.update(line)
                    if stream:
                        stream.write(line)
                    count += 1
    finally:
        if stream:
            stream.close()
    if count != len(selected):
        raise ValueError("The original archive does not reproduce all selected lines")
    return digest.hexdigest()


def wrapper(graph: dict, role: str) -> str:
    args = [graph[field] for field in (
        "n", "bits", "E", "edges", "out_offsets", "fee_small", "fee_large", "fee_trailer", "profile_tag",
    )]
    args.insert(2, SLOTS)
    args.append(1 if role == "update" else 2)
    ports = ", ".join(PUBLIC)
    encoded = ",\n".join("    " + json.dumps(value, separators=(",", ":")) for value in args)
    return (
        'pragma circom 2.1.9;\ninclude "m06a_corridor_template.circom";\n\n'
        + f"component main {{public [{ports}]}} = M06ACorridor(\n{encoded}\n);\n"
    )


def receipt(graph, training, selected, proofs, eligible_count, cohort_sha) -> dict:
    policy = json.loads(PIN.read_text())["allowance_policy"]
    allowances = [policy["daily_free_km_per_vehicle"] * rate for rate in policy["standard_rates_01twd_per_km"]]
    matches = allowance_matches = positive_after_allowance = 0
    gross_total = allowance_total = 0
    for trip in selected:
        times = trip_clock(trip)
        if len(times) != SLOTS + 1:
            raise ValueError("Unusable observation clock")
        path = [graph["idx"][node] for node in trip["gantries"]]
        path += [graph["exit_id"]] * (SLOTS + 1 - len(path))
        pins = {k: tuple(path[k:k+2]) for k in range(SLOTS)}
        value = forward_dp_check(graph, trip["veh_class"], path[0], pins, 0)
        listed = trip["statutory_gantry_sum_01twd"]
        allowance = allowances[trip["veh_class"]]
        per_trip = max(0, value - allowance)
        matches += int(value == listed)
        allowance_matches += int(per_trip == listed - min(listed, allowance))
        positive_after_allowance += int(per_trip != 0)
        gross_total += value
        allowance_total += per_trip
    return {
        "timezone": "Asia/Taipei", "calibration": [START, CUT], "test": [CUT, END],
        "time_field": "first gantry detection, inclusive start and exclusive end",
        "calibration_trips": len(training), "topology_eligible_test_trips": eligible_count,
        "selected_test_trips": len(selected), "calibration_test_overlap": 0,
        "selection_sha256": cohort_sha, "profile_tag": str(graph["profile_tag"]),
        "gantries": graph["n"] - 1, "directed_edges_including_exit": graph["E"],
        "interchange_edges": graph["interchange_edges_count"],
        "vehicle_classes": dict(Counter(str(row["veh_class"]) for row in selected)),
        "proof_selection_classes": dict(Counter(str(row["veh_class"]) for row in proofs)),
        "list_price_matches": matches,
        "per_trip_allowance": {
            "scope": "Independent trip diagnostics with one fresh allowance per trip",
            "allows_01twd_by_class": allowances,
            "matches": allowance_matches,
            "trips_with_positive_fee": positive_after_allowance,
            "gross_01twd": gross_total,
            "after_allowance_01twd": allowance_total,
        },
        "scope": "2019 trace replay under archived 2024/25 gantry list prices in 0.1 TWD units",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-cohort", action="store_true")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--tariff", type=Path, default=TARIFF_JSON)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--local-csv", type=Path)
    parser.add_argument("--wrappers", type=Path, help="Write two wrappers into a fresh directory")
    parser.add_argument("--expect", type=Path, help="Compare the generated cohort receipt")
    args = parser.parse_args()
    graph, training, selected, proofs, eligible = select(args.source, args.tariff)
    result = receipt(graph, training, selected, proofs, eligible, csv_and_hash(args.source, selected, args.local_csv))
    if (result["list_price_matches"] != HOLDOUT_SIZE
            or result["per_trip_allowance"]["matches"] != HOLDOUT_SIZE):
        raise SystemExit("Gantry list-price replay failed to match the enumerated route")
    if args.expect and result != json.loads(args.expect.read_text()):
        raise SystemExit("The deterministic holdout differs from the packaged receipt")
    if args.wrappers:
        args.wrappers.mkdir()
        for role in ("update", "close"):
            (args.wrappers / f"m06a_{role}.circom").write_text(wrapper(graph, role))
    with args.receipt.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"M06A holdout verified: {HOLDOUT_SIZE} trips, {result['gantries']} gantries, "
          f"{result['directed_edges_including_exit']} edges including EXIT", flush=True)


if __name__ == "__main__":
    main()
