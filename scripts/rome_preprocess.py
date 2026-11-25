#!/usr/bin/env python3
"""Import local CRAWDAD records and audit the frozen Rome eligibility cohort."""

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import math
from pathlib import Path
from random import Random
import re
import secrets
import tarfile

import numpy as np

from compile_circuits import sha256


ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "datasets/rome/source_pins.json"
POINT = re.compile(r"^(\d+);([^;]+);POINT\s*\((-?[.\d]+)\s+(-?[.\d]+)\)\s*$")
SOURCE = re.compile(r"rome:(\d+)-\d+:chunk\d+")
CITY = 10_000
CELL = 500
FIX_CELL = 100
FIX_COUNT = 10
# Binary64 equirectangular coefficients for radius 6371 km and latitude 41.892
# degrees. Pin the coefficients so cell-boundary decisions avoid platform libm differences.
LATITUDE_METRES_PER_DEGREE = 111194.92664455873
LONGITUDE_METRES_PER_DEGREE = 82774.03557213242


def centered_axis(values, metres_per_degree):
    metres = [value * metres_per_degree for value in values]
    lower, upper = min(metres), max(metres)
    return [min(CITY // FIX_CELL - 1, max(0, math.floor(
        (CITY / 2 + ((value - lower) - (upper - lower) / 2)) / FIX_CELL
    ))) for value in metres]


def cell(w: dict) -> int:
    grid = CITY // CELL
    x,y = (min(grid-1, max(0, int(w[axis]//CELL))) for axis in ("x_m", "y_m"))
    return grid*y + x


@contextmanager
def raw_stream(path: Path):
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            names = [row for row in archive.getmembers() if row.isfile() and row.name.endswith(".txt")]
            if len(names) != 1:
                raise ValueError("Expected one trace text member in the licensed archive")
            with archive.extractfile(names[0]) as stream:
                yield stream
    else:
        with path.open("rb") as stream:
            yield stream


def read_raw(path: Path):
    with raw_stream(path) as stream:
        yield from io.TextIOWrapper(stream, encoding="utf-8")


def raw_sha256(path: Path):
    with raw_stream(path) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepared_lines(rows):
    for row in rows:
        yield (json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)+"\n").encode()


def candidate_blocks(raw: Path, max_rows: int = 1000):
    """Emit ten-fix windows in the order their taxi segments finish in the source."""
    active, segment_number = {}, Counter()

    def windows(ident, number, points):
        for k in range(len(points) // FIX_COUNT):
            block = points[k*FIX_COUNT:(k+1)*FIX_COUNT]
            lats = [lat for _, lat, _ in block]
            lons = [lon for _, _, lon in block]
            xs = centered_axis(lons, LONGITUDE_METRES_PER_DEGREE)
            ys = centered_axis(lats, LATITUDE_METRES_PER_DEGREE)
            rows = []
            grid = CITY // FIX_CELL
            for j, ((stamp, _, _), cx, cy) in enumerate(zip(block, xs, ys, strict=True)):
                rows.append({"window_id": j, "timestamp": stamp, "x_m": float(cx*FIX_CELL),
                             "y_m": float(cy*FIX_CELL), "cell_x": cx, "cell_y": cy,
                             "cell_id": cy*grid+cx, "points_in_window": 1})
            yield f"rome:{ident}-{number}:chunk{k}", rows

    def record(index, item):
        source, rows = item
        return {"user_id": f"{index:03d}", "source_user_id": source, "city_size_m": float(CITY),
                "cell_size_m": float(FIX_CELL), "grid_w": CITY // FIX_CELL, "num_windows": FIX_COUNT,
                "windows": rows}

    selected = 0
    for line in read_raw(raw):
        match = POINT.fullmatch(line.strip())
        if match is None:
            continue
        ident, stamp, lat, lon = match.groups()
        parsed = datetime.fromisoformat(stamp)
        when = int((parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp())
        prior = active.get(ident, [])
        if prior and when - prior[-1][0] > 120:
            for item in windows(ident, segment_number[ident], prior):
                yield record(selected, item)
                selected += 1
                if selected == max_rows:
                    return
            segment_number[ident] += 1
            prior = []
        prior.append((when, float(lat), float(lon)))
        active[ident] = prior
    for ident, points in active.items():
        for item in windows(ident, segment_number[ident], points):
            yield record(selected, item)
            selected += 1
            if selected == max_rows:
                return


def eligible(rows, matrix):
    viable = set(int(x) for x in np.flatnonzero((np.isfinite(matrix).sum(axis=0) > 1) |
                                                (np.isfinite(matrix).sum(axis=1) > 1)))
    excluded, kept = Counter(), []
    for index, row in enumerate(rows):
        points = row["windows"][:9]
        if len(points) != 9:
            raise ValueError("Expected nine fixes per evaluation block")
        cells = [cell(point) for point in points]
        if len(set(cells)) <= 1:
            excluded["stationary"] += 1
            continue
        if any(a not in viable or b not in viable or not np.isfinite(matrix[a,b])
               for a,b in zip(cells, cells[1:])):
            excluded["disconnected"] += 1
            continue
        identity = SOURCE.fullmatch(row["source_user_id"])
        if identity is None:
            raise ValueError("Cannot recover the source taxi group")
        rng = Random(20261113 + index)
        measured, noisy = [], []
        for a,b in zip(points, points[1:]):
            distance = max(1, round(math.hypot(a["x_m"]-b["x_m"], a["y_m"]-b["y_m"])/10))
            measured.append(distance)
            noisy.append(max(1, distance + rng.choice((-1,0,1))))
        kept.append({"raw_idx": index, "source_user_id": row["source_user_id"], "taxi": identity[1],
                     "d_true": measured, "d_tilde": noisy})
    return kept, dict(excluded)


def split(kept):
    taxis = sorted({row["taxi"] for row in kept}, key=lambda taxi: hashlib.sha256(
        f"tollveil-v15/rome/split/v1/{taxi}".encode()).digest())
    half = len(taxis)//2
    return {group: taxis[lower:upper] for group,lower,upper in (
        ("calibration",0,half),("holdout",half,2*half),("reserved",2*half,len(taxis)),
    )}


def stratified(kept, held_out):
    by_taxi = defaultdict(list)
    for j,row in enumerate(kept):
        if row["taxi"] in held_out:
            by_taxi[row["taxi"]].append(j)
    rng = Random(202611246)
    selected = []
    for taxi in sorted(by_taxi):
        pool = list(by_taxi[taxi])
        rng.shuffle(pool)
        selected.extend(pool[:5])
    remaining = sorted(set(j for pool in by_taxi.values() for j in pool) - set(selected))
    rng.shuffle(remaining)
    while len(selected) < 55 and remaining:
        selected.append(remaining.pop())
    return sorted(selected)


def manifest(kept, split_map, selected, secret):
    def commit(label, value):
        message = json.dumps([label, value], separators=(",", ":"), sort_keys=True).encode()
        return hmac.digest(secret, message, "sha256").hex()

    groups = {}
    proof = {commit("block", kept[j]) for j in selected}
    for name, taxis in split_map.items():
        groups[name] = sorted((
            {"taxi_commitment": commit("taxi", taxi), "blocks": sorted(commit("block", row)
             for row in kept if row["taxi"] == taxi)}
            for taxi in taxis
        ), key=lambda row: row["taxi_commitment"])
    included = [leaf for rows in groups.values() for row in rows for leaf in row["blocks"]]
    if len(set(included)) != len(included) or not proof <= {x for row in groups["holdout"] for x in row["blocks"]}:
        raise ValueError("Public commitments did not certify the intended distinct sets")
    return {"method": "HMAC-SHA256 with private audit salt", "splits": groups, "proof_subset": sorted(proof)}


def stable_columns(row: dict) -> dict:
    return {key: row[key] for key in ("raw_idx", "source_user_id", "d_true", "d_tilde")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    kind = parser.add_mutually_exclusive_group(required=True)
    kind.add_argument("--raw", type=Path, help="Local official CRAWDAD archive or extracted trace")
    kind.add_argument("--prepared", type=Path, help="Local historical ten-fix blocks")
    parser.add_argument("--road", type=Path, default=ROOT/"datasets/rome/cell_dist.npy")
    parser.add_argument("--expected-summary", type=Path, help="Compare all historical source-to-window records")
    parser.add_argument("--local-summary", type=Path, help="Write restricted join data locally")
    parser.add_argument("--local-selection", type=Path, help="Write private proof-selection offsets")
    parser.add_argument("--local-prepared", type=Path, help="Write the private reconstructed historical JSONL")
    parser.add_argument("--commitment-key", type=Path, help="32-byte local private audit key")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    pins = json.loads(PIN.read_text())
    if sha256(args.road) != pins["road_matrix_sha256"]:
        raise SystemExit("Road distance matrix differs from the frozen pin")
    if args.prepared:
        input_hash = sha256(args.prepared)
        if input_hash != pins["prepared_sha256"]:
            raise SystemExit("Prepared input differs from the frozen pin")
        with args.prepared.open() as stream:
            rows = [json.loads(line) for line in stream if line.strip()]
    else:
        input_hash = raw_sha256(args.raw)
        if input_hash != pins["raw_text_sha256"]:
            raise SystemExit("Rome trace text differs from the provider pin")
        rows = list(candidate_blocks(args.raw))
    prepared_hash = hashlib.sha256()
    for line in prepared_lines(rows):
        prepared_hash.update(line)
    if prepared_hash.hexdigest() != pins["prepared_sha256"]:
        raise SystemExit("Reconstructed rows differ from the frozen prepared pin")
    kept, exclusions = eligible(rows,np.load(args.road, allow_pickle=False))
    split_map = split(kept)
    chosen = stratified(kept, split_map["holdout"])
    expected_rows = [stable_columns(row) for row in kept]
    if args.expected_summary:
        with args.expected_summary.open() as stream:
            reference = [stable_columns(json.loads(line)) for line in stream if line.strip()]
        if expected_rows != reference:
            raise SystemExit("Output differs from the frozen eligible cohort at the row level")
    distributions = {name: {"taxis": len(taxis), "blocks": sum(row["taxi"] in taxis for row in kept)}
                     for name,taxis in split_map.items()}
    if (len(kept), len(chosen)) != (856, 55):
        raise SystemExit("Frozen input did not reproduce the eligibility and proof counts")
    secret = args.commitment_key.read_bytes() if args.commitment_key else secrets.token_bytes(32)
    if len(secret) != 32:
        raise ValueError("The local audit key must have 32 bytes")
    result = {"input_scope": "frozen_prepared_blocks" if args.prepared else "provider_raw_trace",
              "input_sha256": input_hash, "prepared_sha256": prepared_hash.hexdigest(),
              "road_matrix_sha256": sha256(args.road),
              "processed": len(rows), "eligible": len(kept), "excluded": exclusions, "splits": distributions,
              "proof_sessions": len(chosen), "historical_join_row_match": args.expected_summary is not None,
              "commitments": manifest(kept, split_map, chosen, secret)}
    if args.local_prepared:
        with args.local_prepared.open("xb") as stream:
            stream.writelines(prepared_lines(rows))
    if args.local_summary:
        with args.local_summary.open("x") as stream:
            for row in expected_rows:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
    if args.local_selection:
        with args.local_selection.open("x") as stream:
            json.dump({"sessions": [{"block_idx": j, "fault_scenario": i % 5 == 2 and i < 50}
                                for i,j in enumerate(chosen)]}, stream)
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"Rome eligibility: {len(kept)}/{len(rows)} blocks, {len(chosen)} stratified proof sessions")


if __name__ == "__main__":
    main()
