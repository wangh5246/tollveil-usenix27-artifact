#!/usr/bin/env python3
"""Rome cohort and proof-gated corridor replay entry point."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

WORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORK / "scripts"))
sys.path.insert(0, str(WORK / "protocol"))

from causal_profile import LONG, PUBLIC, SHORT, build
from causal_witness import Certifier, Facts, Scenario
from phase2_compare import ROME_SUMMARY, ROME_TRAJECTORIES, rome_records




def load_holdout_blocks_with_taxi() -> tuple[list[dict], dict]:
    """Load the G2/G4 taxi-disjoint holdout with local timestamps."""
    _, _, split = rome_records()
    with ROME_TRAJECTORIES.open() as f:
        raw = [json.loads(line) for line in f if line.strip()]
    with ROME_SUMMARY.open() as f:
        blocks = [json.loads(line) for line in f if line.strip()]

    sources = {}
    for b in blocks:
        m = re.fullmatch(r"rome:(\d+)-\d+:chunk\d+", b["source_user_id"])
        assert m is not None
        sources[b["source_user_id"]] = m[1]
    ranked = sorted(
        set(sources.values()),
        key=lambda i: hashlib.sha256(f"tollveil-v15/rome/split/v1/{i}".encode()).digest(),
    )
    cut = len(ranked) // 2
    train_ids = set(ranked[:cut])
    holdout_ids = set(ranked[cut : 2 * cut])
    assert len(train_ids & holdout_ids) == 0

    holdout_list = []
    for idx, b in enumerate(blocks):
        taxi = sources[b["source_user_id"]]
        if taxi in holdout_ids:
            coords = raw[b["raw_idx"]]["windows"][:9]
            cells = tuple(
                20 * min(19, max(0, int(float(w["y_m"]) // 500)))
                + min(19, max(0, int(float(w["x_m"]) // 500)))
                for w in coords
            )
            holdout_list.append({
                "block_idx": idx,
                "taxi_id": taxi,
                "raw_cells": cells,
                "d_true": tuple(b["d_true"]),
                "d_tilde": tuple(b["d_tilde"]),
                "timestamps": tuple(int(w["timestamp"]) for w in coords),
            })
    assert len(holdout_list) == split["holdout_blocks"] == 337
    return holdout_list, {
        **split,
        "train_taxi_count": len(train_ids),
        "holdout_taxi_count": len(holdout_ids),
        "taxi_id_overlap": len(train_ids & holdout_ids),
    }


def compute_lower_forward(profile, entry: int, tiers: tuple, pins: dict, rates_arr, short_pairs, long_pairs) -> int:
    """Offline exact coupled lower bound L* on the same causal graph for contraction width reporting."""
    n = len(profile.cells)
    INF = 10**12
    cur = np.full(n, INF, dtype=np.int64)
    cur[entry] = 0
    for i, tier in enumerate(tiers):
        nxt = np.full(n, INF, dtype=np.int64)
        if i in pins:
            a, b, d = pins[i]
            pairs = profile.long if tier else profile.short
            if b in pairs[a] and cur[a] < INF:
                nxt[b] = min(nxt[b], cur[a] + d * int(rates_arr[i, a]))
        else:
            a, b = long_pairs if tier else short_pairs
            keep = cur[a] < INF
            np.minimum.at(nxt, b[keep], cur[a[keep]])
        cur = nxt
    ans = int(cur.min())
    assert ans < INF
    return ans


def evaluate_all_holdout_regimes(profile, cert: Certifier, holdout_blocks: list[dict]) -> dict:
    """Evaluate all 337 held-out blocks under Peak heterogeneous and Off-peak spatial tariffs,
    plus fleet rolling AvailableMargin capital efficiency."""
    cell_to_idx = {c: i for i, c in enumerate(profile.cells)}
    short_pairs = cert.short_pairs
    long_pairs = cert.long_pairs

    # Construct off-peak spatial tariff (smoother spatial gradient: 50% congestion dampening)
    offpeak_exact = tuple(tuple(max(1, (r + 1) // 2) for r in row) for row in profile.rates)
    offpeak_hi = tuple(tuple(max(2, (r + 1) // 2) for r in row) for row in profile.hi)

    def forward_upper_custom(entry, tiers, caps, pins, rates_e_arr, rates_h_arr):
        unreachable = -1_000_000_000
        cur = np.full(len(profile.cells), unreachable, dtype=np.int64)
        cur[entry] = 0
        for i, (tier, cap) in enumerate(zip(tiers, caps)):
            nxt = np.full_like(cur, unreachable)
            if i in pins:
                a, b, d = pins[i]
                pairs = profile.long if tier else profile.short
                if b in pairs[a] and cur[a] >= 0:
                    nxt[b] = cur[a] + d * int(rates_e_arr[i, a])
            else:
                a, b = long_pairs if tier else short_pairs
                keep = cur[a] >= 0
                ca, cb = a[keep], b[keep]
                fee = cap * rates_h_arr[i, ca]
                np.maximum.at(nxt, cb, cur[ca] + fee)
            cur = nxt
        return int(cur.max())

    regimes = {}
    for regime_name, r_exact, r_hi in (
        ("peak_heterogeneous", profile.rates, profile.hi),
        ("offpeak_spatial", offpeak_exact, offpeak_hi),
    ):
        r_exact_arr = np.array(r_exact, dtype=np.int64)
        r_hi_arr = np.array(r_hi, dtype=np.int64)
        u_by_k = [[] for _ in range(9)]
        l_by_k = [[] for _ in range(9)]
        w_by_k = [[] for _ in range(9)]
        deposits = []
        final_fees = []
        early_rel_exact_frac = []
        early_rel_bucket_frac = []
        bucket_q = 2000

        # Fleet rolling margin: track per-taxi concurrent working capital across waves of trips
        fleet_trips_by_taxi = defaultdict(list)

        for blk in holdout_blocks:
            path = tuple(cell_to_idx[c] for c in blk["raw_cells"])
            dists = blk["d_true"]
            entry = path[0]
            # Genesis causal upper bound (t=0, all future unknown -> LONG)
            d0 = forward_upper_custom(entry, (1,) * 8, (LONG,) * 8, {}, r_exact_arr, r_hi_arr)
            deposits.append(d0)
            us = []
            ls = []
            for k in range(9):
                tiers = tuple(
                    (int(path[i + 1] not in profile.short[path[i]]) if i < k else 1)
                    for i in range(8)
                )
                caps = tuple(((LONG if tiers[i] else SHORT) if i < k else LONG) for i in range(8))
                pins = {i: (path[i], path[i + 1], dists[i]) for i in range(k)}
                uk = forward_upper_custom(entry, tiers, caps, pins, r_exact_arr, r_hi_arr)
                lk = compute_lower_forward(profile, entry, tiers, pins, r_exact_arr, short_pairs, long_pairs)
                u_by_k[k].append(uk)
                l_by_k[k].append(lk)
                w_by_k[k].append(uk - lk)
                us.append(uk)
                ls.append(lk)
            q_final = us[8]
            assert us[8] == ls[8]
            final_fees.append(q_final)
            # Average locked capital fraction over 8 slots [0..7] relative to Hold (constant d0)
            # Exact streaming releases (d0 - u[k]) immediately at step k
            mean_locked_exact = float(np.mean(us[:8]))
            # Bucketed streaming releases floor((d0 - u[k]) / bucket_q) * bucket_q
            locked_bucket = [d0 - ((d0 - uk) // bucket_q) * bucket_q for uk in us[:8]]
            mean_locked_bucket = float(np.mean(locked_bucket))
            early_rel_exact_frac.append(1.0 - mean_locked_exact / d0)
            early_rel_bucket_frac.append(1.0 - mean_locked_bucket / d0)
            fleet_trips_by_taxi[blk["taxi_id"]].append({
                "deposit": d0,
                "u_curve": us,
                "locked_bucket": locked_bucket,
                "final_fee": q_final,
            })

        # Simulate fleet rolling AvailableMargin pool for a 10-taxi fleet launching staggered trips
        # Compare Hold (full deposit locked until close) vs Streaming Exact vs Streaming Bucket (q=2000)
        # Across a rolling 33-wave dispatch (10 concurrent taxis, 1 slot stagger -> active slots overlap)
        all_trips = [t for tid in sorted(fleet_trips_by_taxi) for t in fleet_trips_by_taxi[tid]]
        # Rolling window of 10 concurrent trips staggered by 1 slot each
        peak_hold = 0
        peak_exact = 0
        peak_bucket = 0
        avg_hold_list, avg_exact_list, avg_bucket_list = [], [], []
        n_trips = len(all_trips)
        for start in range(0, n_trips - 10 + 1):
            window = all_trips[start : start + 10]
            # At steady-state tick t, trip j in window is at progress slot (j % 8)
            h_sum = sum(w["deposit"] for w in window)
            e_sum = sum(w["u_curve"][j % 8] for j, w in enumerate(window))
            b_sum = sum(w["locked_bucket"][j % 8] for j, w in enumerate(window))
            peak_hold = max(peak_hold, h_sum)
            peak_exact = max(peak_exact, e_sum)
            peak_bucket = max(peak_bucket, b_sum)
            avg_hold_list.append(h_sum)
            avg_exact_list.append(e_sum)
            avg_bucket_list.append(b_sum)

        # Internal zero-fee rolling transfers vs per-step external payout fee ($0.25/payout = 250 units)
        n_streaming_releases = sum(
            sum(1 for k in range(1, 8) if t["u_curve"][k] < t["u_curve"][k - 1]) for t in all_trips
        )
        regimes[regime_name] = {
            "blocks_evaluated": len(holdout_blocks),
            "mean_genesis_deposit": round(float(np.mean(deposits)), 2),
            "median_genesis_deposit": round(float(np.median(deposits)), 2),
            "mean_final_fee": round(float(np.mean(final_fees)), 2),
            "median_final_fee": round(float(np.median(final_fees)), 2),
            "mean_upper_by_k": [round(float(np.mean(arr)), 2) for arr in u_by_k],
            "mean_lower_by_k": [round(float(np.mean(arr)), 2) for arr in l_by_k],
            "mean_width_by_k": [round(float(np.mean(arr)), 2) for arr in w_by_k],
            "width_reduction_k4_pct": round((1.0 - float(np.mean(w_by_k[4])) / float(np.mean(w_by_k[0]))) * 100.0, 2),
            "width_reduction_k6_pct": round((1.0 - float(np.mean(w_by_k[6])) / float(np.mean(w_by_k[0]))) * 100.0, 2),
            "mean_capital_freed_exact_pct": round(float(np.mean(early_rel_exact_frac)) * 100.0, 2),
            "mean_capital_freed_bucket2000_pct": round(float(np.mean(early_rel_bucket_frac)) * 100.0, 2),
            "fleet_rolling_margin_10_concurrent": {
                "mean_locked_hold": round(float(np.mean(avg_hold_list)), 2),
                "mean_locked_exact": round(float(np.mean(avg_exact_list)), 2),
                "mean_locked_bucket2000": round(float(np.mean(avg_bucket_list)), 2),
                "peak_locked_hold": int(peak_hold),
                "peak_locked_exact": int(peak_exact),
                "peak_locked_bucket2000": int(peak_bucket),
                "mean_working_capital_reduction_exact_pct": round((1.0 - float(np.mean(avg_exact_list)) / float(np.mean(avg_hold_list))) * 100.0, 2),
                "mean_working_capital_reduction_bucket2000_pct": round((1.0 - float(np.mean(avg_bucket_list)) / float(np.mean(avg_hold_list))) * 100.0, 2),
                "internal_margin_releases_zero_fee": n_streaming_releases,
            },
        }
    return regimes


if __name__ == "__main__":
    from replay_escrow import main

    main("rome")
