#!/usr/bin/env python3
"""Phase 6.1: Driver-disjoint 50/50 Rome 396-cell holdout evaluation & >=200 real Groth16 proofs."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from random import Random

import numpy as np

WORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORK / "scripts"))
sys.path.insert(0, str(WORK / "protocol"))

from causal_exactness import genesis
from causal_ledger import CausalLedger, Enrollment
from causal_profile import LONG, PUBLIC, SHORT, build
from causal_witness import Certifier, Facts, Scenario
from circom_crypto import InfraBroadcaster, OBUKeyPair
from controlled_bench import parse_max_rss_bytes
from phase2_compare import ROME_SUMMARY, ROME_TRAJECTORIES, rome_records
from potential_certificate import field_input

NODE_BIN = "/opt/homebrew/bin/node"
RAPIDSNARK_BIN = "rapidsnark"
SNARKJS_BIN = "/usr/local/bin/snarkjs"

OUT_DIR = WORK / "receipts/phase6"
PROOF_DIR = OUT_DIR / "rome_proofs"
RECEIPT_PATH = OUT_DIR / "rome_holdout_396.json"


class PersistentWitnessGen:
    def __init__(self, role: str) -> None:
        base = WORK / f"circuits/causal/build_{role}-r3"
        stem = f"causal_{role}"
        js_dir = base / f"{stem}_js"
        self.proc = subprocess.Popen(
            [
                NODE_BIN,
                str(WORK / "scripts/batch_gen_witness.cjs"),
                str(js_dir / "witness_calculator.js"),
                str(js_dir / f"{stem}.wasm"),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def generate(self, data: dict, wtns_path: Path) -> float:
        assert self.proc.stdin and self.proc.stdout
        req = {"input": field_input(data), "wtns_path": str(wtns_path)}
        self.proc.stdin.write(json.dumps(req, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        if not resp.get("ok"):
            raise RuntimeError(f"Witness generation failed: {resp.get('error')}")
        return float(resp["witness_ms"])

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=15)


def load_holdout_blocks_with_taxi() -> tuple[list[dict], dict]:
    """Load the exact same driver-disjoint 50/50 split used in G2/G4, attaching taxi_id."""
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


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PROOF_DIR.mkdir(parents=True, exist_ok=True)

    profile = build()
    cert = Certifier(profile)
    cell_to_idx = {c: i for i, c in enumerate(profile.cells)}
    holdout_blocks, split_meta = load_holdout_blocks_with_taxi()

    print(f"[Rome 396] Loaded {len(holdout_blocks)} held-out blocks across {split_meta['holdout_taxi_count']} unseen taxis (overlap={split_meta['taxi_id_overlap']}).")
    t_start = time.perf_counter()

    # 1. Full 337-block exact contraction & fleet rolling margin evaluation (Peak & Off-peak)
    regime_stats = evaluate_all_holdout_regimes(profile, cert, holdout_blocks)
    print(f"[Rome 396] Full 337-block peak/offpeak contraction & rolling margin done in {time.perf_counter()-t_start:.2f}s.")

    # 2. Pre-register 55 held-out blocks (fixed seed, stratified across all 10 held-out taxis)
    by_taxi = defaultdict(list)
    for b in holdout_blocks:
        by_taxi[b["taxi_id"]].append(b)
    rng = Random(202611246)
    selected = []
    # Take 5 per taxi (50) + 5 additional random blocks from remaining = 55 blocks -> 220 real 396-cell proofs!
    used_indices = set()
    for tid in sorted(by_taxi):
        pool = list(by_taxi[tid])
        rng.shuffle(pool)
        take = min(5, len(pool))
        for blk in pool[:take]:
            selected.append(blk)
            used_indices.add(blk["block_idx"])
    remaining = [b for b in holdout_blocks if b["block_idx"] not in used_indices]
    rng.shuffle(remaining)
    while len(selected) < 55 and remaining:
        selected.append(remaining.pop())
    selected.sort(key=lambda b: b["block_idx"])
    assert len(selected) == 55

    # Prepare persistent witness generators & rapidsnark configs
    upd_base = WORK / "circuits/causal/build_update-r3"
    cls_base = WORK / "circuits/causal/build_close-r3"
    upd_zkey = upd_base / "causal_update.zkey"
    upd_vkey = upd_base / "causal_update_vkey.json"
    cls_zkey = cls_base / "causal_close.zkey"
    cls_vkey = cls_base / "causal_close_vkey.json"

    wg_upd = PersistentWitnessGen("update")
    wg_cls = PersistentWitnessGen("close")
    infra = InfraBroadcaster()
    obu_keys = {tid: OBUKeyPair(hashlib.sha256(f"tollveil-v15-rome-obu-{tid}".encode()).digest()) for tid in sorted(by_taxi)}

    verify_manifest = []
    proof_records = []
    session_summaries = []
    prove_times_upd = []
    prove_times_cls = []
    witness_times_upd = []
    witness_times_cls = []
    peak_rss_mb_list = []

    with tempfile.TemporaryDirectory(prefix="tollveil_p6_rome_") as td:
        tmp = Path(td)
        ledger_path = tmp / "rome_holdout_ledger.sqlite"
        # Pass-through verifier during generation; we verify ALL 220 proofs independently via snarkjs right after,
        # AND re-check every statement against the SQLite ledger!
        proof_cache_for_ledger = {}

        def cached_verifier(role: int, pub: list, proof: dict) -> bool:
            return True

        ledger = CausalLedger(ledger_path, cached_verifier, infra.pubkey_hex)
        # Fleet rolling margin tracker per taxi
        fleet_available_margin = defaultdict(int)
        fleet_external_topup = defaultdict(int)
        fleet_cumulative_deposits = defaultdict(int)
        fleet_cumulative_internal_reused = defaultdict(int)

        try:
            for s_idx, blk in enumerate(selected):
                tid = blk["taxi_id"]
                key = obu_keys[tid]
                path = tuple(cell_to_idx[c] for c in blk["raw_cells"])
                dists = blk["d_true"]
                sid = 6_000_000 + blk["block_idx"]
                scen = Scenario(profile, key, sid, path, dists)
                init_state = genesis(scen, cert)
                deposit = init_state.upper

                # Rolling AvailableMargin funding check
                fleet_cumulative_deposits[tid] += deposit
                reused = min(fleet_available_margin[tid], deposit)
                fleet_available_margin[tid] -= reused
                fleet_cumulative_internal_reused[tid] += reused
                fleet_external_topup[tid] += (deposit - reused)

                epoch_id = 100 + s_idx
                closes_at = 50
                ledger.register_trusted(
                    Enrollment(sid, profile.tag, scen.entry, scen.pk_commit, deposit, init_state.commit(scen.identity, 0), epoch_id, closes_at),
                    deposit,
                )

                # Each causal_update opens at most 1 new slot (Num2Bits(1) on openedCount - oldCountOpen);
                # causal_close opens all remaining valid slots and applies corroborated infra waiver M = F & M_infra.
                has_fault_scenario = (s_idx % 5 == 2) and (s_idx < 50)
                if has_fault_scenario:
                    step_specs = [
                        ("update", Facts(2, 0b00000001, 0, 0), 10),
                        ("update", Facts(4, 0b00000011, 0, 0), 20),
                        ("update", Facts(6, 0b00000111, 0, 0), 30),
                        # At close: slots 0..5 opened, slot 6 corroborated infra fault (waived), slot 7 uncorroborated OBU fault (charged worst-case)
                        ("close", Facts(8, 0b00111111, 0b01000000, 0b11000000), 55),
                    ]
                else:
                    step_specs = [
                        ("update", Facts(2, 0b00000001, 0, 0), 10),
                        ("update", Facts(4, 0b00000011, 0, 0), 20),
                        ("update", Facts(6, 0b00000111, 0, 0), 30),
                        ("close", Facts(8, 0b11111111, 0, 0), 55),
                    ]

                prev_state = init_state
                sess_steps = []
                for rev, (role_name, facts, now_ts) in enumerate(step_specs):
                    rel_tag = 1 if role_name == "update" else 2
                    data, next_state = scen.fill(facts, prev_state, rev, deposit, rel_tag, cert)

                    # Cross-check against independent forward DP
                    pins = {i: (path[i], path[i + 1], dists[i]) for i in range(8) if (facts.mask >> i) & 1}
                    ref_upper = cert.forward(scen.entry, tuple(data["isLongGap"]), tuple(data["cap"]), pins, facts.fault & facts.infra)
                    assert ref_upper == data["upper"], f"Forward DP mismatch on sid={sid} rev={rev}"

                    wtns_path = tmp / f"w_{sid}_{rev}.wtns"
                    proof_id = f"rome_b{blk['block_idx']:03d}_r{rev}_{role_name}"
                    proof_path = PROOF_DIR / f"{proof_id}_proof.json"
                    public_path = PROOF_DIR / f"{proof_id}_public.json"

                    wg = wg_upd if role_name == "update" else wg_cls
                    zkey = upd_zkey if role_name == "update" else cls_zkey
                    vkey = upd_vkey if role_name == "update" else cls_vkey

                    w_ms = wg.generate(data, wtns_path)
                    tp0 = time.perf_counter()
                    pres = subprocess.run(
                        ["/usr/bin/time", "-l", RAPIDSNARK_BIN, str(zkey), str(wtns_path), str(proof_path), str(public_path)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    p_ms = (time.perf_counter() - tp0) * 1000.0
                    rss_b = parse_max_rss_bytes(pres.stderr)
                    rss_mb = round(rss_b / (1024 * 1024), 2) if rss_b else None
                    if rss_mb is not None:
                        peak_rss_mb_list.append(rss_mb)
                    wtns_path.unlink(missing_ok=True)

                    pub_vec = json.loads(public_path.read_text())
                    expected_pub = [str(data[k]) for k in PUBLIC]
                    assert pub_vec == expected_pub, f"Public vector mismatch on {proof_id}"
                    proof_obj = json.loads(proof_path.read_text())

                    # Apply to SQLite CausalLedger
                    bulletin = infra.publish_broadcast(profile.tag, epoch_id, facts.infra) if role_name == "close" else None
                    ledger_row = ledger.apply(
                        sid=sid,
                        revision=rev,
                        role=rel_tag,
                        proof=proof_obj,
                        next_state=data["nextState"],
                        refund_delta=data["refundDelta"],
                        charge=data["charge"],
                        now=now_ts,
                        bulletin=bulletin,
                    )
                    # Credit released refundDelta immediately to taxi's zero-fee AvailableMargin pool
                    fleet_available_margin[tid] += data["refundDelta"]

                    if role_name == "update":
                        prove_times_upd.append(p_ms)
                        witness_times_upd.append(w_ms)
                    else:
                        prove_times_cls.append(p_ms)
                        witness_times_cls.append(w_ms)

                    verify_manifest.append({
                        "id": proof_id,
                        "vkey": str(vkey),
                        "public_path": str(public_path),
                        "proof_path": str(proof_path),
                    })
                    proof_records.append({
                        "id": proof_id,
                        "block_idx": blk["block_idx"],
                        "sid": sid,
                        "revision": rev,
                        "role": role_name,
                        "upper": data["upper"],
                        "refund_delta": data["refundDelta"],
                        "charge": data["charge"],
                        "witness_ms": round(w_ms, 3),
                        "prove_ms": round(p_ms, 3),
                        "peak_rss_mb": rss_mb,
                        "proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
                        "public_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
                    })
                    sess_steps.append(data["refundDelta"])
                    prev_state = next_state

                final_row = ledger.current(sid)
                assert final_row["closed"] == 1
                assert final_row["revision"] == 4
                conservation_err = (final_row["returned"] + final_row["charged"]) - deposit
                assert conservation_err == 0, f"Conservation error {conservation_err} on sid={sid}"

                waiver_saving = 0
                if has_fault_scenario:
                    # Verify that without infra corroboration (mask=0), charge is strictly higher
                    no_waiver_charge = cert.forward(
                        scen.entry, tuple(data["isLongGap"]), tuple(data["cap"]),
                        {i: (path[i], path[i + 1], dists[i]) for i in range(6)}, 0,
                    )
                    assert no_waiver_charge > final_row["charged"]
                    waiver_saving = no_waiver_charge - final_row["charged"]

                session_summaries.append({
                    "block_idx": blk["block_idx"],
                    "sid": sid,
                    "deposit": deposit,
                    "charged": final_row["charged"],
                    "returned": final_row["returned"],
                    "conservation_error": conservation_err,
                    "fault_scenario": has_fault_scenario,
                    "waiver_saving": waiver_saving,
                })
                if (s_idx + 1) % 10 == 0 or s_idx == len(selected) - 1:
                    print(f"[Rome 396] Progress: {s_idx+1}/{len(selected)} sessions ({len(proof_records)} proofs), last prove={p_ms:.1f} ms")
        finally:
            wg_upd.close()
            wg_cls.close()

        # 3. Independent Groth16 verification of ALL 220 proofs via snarkjs
        manifest_path = tmp / "verify_manifest.json"
        manifest_path.write_text(json.dumps(verify_manifest))
        t_v0 = time.perf_counter()
        vres = subprocess.run(
            [NODE_BIN, str(WORK / "scripts/batch_verify_groth16.cjs"), SNARKJS_BIN, str(manifest_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        v_summary = json.loads(vres.stdout)
        v_elapsed = time.perf_counter() - t_v0
        assert v_summary["all_verified"] and v_summary["passed"] == 220

        # Also spot-check 5 proofs via exact snarkjs CLI command
        cli_spot_ok = 0
        for item in verify_manifest[::44]:
            c_res = subprocess.run(
                [NODE_BIN, SNARKJS_BIN, "groth16", "verify", item["vkey"], item["public_path"], item["proof_path"]],
                capture_output=True,
                text=True,
                check=True,
            )
            if "OK!" in c_res.stdout:
                cli_spot_ok += 1
        assert cli_spot_ok == len(verify_manifest[::44])

    def pct_stats(arr):
        a = np.asarray(arr, dtype=np.float64)
        q25, med, q75, p95 = np.percentile(a, [25, 50, 75, 95])
        return {
            "n": len(arr),
            "median_ms": round(float(med), 3),
            "iqr_ms": round(float(q75 - q25), 3),
            "p95_ms": round(float(p95), 3),
            "mean_ms": round(float(a.mean()), 3),
        }

    total_cum_dep = sum(fleet_cumulative_deposits.values())
    total_reused = sum(fleet_cumulative_internal_reused.values())
    total_topup = sum(fleet_external_topup.values())

    receipt = {
        "schema": "tollveil.v15.phase6.rome_holdout_396.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS",
        "split": split_meta,
        "full_holdout_337_regimes": regime_stats,
        "real_proof_evaluation": {
            "blocks_proved": len(selected),
            "proofs_total": len(proof_records),
            "update_proofs": len(prove_times_upd),
            "close_proofs": len(prove_times_cls),
            "fault_waiver_sessions": sum(1 for s in session_summaries if s["fault_scenario"]),
            "all_verified_snarkjs": v_summary["all_verified"],
            "snarkjs_verified_count": v_summary["passed"],
            "snarkjs_cli_spot_checked": cli_spot_ok,
            "verify_total_seconds": round(v_elapsed, 3),
            "verify_ms_stats": pct_stats([r["verify_ms"] for r in v_summary["results"]]),
            "sqlite_sessions_closed": len(session_summaries),
            "sqlite_conservation_errors": sum(abs(s["conservation_error"]) for s in session_summaries),
            "using_visited_cell_subgraph": False,
            "circuit_domain_cells": 396,
            "update_prove_ms": pct_stats(prove_times_upd),
            "close_prove_ms": pct_stats(prove_times_cls),
            "update_witness_ms": pct_stats(witness_times_upd),
            "close_witness_ms": pct_stats(witness_times_cls),
            "prover_max_peak_rss_mb": max(peak_rss_mb_list),
            "prover_median_peak_rss_mb": round(float(np.median(peak_rss_mb_list)), 2),
            "rolling_margin_55_sessions": {
                "cumulative_deposits": total_cum_dep,
                "internal_margin_reused_zero_fee": total_reused,
                "external_topup_needed": total_topup,
                "external_funding_reduction_pct": round(total_reused / total_cum_dep * 100.0, 2),
            },
            "proof_dir": str(PROOF_DIR),
            "elapsed_total_seconds": round(time.perf_counter() - t_start, 2),
        },
        "sessions": session_summaries,
        "proof_hashes": {r["id"]: {"proof_sha256": r["proof_sha256"], "public_sha256": r["public_sha256"]} for r in proof_records},
    }
    RECEIPT_PATH.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"[Rome 396] DONE! {len(proof_records)} real 396-cell proofs verified (snarkjs={v_summary['passed']}/{v_summary['total']}, CLI spot={cli_spot_ok}, SQLite errors=0).")
    print(f"[Rome 396] Update prove median={receipt['real_proof_evaluation']['update_prove_ms']['median_ms']} ms, Close prove median={receipt['real_proof_evaluation']['close_prove_ms']['median_ms']} ms, Peak RSS={receipt['real_proof_evaluation']['prover_max_peak_rss_mb']} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
