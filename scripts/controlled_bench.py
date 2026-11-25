#!/usr/bin/env python3
"""Controlled ABBA benchmark harness for TollVeil v15.

Monitors pre/post `sysctl vm.swapusage`, `vm_stat`, and per-prover peak RSS,
performs uncounted warmup iterations, and runs interleaved ABBA pairs of:
  1. Witness generation (optional or cached per arm)
  2. Native C++ Groth16 proving (`rapidsnark`)
  3. Independent Groth16 verification (`snarkjs groth16 verify`)
  4. SQLite `BEGIN IMMEDIATE` atomic ledger commit
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

NODE_BIN = "/opt/homebrew/bin/node"
RAPIDSNARK_BIN = "rapidsnark"
SNARKJS_BIN = "/usr/local/bin/snarkjs"


def read_swap_usage() -> dict:
    res = subprocess.run(["sysctl", "vm.swapusage"], capture_output=True, text=True, check=True)
    raw = res.stdout.strip()
    parsed: dict[str, float | str] = {"raw": raw}
    for key in ("total", "used", "free"):
        m = re.search(rf"{key}\s*=\s*([0-9.]+)M", raw)
        if m:
            parsed[f"{key}_mb"] = float(m.group(1))
    return parsed


def read_vm_stat() -> dict:
    res = subprocess.run(["vm_stat"], capture_output=True, text=True, check=True)
    out: dict[str, int] = {}
    for line in res.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            v = v.strip().rstrip(".")
            if v.isdigit():
                out[k.strip()] = int(v)
    return {
        "pageouts": out.get("Pageouts", 0),
        "swapouts": out.get("Swapouts", 0),
        "swapins": out.get("Swapins", 0),
    }


def read_hw_info() -> dict:
    info = {}
    for key in ("hw.model", "hw.ncpu", "hw.memsize"):
        res = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, check=True)
        info[key] = res.stdout.strip()
    return info


def parse_max_rss_bytes(stderr: str) -> int | None:
    m = re.search(r"(\d+)\s+maximum resident set size", stderr)
    return int(m.group(1)) if m else None


def init_bench_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=FULL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bench_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            arm TEXT NOT NULL,
            pair_idx INTEGER NOT NULL,
            proof_sha256 TEXT NOT NULL,
            public_sha256 TEXT NOT NULL,
            recorded_at_ns INTEGER NOT NULL
        );
        """
    )
    return conn


def run_single_arm(
    arm_label: str,
    pair_idx: int,
    zkey_path: Path,
    vkey_path: Path,
    wtns_path: Path,
    work_dir: Path,
    conn: sqlite3.Connection,
    gen_witness_js: Path | None = None,
    wasm_path: Path | None = None,
    input_json: Path | None = None,
) -> dict:
    proof_path = work_dir / f"proof_{arm_label}_{pair_idx}.json"
    public_path = work_dir / f"public_{arm_label}_{pair_idx}.json"

    witness_ms = 0.0
    if gen_witness_js is not None and wasm_path is not None and input_json is not None:
        wtns_path = work_dir / f"wtns_{arm_label}_{pair_idx}.wtns"
        tw0 = time.perf_counter()
        wres = subprocess.run(
            [NODE_BIN, str(gen_witness_js), str(wasm_path), str(input_json), str(wtns_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        witness_ms = (time.perf_counter() - tw0) * 1000.0

    # 1. Native rapidsnark prove
    tp0 = time.perf_counter()
    pres = subprocess.run(
        ["/usr/bin/time", "-l", RAPIDSNARK_BIN, str(zkey_path), str(wtns_path), str(proof_path), str(public_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    prove_ms = (time.perf_counter() - tp0) * 1000.0
    prover_rss_bytes = parse_max_rss_bytes(pres.stderr)

    # 2. Independent snarkjs verify
    tv0 = time.perf_counter()
    vres = subprocess.run(
        [NODE_BIN, SNARKJS_BIN, "groth16", "verify", str(vkey_path), str(public_path), str(proof_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    verify_ms = (time.perf_counter() - tv0) * 1000.0
    if "OK!" not in vres.stdout:
        raise RuntimeError(f"Groth16 verify failed: {vres.stdout}\n{vres.stderr}")

    # 3. SQLite BEGIN IMMEDIATE atomic commit
    proof_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
    public_sha = hashlib.sha256(public_path.read_bytes()).hexdigest()
    ts0 = time.perf_counter()
    conn.execute("BEGIN IMMEDIATE;")
    conn.execute(
        "INSERT INTO bench_receipts (arm, pair_idx, proof_sha256, public_sha256, recorded_at_ns) VALUES (?, ?, ?, ?, ?);",
        (arm_label, pair_idx, proof_sha, public_sha, time.time_ns()),
    )
    conn.execute("COMMIT;")
    sqlite_tx_ms = (time.perf_counter() - ts0) * 1000.0

    total_ms = witness_ms + prove_ms + verify_ms + sqlite_tx_ms
    return {
        "arm": arm_label,
        "pair_idx": pair_idx,
        "witness_ms": round(witness_ms, 3),
        "prove_ms": round(prove_ms, 3),
        "verify_ms": round(verify_ms, 3),
        "sqlite_tx_ms": round(sqlite_tx_ms, 3),
        "total_ms": round(total_ms, 3),
        "prover_peak_rss_mb": round(prover_rss_bytes / (1024 * 1024), 2) if prover_rss_bytes else None,
        "verified": True,
    }


def summarize_metric(values: list[float]) -> dict:
    arr = np.asarray(values, dtype=np.float64)
    q25, med, q75, p95 = np.percentile(arr, [25, 50, 75, 95])
    return {
        "n": len(values),
        "median_ms": round(float(med), 3),
        "iqr_ms": round(float(q75 - q25), 3),
        "p95_ms": round(float(p95), 3),
        "mean_ms": round(float(arr.mean()), 3),
        "min_ms": round(float(arr.min()), 3),
        "max_ms": round(float(arr.max()), 3),
    }


def rel_dev_pct(a: float, b: float) -> float:
    denom = 0.5 * (a + b)
    if denom == 0.0:
        return 0.0
    return abs(a - b) / denom * 100.0


def run_abba_benchmark(
    arm_a_cfg: dict,
    arm_b_cfg: dict,
    pairs: int = 10,
    warmups: int = 2,
    max_swap_delta_mb: float = 128.0,
    include_witness: bool = True,
) -> dict:
    hw = read_hw_info()
    swap_before = read_swap_usage()
    vm_before = read_vm_stat()

    with tempfile.TemporaryDirectory(prefix="tollveil_abba_") as td:
        td_path = Path(td)
        conn = init_bench_db(td_path / "bench_ledger.sqlite")

        # Precompute witness once per arm if not including witness per run
        pre_wtns = {}
        if not include_witness:
            for label, cfg in (("A", arm_a_cfg), ("B", arm_b_cfg)):
                wp = td_path / f"pre_{label}.wtns"
                subprocess.run(
                    [NODE_BIN, str(cfg["gen_witness_js"]), str(cfg["wasm_path"]), str(cfg["input_json"]), str(wp)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                pre_wtns[label] = wp

        # Warmups (excluded from stats)
        for w in range(warmups):
            for label, cfg in (("A", arm_a_cfg), ("B", arm_b_cfg)):
                run_single_arm(
                    arm_label=f"warmup_{label}",
                    pair_idx=w,
                    zkey_path=Path(cfg["zkey_path"]),
                    vkey_path=Path(cfg["vkey_path"]),
                    wtns_path=pre_wtns.get(label, td_path / "unused.wtns"),
                    work_dir=td_path,
                    conn=conn,
                    gen_witness_js=Path(cfg["gen_witness_js"]) if include_witness else None,
                    wasm_path=Path(cfg["wasm_path"]) if include_witness else None,
                    input_json=Path(cfg["input_json"]) if include_witness else None,
                )

        # Interleaved ABBA schedule: for pair p, even p runs (A, B), odd p runs (B, A)
        # Every 2 pairs form an exact A-B-B-A block.
        records_a = []
        records_b = []
        schedule = []
        for p in range(pairs):
            order = ("A", "B") if (p % 2 == 0) else ("B", "A")
            for label in order:
                cfg = arm_a_cfg if label == "A" else arm_b_cfg
                rec = run_single_arm(
                    arm_label=label,
                    pair_idx=p,
                    zkey_path=Path(cfg["zkey_path"]),
                    vkey_path=Path(cfg["vkey_path"]),
                    wtns_path=pre_wtns.get(label, td_path / "unused.wtns"),
                    work_dir=td_path,
                    conn=conn,
                    gen_witness_js=Path(cfg["gen_witness_js"]) if include_witness else None,
                    wasm_path=Path(cfg["wasm_path"]) if include_witness else None,
                    input_json=Path(cfg["input_json"]) if include_witness else None,
                )
                schedule.append(label)
                if label == "A":
                    records_a.append(rec)
                else:
                    records_b.append(rec)

        row_count = conn.execute("SELECT COUNT(*) FROM bench_receipts WHERE arm IN ('A','B');").fetchone()[0]
        conn.close()

    swap_after = read_swap_usage()
    vm_after = read_vm_stat()
    swap_delta_mb = round(abs(swap_after.get("used_mb", 0.0) - swap_before.get("used_mb", 0.0)), 2)
    pageouts_delta = vm_after["pageouts"] - vm_before["pageouts"]
    swap_clean = swap_delta_mb <= max_swap_delta_mb

    metrics_list = ["prove_ms", "verify_ms", "sqlite_tx_ms", "total_ms"]
    if include_witness:
        metrics_list.insert(0, "witness_ms")

    summary_a = {m: summarize_metric([r[m] for r in records_a]) for m in metrics_list}
    summary_b = {m: summarize_metric([r[m] for r in records_b]) for m in metrics_list}
    rel_devs = {
        m: round(rel_dev_pct(summary_a[m]["median_ms"], summary_b[m]["median_ms"]), 4)
        for m in metrics_list
    }
    peak_rss_mb = max(
        [r["prover_peak_rss_mb"] for r in (records_a + records_b) if r["prover_peak_rss_mb"] is not None],
        default=None,
    )

    return {
        "schema": "tollveil.v15.controlled_abba_bench.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "hardware": hw,
        "swap_before": swap_before,
        "swap_after": swap_after,
        "swap_used_delta_mb": swap_delta_mb,
        "vm_stat_before": vm_before,
        "vm_stat_after": vm_after,
        "pageouts_delta": pageouts_delta,
        "swap_clean": swap_clean,
        "config": {
            "pairs": pairs,
            "warmups": warmups,
            "include_witness": include_witness,
            "schedule": "".join(schedule),
            "sqlite_committed_rows": row_count,
        },
        "arm_A": summary_a,
        "arm_B": summary_b,
        "relative_median_deviation_pct": rel_devs,
        "prover_max_peak_rss_mb": peak_rss_mb,
        "raw_trials": {"A": records_a, "B": records_b},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Controlled ABBA benchmark harness.")
    ap.add_argument("--zkey", type=Path, required=True)
    ap.add_argument("--vkey", type=Path, required=True)
    ap.add_argument("--gen-witness-js", type=Path, required=True)
    ap.add_argument("--wasm", type=Path, required=True)
    ap.add_argument("--input-json", type=Path, required=True)
    ap.add_argument("--pairs", type=int, default=10)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--max-rel-dev-pct", type=float, default=2.5)
    ap.add_argument("--receipt", type=Path, required=True)
    args = ap.parse_args()

    cfg = {
        "zkey_path": str(args.zkey.resolve()),
        "vkey_path": str(args.vkey.resolve()),
        "gen_witness_js": str(args.gen_witness_js.resolve()),
        "wasm_path": str(args.wasm.resolve()),
        "input_json": str(args.input_json.resolve()),
    }
    result = run_abba_benchmark(cfg, cfg, pairs=args.pairs, warmups=args.warmups, include_witness=True)
    prove_dev = result["relative_median_deviation_pct"]["prove_ms"]
    total_dev = result["relative_median_deviation_pct"]["total_ms"]
    passed = (
        result["swap_clean"]
        and prove_dev < args.max_rel_dev_pct
        and total_dev < args.max_rel_dev_pct
        and result["config"]["sqlite_committed_rows"] == 2 * args.pairs
    )
    result["threshold_max_rel_dev_pct"] = args.max_rel_dev_pct
    result["status"] = "PASS" if passed else "FAIL"

    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": result["status"],
        "prove_median_A_ms": result["arm_A"]["prove_ms"]["median_ms"],
        "prove_median_B_ms": result["arm_B"]["prove_ms"]["median_ms"],
        "prove_rel_dev_pct": prove_dev,
        "total_median_A_ms": result["arm_A"]["total_ms"]["median_ms"],
        "total_median_B_ms": result["arm_B"]["total_ms"]["median_ms"],
        "total_rel_dev_pct": total_dev,
        "prover_max_peak_rss_mb": result["prover_max_peak_rss_mb"],
        "swap_used_delta_mb": result["swap_used_delta_mb"],
        "receipt": str(args.receipt),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
