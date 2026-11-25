#!/usr/bin/env python3
"""Deterministic Circom 2.1.9 compiler wrapper and multi-dir byte-identity verifier.

Root-cause finding (Circom 2.1.9):
  - `--O2` performs linear constraint simplification using Rust HashMap iteration order
    (randomized SipHash per process) and parallel passes, producing non-deterministic
    `.r1cs` byte sequences across repeated builds of large circuits.
  - `--O1` performs AST-order signal-to-signal and signal-to-constant simplification;
    combined with fixed compiler binary (2.1.9), `RAYON_NUM_THREADS=1`, fixed locale,
    `--prime bn128`, and fixed `-l` search path order, it produces 100% byte-identical
    `.r1cs` and `.wasm` outputs across independent clean directories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("${WORKSPACE_ROOT}")
CIRCOM_BIN = Path("circom")
EXPECTED_VERSION = "circom compiler 2.1.9"
DEFAULT_LIB_DIRS = [
    ROOT / ".worktrees/waybill_formal/node_modules",
    ROOT / ".worktrees/waybill_formal/node_modules/circomlib/circuits",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_compiler_version() -> str:
    res = subprocess.run([str(CIRCOM_BIN), "--version"], capture_output=True, text=True, check=True)
    ver = res.stdout.strip()
    if ver != EXPECTED_VERSION:
        raise RuntimeError(f"Expected {EXPECTED_VERSION!r}, got {ver!r}")
    return ver


def parse_circom_metrics(stdout: str, time_stderr: str) -> dict:
    metrics: dict[str, int | float | None] = {
        "non_linear_constraints": None,
        "linear_constraints": None,
        "public_inputs": None,
        "public_outputs": None,
        "private_inputs": None,
        "wires": None,
        "peak_rss_bytes": None,
    }
    patterns = {
        "non_linear_constraints": r"non-linear constraints:\s*(\d+)",
        "linear_constraints": r"(?m)^linear constraints:\s*(\d+)",
        "public_inputs": r"public inputs:\s*(\d+)",
        "public_outputs": r"public outputs:\s*(\d+)",
        "private_inputs": r"private inputs:\s*(\d+)",
        "wires": r"wires:\s*(\d+)",
    }
    for k, pat in patterns.items():
        m = re.search(pat, stdout)
        if m:
            metrics[k] = int(m.group(1))
    m_rss = re.search(r"(\d+)\s+maximum resident set size", time_stderr)
    if m_rss:
        metrics["peak_rss_bytes"] = int(m_rss.group(1))
    return metrics


def deterministic_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAYON_NUM_THREADS": "1",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
    }
    return env


def compile_once(
    circuit_path: Path,
    out_dir: Path,
    opt: str = "--O1",
    extra_libs: list[Path] | None = None,
    emit_sym: bool = False,
) -> dict:
    circuit_path = circuit_path.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    lib_dirs = list(DEFAULT_LIB_DIRS) + [p.resolve() for p in (extra_libs or [])]

    cmd = [
        "/usr/bin/time", "-l",
        str(CIRCOM_BIN),
        str(circuit_path),
        "--r1cs",
        "--wasm",
    ]
    if emit_sym:
        cmd.append("--sym")
    cmd.extend([opt, "--prime", "bn128"])
    for ld in lib_dirs:
        cmd.extend(["-l", str(ld)])
    cmd.extend(["-o", str(out_dir)])

    t0 = time.perf_counter()
    res = subprocess.run(cmd, env=deterministic_env(), capture_output=True, text=True)
    elapsed_s = time.perf_counter() - t0
    if res.returncode != 0:
        raise RuntimeError(
            f"Circom failed (rc={res.returncode}) on {circuit_path}:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )

    stem = circuit_path.stem
    r1cs_path = out_dir / f"{stem}.r1cs"
    wasm_path = out_dir / f"{stem}_js" / f"{stem}.wasm"
    if not r1cs_path.exists() or not wasm_path.exists():
        raise RuntimeError(f"Expected outputs missing: {r1cs_path}, {wasm_path}")

    metrics = parse_circom_metrics(res.stdout, res.stderr)
    return {
        "circuit": str(circuit_path),
        "circuit_sha256": sha256_file(circuit_path),
        "out_dir": str(out_dir),
        "opt_flag": opt,
        "prime": "bn128",
        "rayon_num_threads": 1,
        "compile_seconds": round(elapsed_s, 4),
        "r1cs_path": str(r1cs_path),
        "r1cs_size_bytes": r1cs_path.stat().st_size,
        "r1cs_sha256": sha256_file(r1cs_path),
        "wasm_path": str(wasm_path),
        "wasm_size_bytes": wasm_path.stat().st_size,
        "wasm_sha256": sha256_file(wasm_path),
        "metrics": metrics,
    }


def verify_determinism(
    circuit_path: Path,
    trials: int = 3,
    opt: str = "--O1",
    extra_libs: list[Path] | None = None,
) -> dict:
    ver = verify_compiler_version()
    runs = []
    for idx in range(trials):
        with tempfile.TemporaryDirectory(prefix=f"det_circom_t{idx}_") as td:
            info = compile_once(circuit_path, Path(td), opt=opt, extra_libs=extra_libs)
            # Clear ephemeral paths in recorded summary
            info["trial"] = idx + 1
            runs.append(info)
    r1cs_set = {r["r1cs_sha256"] for r in runs}
    wasm_set = {r["wasm_sha256"] for r in runs}
    all_identical = (len(r1cs_set) == 1) and (len(wasm_set) == 1) and (len(runs) == trials)
    return {
        "compiler_version": ver,
        "circuit": str(circuit_path.resolve()),
        "circuit_sha256": runs[0]["circuit_sha256"],
        "opt_flag": opt,
        "trials": trials,
        "r1cs_unique_hashes": len(r1cs_set),
        "wasm_unique_hashes": len(wasm_set),
        "r1cs_sha256": runs[0]["r1cs_sha256"] if len(r1cs_set) == 1 else sorted(r1cs_set),
        "wasm_sha256": runs[0]["wasm_sha256"] if len(wasm_set) == 1 else sorted(wasm_set),
        "all_identical": all_identical,
        "metrics": runs[0]["metrics"],
        "compile_seconds_per_trial": [r["compile_seconds"] for r in runs],
        "peak_rss_mb_per_trial": [
            round(r["metrics"]["peak_rss_bytes"] / (1024 * 1024), 2)
            if r["metrics"]["peak_rss_bytes"] is not None else None
            for r in runs
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic Circom 2.1.9 compiler wrapper.")
    ap.add_argument("circuit", type=Path, help="Path to .circom file")
    ap.add_argument("-o", "--out-dir", type=Path, default=None, help="Output directory for compile mode")
    ap.add_argument("--opt", default="--O1", choices=["--O0", "--O1", "--O2"], help="Optimization level (default --O1)")
    ap.add_argument("--verify-determinism", type=int, default=0, help="Compile N times in fresh temp dirs and assert byte identity")
    ap.add_argument("--sym", action="store_true", help="Also emit .sym file")
    ap.add_argument("-l", "--lib", type=Path, action="append", default=[], help="Extra library include dirs")
    ap.add_argument("--receipt", type=Path, default=None, help="Optional path to write JSON receipt")
    args = ap.parse_args()

    ver = verify_compiler_version()
    payload: dict = {
        "schema": "tollveil.v15.deterministic_circom.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "compiler_version": ver,
    }

    ok = True
    if args.verify_determinism > 0:
        det = verify_determinism(args.circuit, trials=args.verify_determinism, opt=args.opt, extra_libs=args.lib)
        payload["determinism_check"] = det
        ok = ok and det["all_identical"]

    if args.out_dir is not None:
        comp = compile_once(args.circuit, args.out_dir, opt=args.opt, extra_libs=args.lib, emit_sym=args.sym)
        payload["compile"] = comp
        if "determinism_check" in payload and payload["determinism_check"]["all_identical"]:
            det_match = (
                comp["r1cs_sha256"] == payload["determinism_check"]["r1cs_sha256"]
                and comp["wasm_sha256"] == payload["determinism_check"]["wasm_sha256"]
            )
            payload["compile_matches_determinism_trials"] = det_match
            ok = ok and det_match

    payload["status"] = "PASS" if ok else "FAIL"
    text = json.dumps(payload, indent=2) + "\n"
    if args.receipt is not None:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(text, encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
