#!/usr/bin/env python3
"""Measure witness generation, proving and pairing within the same host trials."""

import argparse
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from time import perf_counter

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))

from compile_circuits import sha256
from live_groth16 import LiveGroth16Verifier
from potential_certificate import field_input
from replay_escrow import key_registry, rome_cases


def sample(values):
    q25, median, q75, p95 = np.percentile(values, (25, 50, 75, 95))
    return {"n": len(values), "q25": float(q25), "median": float(median),
            "q75": float(q75), "p95": float(p95)}


def timed(command, timeout):
    start = perf_counter()
    result = subprocess.run(["/usr/bin/time", "-l", *command], capture_output=True,
                            text=True, check=True, timeout=timeout)
    ms = (perf_counter() - start) * 1000
    rss = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
    if not rss:
        raise RuntimeError("macOS /usr/bin/time did not report the child peak RSS")
    return ms, int(rss[1]) / (1024**2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--historical-cohort", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds per child stage")
    parser.add_argument("--native-witness", type=Path)
    parser.add_argument("--repeated-after-sha256", help="Receipt hash of an earlier attempt")
    args = parser.parse_args()
    if args.trials < 3:
        parser.error("At least three timed trials are required")
    if args.timeout <= 0:
        parser.error("A positive per-stage timeout is required")
    if shutil.which("taskpolicy") is None:
        parser.error("The low-priority host experiment requires macOS taskpolicy")
    if args.out.exists():
        raise FileExistsError(args.out)
    env_threads = os.environ.get("OMP_NUM_THREADS")
    if env_threads != "2":
        parser.error("Run with OMP_NUM_THREADS=2 for the registered measurement")
    build, keys = args.build.resolve(), args.keys.resolve()
    manifest = build / "compiled_circuits_manifest.json"
    compiled = json.loads(manifest.read_text())["circuits"]
    setup = json.loads((keys / "phase2_setup_manifest.json").read_text())
    if setup["compiler_build_manifest_sha256"] != sha256(manifest):
        raise ValueError("Proving setup and witness build differ")
    name = "causal_update"
    registry = key_registry(keys, compiled, setup, {name})
    historical = json.loads(args.historical_cohort.read_text())["sessions"][:1]
    _, _, cases, step = rome_cases(historical)
    case = cases[0]
    timings, failures = [], []
    with tempfile.TemporaryDirectory(prefix="tollveil-host-") as scratch, LiveGroth16Verifier(registry) as verifier:
        work = Path(scratch)
        js = build / name / f"{name}_js"
        zkey = keys / name / f"{name}.zkey"
        witness_in, witness_out = work / "input.json", work / "witness.wtns"
        proof_path, public_path = work / "proof.json", work / "public.json"
        for i in range(args.trials + 2):
            stage = "prepare"
            try:
                start = perf_counter()
                witness, _, _, _ = step(case, 0, case[2])
                prepare = (perf_counter() - start) * 1000
                witness_in.write_text(json.dumps(field_input(witness)))
                witness_command = [args.native_witness.resolve()] if args.native_witness else [
                    "node", js / "generate_witness.js", js / f"{name}.wasm",
                ]
                stage = "witness"
                witness_ms, witness_rss = timed(["taskpolicy", "-b", *witness_command, witness_in, witness_out],
                                                args.timeout)
                stage = "prove"
                prove_ms, prove_rss = timed(["taskpolicy", "-b", "rapidsnark", zkey, witness_out,
                                             proof_path, public_path], args.timeout)
                stage = "verify"
                proof, public = json.loads(proof_path.read_text()), json.loads(public_path.read_text())
                if public != [str(witness[field]) for field in compiled[name]["public_input_names"]]:
                    raise ValueError("Public statement differs from the compiled wire order")
                start = perf_counter()
                pairing = verifier.verify(name, tuple(public), proof)
                verify_ms = (perf_counter() - start) * 1000
                if i >= 2:
                    timings.append({
                        "trial": i-1, "preparation_ms": prepare, "witness_ms": witness_ms,
                        "prove_ms": prove_ms, "verify_ms": verify_ms, "pairing_ms": pairing,
                        "total_ms": witness_ms + prove_ms + verify_ms,
                        "witness_peak_rss_mib": witness_rss, "prover_peak_rss_mib": prove_rss,
                        "proof_and_vector_bytes": proof_path.stat().st_size + public_path.stat().st_size,
                    })
            except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
                failures.append({"trial": i-1, "stage": stage, "type": type(error).__name__,
                                 "exit": getattr(error, "returncode", None)})
    metrics = ("preparation_ms", "witness_ms", "prove_ms", "verify_ms", "pairing_ms", "total_ms",
               "witness_peak_rss_mib", "prover_peak_rss_mib", "proof_and_vector_bytes")
    summary = {stage: sample([row[stage] for row in timings]) for stage in metrics} if timings else {}
    with args.out.open("x") as stream:
        json.dump({
            "scope": "low-priority macOS host, one retained Rome witness shape",
            "priority": "taskpolicy -b for witness calculator and prover", "omp_num_threads": 2,
            "witness_backend": "native" if args.native_witness else "wasm",
            "verifier_threads": 1, "os": platform.mac_ver()[0], "machine": platform.machine(),
            "requested_measured_trials": args.trials, "warmups": 2, "per_child_timeout_s": args.timeout,
            "repeated_after_sha256": args.repeated_after_sha256, "timings": timings, "summary": summary,
            "peak_child_rss_mib": max(max(r["witness_peak_rss_mib"], r["prover_peak_rss_mib"]) for r in timings)
            if timings else None,
            "failures": failures, "build_manifest_sha256": sha256(manifest),
        }, stream, indent=2)
        stream.write("\n")
    if failures:
        raise SystemExit("The host benchmark recorded failed trials")
    print(f"Host paired trial median {summary['total_ms']['median']:.2f} ms over {len(timings)} trials", flush=True)


if __name__ == "__main__":
    main()
