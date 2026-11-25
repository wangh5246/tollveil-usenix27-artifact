#!/usr/bin/env python3
"""Create or reverify circuit-specific development keys from a pinned Phase 1."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile

from compile_circuits import sha256
from verify_qap_and_vkeys import r1cs_rank, verify_vkey, verify_zkey_padding


@lru_cache(maxsize=None)
def phase1_hash(path: Path) -> str:
    return sha256(path)


def stripped(path: Path) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", path.read_text())


def transcript_hashes(log: str, heading: str) -> list[str]:
    digest = r"((?:\s+[a-fA-F0-9]{8}){16})"
    return ["".join(value.split()).lower() for value in re.findall(heading + r": *" + digest, log)]


def run(cli: str, command: list, log_path: Path, *, stdin: str | None = None) -> str:
    with log_path.open("x") as log:
        subprocess.run([cli, *map(str, command)], input=stdin, text=True, stdout=log,
                       stderr=subprocess.STDOUT, check=True, timeout=1800)
    return stripped(log_path)


def setup(name: str, files: dict, build: Path, row: dict, out: Path, cli: str) -> dict:
    ptau = Path(files["ptau"]).resolve(strict=True)
    phase1 = phase1_hash(ptau)
    if phase1 != files["ptau_sha256"]:
        raise ValueError(f"{name}: prepared Phase 1 file fails its pin")
    r1cs = build / name / f"{name}.r1cs"
    if sha256(r1cs) != row["r1cs_sha256"]:
        raise ValueError(f"{name}: compiled R1CS differs from its pin")
    final_dir = out / name
    if final_dir.exists():
        raise FileExistsError(final_dir)
    stage = Path(tempfile.mkdtemp(dir=out, prefix=f"{name}.attempt-"))
    initial = stage / f"{name}.initial.zkey"
    final = stage / f"{name}.zkey"
    vkey = stage / f"{name}_vkey.json"
    if "initial" in files:
        shutil.copyfile(files["initial"], initial)
    else:
        run(cli, ["groth16", "setup", r1cs, ptau, initial], stage / "initial.log")
    if not initial.is_file() or not initial.stat().st_size:
        raise ValueError(f"{name}: initial setup did not produce a proving key")

    contribution = []
    if "retained" in files:
        shutil.copyfile(files["retained"], final)
    else:
        log = run(cli, ["zkey", "contribute", initial, final, "--name=TollVeil relation contribution"],
                  stage / "contribute.log", stdin=secrets.token_hex(64) + "\n")
        contribution = transcript_hashes(log, "Contribution Hash")
        if len(contribution) != 1:
            raise ValueError(f"{name}: contribution digest missing from transcript")
    verified_file = stage / "verify.log"
    verified = run(cli, ["zkey", "verify", r1cs, ptau, final], verified_file)
    circuit = transcript_hashes(verified, "Circuit Hash")
    contributions = transcript_hashes(verified, r"contribution #\d+ [^:\n]*")[::-1]
    if "ZKey Ok!" not in verified or len(circuit) != 1 or not contributions:
        raise ValueError(f"{name}: Groth16 ceremony transcript is incomplete or rejected")
    if contribution and contributions[-1:] != contribution:
        raise ValueError(f"{name}: contribution digest differs on verification")

    # Recheck the exact initial artifact recorded in the receipt independently
    # of the verifier's reconstruction of the initial key from R1CS and PTAU.
    # Use the unambiguous alias. The CLI otherwise matches "zkey verify"
    # before recognizing the "init" subcommand.
    linked = run(cli, ["zkvi", initial, ptau, final], stage / "verify_init.log")
    if "ZKey Ok!" not in linked or transcript_hashes(linked, "Circuit Hash") != circuit:
        raise ValueError(f"{name}: supplied initial key fails transcript verification")
    run(cli, ["zkey", "export", "verificationkey", final, vkey], stage / "export.log")
    algebra = r1cs_rank(r1cs)
    verify_zkey_padding(final, algebra)
    verify_vkey(vkey, algebra["public_wires_excluding_constant"])
    if "retained_vkey" in files and json.loads(vkey.read_text()) != json.loads(Path(files["retained_vkey"]).read_text()):
        raise ValueError(f"{name}: retained verification key differs from binary zkey")

    record = {
        "relation": name,
        "source_sha256": row["source_sha256"],
        "r1cs_sha256": row["r1cs_sha256"],
        "wasm_sha256": row["wasm_sha256"],
        "ptau_sha256": phase1,
        "zkey_initial_sha256": sha256(initial),
        "ceremony_circuit_hash": circuit[0],
        "contribution_digests": contributions,
        "fresh_phase2_contribution": bool(contribution),
        "zkey_final_sha256": sha256(final),
        "vkey_sha256": sha256(vkey),
        "verify_log_sha256": sha256(verified_file),
        "zkey_verify_exit": 0,
        "zkey_verify_init_exit": 0,
    }
    (stage / "ceremony.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    stage.rename(final_dir)
    print(f"{name}: ZKey Ok! ({len(contributions)} verified contributions)", flush=True)
    return record


def reuse(out: Path, name: str, row: dict, files: dict) -> dict | None:
    relation = out / name
    if not relation.exists():
        return None
    record = json.loads((relation / "ceremony.json").read_text())
    if any(record[field] != row[field] for field in ("source_sha256", "r1cs_sha256", "wasm_sha256")):
        raise ValueError(f"{name}: previous ceremony belongs to a different build")
    if record["ptau_sha256"] != files["ptau_sha256"] or record["relation"] != name:
        raise ValueError(f"{name}: previous ceremony used different parameters")
    paths = {
        "zkey_initial_sha256": f"{name}.initial.zkey",
        "zkey_final_sha256": f"{name}.zkey",
        "vkey_sha256": f"{name}_vkey.json",
        "verify_log_sha256": "verify.log",
    }
    if any(sha256(relation / filename) != record[field] for field, filename in paths.items()):
        raise ValueError(f"{name}: previously verified ceremony artifacts changed")
    if (record["zkey_verify_exit"] or record["zkey_verify_init_exit"]
            or "ZKey Ok!" not in stripped(relation / "verify.log")):
        raise ValueError(f"{name}: previously recorded ceremony did not pass")
    print(f"{name}: reused verified key and matching transcript", flush=True)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--snarkjs", default="snarkjs")
    parser.add_argument("--only", nargs="+", help="Verify a subset in a separate run")
    parser.add_argument("--resume", action="store_true", help="Reuse only completed, hash-matching relations")
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    version = subprocess.run([args.snarkjs, "--version"], capture_output=True, text=True).stdout
    if "snarkjs@0.7.6" not in version:
        raise SystemExit("Expected snarkjs 0.7.6")
    catalog = json.loads(args.catalog.read_text())
    compiled = json.loads((args.build / "compiled_circuits_manifest.json").read_text())
    applications = {name for name, row in compiled["circuits"].items() if row["scope"] == "application"}
    if len(applications) != 20 or set(catalog) != applications:
        raise SystemExit("The ceremony catalog must identify all 20 compiled relations")
    names = args.only or sorted(applications)
    if not set(names) <= applications or len(set(names)) != len(names):
        raise SystemExit("Unrecognized or repeated relation")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    args.out.mkdir(exist_ok=args.resume)
    manifest_path = args.out / "phase2_setup_manifest.json"
    if manifest_path.exists():
        raise FileExistsError(manifest_path)

    def check(name):
        row = compiled["circuits"][name]
        files = catalog[name]
        if args.resume:
            record = reuse(args.out, name, row, files)
            if record is not None:
                return name, record
        return name, setup(name, files, args.build, row, args.out, args.snarkjs)

    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        records = dict(executor.map(check, names))
    manifest_path.write_text(json.dumps({
        "snarkjs": "0.7.6",
        "compiler_build_manifest_sha256": sha256(args.build / "compiled_circuits_manifest.json"),
        "gamma": "fixed BN254 G2 generator",
        "phase2_updates": ["delta", "inverse-delta queries"],
        "relations": records,
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
