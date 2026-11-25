#!/usr/bin/env python3
"""Verify the application build, ceremony records, proof and PDF release lineage."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from compile_circuits import sha256
from verify_qap_and_vkeys import verify_vkey

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 50_000_000
FORBIDDEN_EXTENSIONS = {".zkey", ".ptau", ".wtns", ".db", ".sqlite", ".sqlite3", ".pem", ".key", ".pyc"}
FORBIDDEN_PATTERNS = (
    re.compile(r"/(?:Users|Volumes)/|/home/[a-z][a-z0-9_-]+/", re.I),
    re.compile(r"BEGIN (?:[A-Z]+ )?PRIVATE KEY|[a-z0-9]+_PRIVATE_TOKEN", re.I),
)


def json_load(relative):
    return json.loads((ROOT / relative).read_text())


def indexed_path(relative):
    if "\\" in relative or any(p in {".", "..", ".git"} for p in relative.split("/")):
        raise ValueError(f"Invalid artifact path {relative!r}")
    path = PurePosixPath(relative)
    if not path.parts or path.is_absolute() or str(path) != relative:
        raise ValueError(f"Invalid artifact path {relative!r}")
    full = ROOT.joinpath(*path.parts)
    if full.resolve() != full or not full.is_file():
        raise ValueError(f"Missing or redirected artifact file {relative}")
    return full


def inventory():
    entries = {}
    for line in (ROOT / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if not match or match[2] in entries:
            raise ValueError("Malformed or duplicate SHA256SUMS entry")
        file = indexed_path(match[2])
        if sha256(file) != match[1]:
            raise ValueError(f"Checksum mismatch for {match[2]}")
        if file.stat().st_size >= MAX_FILE_BYTES or file.suffix in FORBIDDEN_EXTENSIONS:
            raise ValueError(f"Disallowed release file {match[2]}")
        if any(part in {"node_modules", "__pycache__"} or part.startswith(".env") for part in file.relative_to(ROOT).parts):
            raise ValueError(f"Local configuration or cache under {match[2]}")
        if file.suffix == ".csv" and file.name != "freeway_gov_tw_m06a_schema.csv":
            raise ValueError(f"Unexpected CSV in release {match[2]}")
        if file.suffix in {".cjs", ".py", ".sh", ".md", ".json", ".tex", ".txt", ".log", ".bib"}:
            content = file.read_text(encoding="utf-8")
            if any(pattern.search(content) for pattern in FORBIDDEN_PATTERNS):
                raise ValueError(f"Local identity path or key material in {match[2]}")
        entries[match[2]] = match[1]
    actual = {
        str(path.relative_to(ROOT)) for path in ROOT.rglob("*")
        if (path.is_file() or path.is_symlink()) and not {".git", "node_modules"}.intersection(path.relative_to(ROOT).parts)
        and path.name != "SHA256SUMS"
    }
    if actual != set(entries):
        raise ValueError(f"Manifest file inventory differs. Extra {sorted(actual-set(entries))[:4]}, "
                         f"absent {sorted(set(entries)-actual)[:4]}")
    return entries


def receipts(entries):
    gate_names = sorted(key for key in entries if re.fullmatch(r"receipts/gate_G[0-7]\.json", key))
    if len(gate_names) != 8:
        raise ValueError("Expected G0 through G7 provenance records")
    for gate in gate_names:
        value = json_load(gate)
        for path, digest in value["refs"].items():
            if entries.get(path) != digest:
                raise ValueError(f"Missing or wrong gate reference {gate} -> {path}")
    g7 = json_load("receipts/gate_G7.json")
    if entries.get("TollVeil.pdf") != g7["live_pdf_sha256"]:
        raise ValueError("G7 hash disagrees with the final release PDF")
    for path in ("asset_manifest.json", "compiled_circuits_manifest.json", "proofs/manifest.json",
                 "phase2_setup_manifest.json", "TollVeil.pdf"):
        if g7["refs"].get(path) != entries[path]:
            raise ValueError(f"G7 did not pin {path}")
    return len(gate_names)


def verify_setup(entries, compile_manifest):
    setup = json_load("phase2_setup_manifest.json")
    if setup["compiler_build_manifest_sha256"] != entries["compiled_circuits_manifest.json"]:
        raise ValueError("Ceremonies were not recorded for the released build")
    expected = {name for name,row in compile_manifest["circuits"].items() if row["scope"] == "application"}
    if len(expected) != 20 or expected != set(setup["relations"]):
        raise ValueError("The complete set of application keys must be available")
    public_arity = {}
    for name,row in setup["relations"].items():
        compiled = compile_manifest["circuits"][name]
        if any(row[key] != compiled[key] for key in ("source_sha256", "r1cs_sha256","wasm_sha256")):
            raise ValueError(f"The recorded ceremony differs from the compiled relation {name}")
        filename = f"vkeys/{name}_vkey.json"
        public_arity[filename] = len(compiled["public_input_names"])+len(compiled["public_output_names"])
        verify_vkey(indexed_path(filename),public_arity[filename])
        transcript = f"receipts/ceremonies/{name}.log"
        if (entries[filename] != row["vkey_sha256"] or entries[transcript] != row["verify_log_sha256"]
                or "ZKey Ok!" not in indexed_path(transcript).read_text()
                or not row["contribution_digests"] or row["zkey_verify_exit"] != 0):
            raise ValueError(f"Missing verified ceremony for {name}")
    return public_arity


def verify_proofs(arity, compile_manifest, tmp):
    proof_rows = json_load("proofs/manifest.json")
    aggregation = json_load("proof_cohorts.json")
    if Counter(row["suite"] for row in proof_rows) != aggregation["counts"]:
        raise ValueError("Proof manifest cohort coverage differs")
    identifiers, used = set(), set()
    chains = defaultdict(list)
    proof_hashes = defaultdict(set)
    commands = []
    for row in proof_rows:
        if row["id"] in identifiers or row["proof_path"] in used or row["public_path"] in used:
            raise ValueError("A proof ID or payload path repeats")
        identifiers.add(row["id"])
        used.update((row["proof_path"], row["public_path"]))
        family = row["suite"]
        match = aggregation["allowed_relations"][family]
        if row["vkey"] not in match or row["vkey"] not in arity:
            raise ValueError(f"Unexpected relation for {row['id']}")
        public = json_load(row["public_path"])
        if not isinstance(public,list) or len(public) != arity[row["vkey"]]:
            raise ValueError(f"The public arity of {row['id']} differs from the key")
        if any(not isinstance(v,str) or re.fullmatch(r"0|[1-9][0-9]{0,76}",v) is None for v in public):
            raise ValueError(f"Noncanonical scalar in {row['id']}")
        if family in {"rome_396_holdout", "m06a_corridor", "rome_hold_fixture"}:
            relation = PurePosixPath(row["vkey"]).name.removesuffix("_vkey.json")
            compiled = compile_manifest["circuits"][relation]
            statement = dict(zip(compiled["public_input_names"], map(int, public), strict=True))
            expected_role = 2 if relation.endswith("_close") else 1
            if statement["relTag"] != expected_role:
                raise ValueError(f"{row['id']}: manifest and public transition roles differ")
            chains[(family, statement["sid"])].append(statement)
            proof_hashes[family].add(sha256(indexed_path(row["proof_path"])))
        commands.append({name: str(indexed_path(row[name])) for name in ("vkey","proof_path","public_path")}
                        | {"id": row["id"]})
    for (family, _), statements in chains.items():
        ordered = sorted(statements, key=lambda row:row["revision"])
        length = {"rome_396_holdout":4, "m06a_corridor":3, "rome_hold_fixture":8}[family]
        if len(ordered) != length or [row["revision"] for row in ordered] != list(range(length)):
            raise ValueError("Duplicate or missing corridor revision")
        if [row["relTag"] for row in ordered] != [1]*(length-1)+[2]:
            raise ValueError("Invalid corridor lifecycle roles")
        for key in ("profile", "entry", "pkCommit", "deposit", "vehClass"):
            if len({row.get(key) for row in ordered}) != 1:
                raise ValueError("The proof chain altered enrolled public fields")
        if any(a["nextState"] != b["prevState"] for a,b in zip(ordered, ordered[1:])):
            raise ValueError("The proof chain has an unbound predecessor")
        mask_wire = "infraMask" if family == "m06a_corridor" else "infraredMask"
        if ordered[-1]["nextState"] or any(row["charge"] or row[mask_wire] for row in ordered[:-1]):
            raise ValueError("A transition changes terminal fields outside the close role")
        if sum(row["refundDelta"] for row in ordered) + ordered[-1]["charge"] != ordered[0]["deposit"]:
            raise ValueError("The proof chain violates escrow conservation")
    for family, receipt in (
        ("rome_396_holdout", "rome_proof_gated_replay.json"), ("m06a_corridor", "m06a_proof_gated_replay.json"),
    ):
        ledger = json_load("receipts/v15_1/"+receipt)
        if proof_hashes[family] != {item["proof_sha256"] for item in ledger["proofs"]}:
            raise ValueError("The public proofs differ from the corresponding ledger receipt")
    print(f"Checked {len(chains)} public corridor chains and conserved deposits.")
    temp_manifest = tmp / "proofs.json"
    temp_manifest.write_text(json.dumps(commands))
    snarkjs = shutil.which("snarkjs")
    if snarkjs is None:
        raise RuntimeError("snarkjs 0.7.6 is required")
    summary = json.loads(subprocess.check_output(
        ["node", ROOT / "scripts/batch_verify_groth16.cjs", snarkjs, temp_manifest], text=True,
    ))
    if summary["passed"] != len(proof_rows) or not summary["all_verified"]:
        raise ValueError("Retained proof pairing failed")
    return summary["passed"]


def pinned_m06a(tmp):
    pin = json_load("datasets/tdcs_m06a/source_pins.json")
    provided = os.environ.get("TOLLVEIL_M06A_ARCHIVE")
    if provided:
        record = Path(provided)
        if sha256(record) != pin["archive_sha256"]:
            raise ValueError("Local M06A archive does not match its published hash")
        return record
    record = tmp / pin["archive_name"]
    for url in [pin["provider_archive"],*pin["mirror_commits"]]:
        try:
            with urllib.request.urlopen(url, timeout=12) as incoming, record.open("wb") as output:
                size = 0
                for block in iter(lambda: incoming.read(1024*1024),b""):
                    size += len(block)
                    if size > pin["archive_bytes"]:
                        raise ValueError("M06A response is larger than the pinned file")
                    output.write(block)
            if size == pin["archive_bytes"] and sha256(record) == pin["archive_sha256"]:
                return record
        except (OSError, ValueError):
            continue
    raise RuntimeError("Unable to acquire the pinned M06A file. Set TOLLVEIL_M06A_ARCHIVE to verified local bytes.")


def assets(tmp):
    output = tmp / "generated"
    subprocess.run([sys.executable, ROOT/"scripts/generate_v15_assets.py", "--out", output], check=True)
    manifest = json_load("asset_manifest.json")
    if len(manifest["generated"]) != 10:
        raise ValueError("Expected facts, fact schema, four figures and four tables")
    for target,digest in manifest["generated"].items():
        if sha256(output/target) != digest or sha256(indexed_path(f"manuscript_source/{target}")) != digest:
            raise ValueError(f"Regenerated manuscript asset differs: {target}")
    for target,digest in manifest["authored"].items():
        if sha256(indexed_path(f"manuscript_source/{target}")) != digest:
            raise ValueError(f"Authored manuscript input differs: {target}")
    return len(manifest["generated"])


def full_rebuild(tmp):
    builds = tmp / "compiled"
    subprocess.run([
        sys.executable, ROOT/"scripts/compile_circuits.py", "--out", builds,
        "--expect", ROOT/"compiled_circuits_manifest.json",
    ],check=True)
    qap = tmp / "qap.json"
    subprocess.run([
        sys.executable, ROOT/"scripts/verify_qap_and_vkeys.py", "--build", builds,
        "--vkeys", ROOT/"vkeys", "--out", qap,
    ],check=True)
    retained = json_load("receipts/v15_1/r2_qap_and_vkeys.json")
    actual = json.loads(qap.read_text())
    for name, row in actual["relations"].items():
        if any(retained["relations"][name][field] != value for field,value in row.items()):
            raise ValueError(f"Live binary QAP evidence differs for {name}")
    source = pinned_m06a(tmp)
    result = tmp / "m06a.json"
    subprocess.run([
        sys.executable, ROOT/"scripts/run_phase6_m06a.py", "--verify-cohort", "--source", source,
        "--receipt", result, "--expect", ROOT/"receipts/v15_1/m06a_cohort.json",
    ],check=True)
    models = tmp / "model_checks"
    subprocess.run([sys.executable, ROOT/"scripts/run_g4.py", "--mode", "models", "--out", models],check=True)
    for name in ("network.json","synthetic_stopping.json","synthetic_lp.json"):
        staged = json_load("receipts/v15_1/"+name)
        measured = json.loads((models/name).read_text())
        if measured != staged:
            raise ValueError(f"Model rerun differs: {name}")
    raw = os.environ.get("TOLLVEIL_ROME_RAW")
    if raw:
        rome = tmp / "rome.json"
        subprocess.run([sys.executable, ROOT/"scripts/rome_preprocess.py",
                        "--raw", raw, "--out", rome], check=True)
        current = json.loads(rome.read_text())
        recorded = json_load("receipts/v15_1/rome_cohort_manifest.json")
        for key in ("input_sha256", "prepared_sha256", "road_matrix_sha256", "processed",
                    "eligible", "excluded", "splits", "proof_sessions"):
            if current[key] != recorded[key]:
                raise ValueError(f"Rome provider reconstruction differs in {key}")
        print("Licensed Rome input reproduced frozen prepared bytes, eligibility and proof counts.")
    print("Full build matched 22 R1CS/WASM files, 20 QAPs, 2,000 Taiwan trips and standalone models.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true")
    mode.add_argument("--full-rebuild",action="store_true")
    args = parser.parse_args()
    entries = inventory()
    gate_count = receipts(entries)
    compile_manifest = json_load("compiled_circuits_manifest.json")
    arity = verify_setup(entries, compile_manifest)
    with tempfile.TemporaryDirectory(prefix="tollveil-cleanroom-") as directory:
        tmp = Path(directory)
        pairing = verify_proofs(arity, compile_manifest, tmp)
        generated = assets(tmp)
        if args.full_rebuild:
            full_rebuild(tmp)
    print(f"Verified {len(entries)} file hashes, {pairing} proof pairings, {generated} generated assets, "
          f"and {gate_count} gate records with zero missing links.")


if __name__ == "__main__":
    main()
