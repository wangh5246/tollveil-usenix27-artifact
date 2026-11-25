#!/usr/bin/env python3
"""Rebuild the published Circom main circuits in a fresh output directory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from r1cs_header import read_header


OPTIONS = ["--r1cs", "--wasm", "--sym", "--O1", "--prime", "bn128"]
COMPILER_VERSION = "circom compiler 2.1.9"
BENCHMARKS = {"bench_10k", "bench_100k"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def public_wires(sym_path: Path, n_public: int) -> list[str]:
    wires = {}
    with sym_path.open() as symbols:
        for line in symbols:
            _, wire, _, label = line.rstrip().split(",", maxsplit=3)
            index = int(wire)
            if 1 <= index <= n_public:
                if index in wires or not label.startswith("main."):
                    raise ValueError(f"{sym_path.name}: ambiguous public wire {index}")
                wires[index] = label.removeprefix("main.")
    return [wires[i] for i in range(1, n_public + 1)]


def compile_all(root: Path, output: Path, library: Path, compiler: str) -> dict:
    version = subprocess.check_output([compiler, "--version"], text=True).strip()
    if version != COMPILER_VERSION:
        raise ValueError(f"Expected {COMPILER_VERSION}, got {version}")
    circuit_dir = root / "circuits"
    sources = sorted(circuit_dir.rglob("*.circom"))
    mains = {}
    for path in sources:
        source = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(), flags=re.S)
        declaration = re.search(r"\bcomponent\s+main\b", source)
        if declaration:
            public = re.search(r"\bpublic\s*\[([^]]*)\]", source[declaration.end():])
            names = [name.strip() for name in public[1].split(",")] if public else []
            if path.stem in {name for name, _ in mains.values()}:
                raise ValueError(f"Duplicate main basename {path.stem}")
            mains[path] = (path.stem, names)
    if len(mains) != 22 or not BENCHMARKS.issubset(name for name, _ in mains.values()):
        raise ValueError("Expected 20 application mains and two compiler benchmarks")
    lib_files = sorted(library.rglob("*.circom"))
    if not (library / "poseidon.circom").is_file():
        raise ValueError(f"Circomlib circuits missing in {library}")

    output.mkdir()
    env = dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC", RAYON_NUM_THREADS="1")
    rows = {}
    for path, (name, declared_inputs) in mains.items():
        build = output / name
        build.mkdir()
        source_path = str(path.relative_to(root))
        command = [
            compiler, source_path, *OPTIONS, "-l", str(library),
            "-l", "circuits/phase2", "-o", str(build),
        ]
        with (build / "compile.log").open("x") as log:
            subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)

        r1cs = build / f"{name}.r1cs"
        wasm = build / f"{name}_js/{name}.wasm"
        sym = build / f"{name}.sym"
        header = read_header(r1cs)
        n_outputs = header["public_outputs"]
        n_inputs = header["public_inputs"]
        wires = public_wires(sym, n_outputs + n_inputs)
        if wires[n_outputs:] != declared_inputs:
            raise ValueError(f"{name}: compiled public input order differs from source")
        rows[name] = {
            "source": source_path,
            "scope": "compiler-benchmark" if name in BENCHMARKS else "application",
            "source_sha256": sha256(path),
            "r1cs_sha256": sha256(r1cs),
            "wasm_sha256": sha256(wasm),
            "sym_sha256": sha256(sym),
            "constraints": header["constraints"],
            "public_output_names": wires[:n_outputs],
            "public_input_names": declared_inputs,
        }
        print(f"{name}: {header['constraints']} constraints, {len(wires)} public wires", flush=True)
    return {
        "compiler": version,
        "compiler_options": OPTIONS,
        "source_hashes": {str(p.relative_to(root)): sha256(p) for p in sources},
        "circomlib_circuit_hashes": {str(p.relative_to(library)): sha256(p) for p in lib_files},
        "circuits": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True, help="Fresh directory with an existing parent")
    parser.add_argument("--circom", default="circom")
    parser.add_argument("--circomlib", type=Path, help="Override the vendored circuits directory")
    parser.add_argument("--expect", type=Path, help="Require exact equality with this build manifest")
    args = parser.parse_args()
    root = args.root.resolve()
    library = args.circomlib or root / "third_party/circomlib/circuits"
    manifest = compile_all(root, args.out.resolve(), library.resolve(), args.circom)
    (args.out / "compiled_circuits_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if args.expect and json.loads(args.expect.read_text()) != manifest:
        raise SystemExit("Compiled source, binary, or symbol manifest differs from the release")


if __name__ == "__main__":
    main()
