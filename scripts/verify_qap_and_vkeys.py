#!/usr/bin/env python3
"""Check the BN254 public A-polynomials of the snarkjs 0.7.6 Groth16 QAP."""

import argparse
import json
from pathlib import Path
import struct

from compile_circuits import BENCHMARKS, sha256
from r1cs_header import read_header


P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
U32 = struct.Struct("<I")
SECTION = struct.Struct("<IQ")
MONTOGOMERY_ONE = (1 << 512) % P


def sections(file, magic: bytes, versions: set[int], size: int) -> dict[int, tuple[int, int]]:
    if file.read(4) != magic:
        raise ValueError(f"{file.name}: invalid {magic!r} magic")
    version, count = struct.unpack("<II", file.read(8))
    if version not in versions or count > (size - 12) // SECTION.size:
        raise ValueError(f"{file.name}: invalid version or section count")
    spans = {}
    for _ in range(count):
        kind, length = SECTION.unpack(file.read(SECTION.size))
        start = file.tell()
        if kind in spans or start + length > size:
            raise ValueError(f"{file.name}: malformed section {kind}")
        spans[kind] = (start, length)
        file.seek(length, 1)
    if file.tell() != size:
        raise ValueError(f"{file.name}: extra bytes after the last section")
    return spans


def insert(basis: dict[int, list[int]], row: list[int]) -> None:
    """Add one evaluation row by exact elimination over the scalar field."""
    for pivot, value in enumerate(row):
        if value == 0:
            continue
        if pivot not in basis:
            inverse = pow(value, -1, P)
            basis[pivot] = [(entry * inverse) % P for entry in row]
            return
        original = basis[pivot]
        for column in range(pivot, len(row)):
            row[column] = (row[column] - value * original[column]) % P


def r1cs_rank(path: Path) -> dict:
    header = read_header(path)
    if header["field"] != P:
        raise ValueError(f"{path.name}: expected BN254 scalar field")
    public = header["public_outputs"] + header["public_inputs"]
    k = public + 1
    if not 1 <= k <= header["wires"]:
        raise ValueError(f"{path.name}: invalid public wire range")

    with path.open("rb") as file:
        offset, length = sections(file, b"r1cs", {1}, path.stat().st_size)[2]
        file.seek(offset)
        data = memoryview(file.read(length))
    if header["constraints"] > length // 12:
        raise ValueError(f"{path.name}: truncated constraints")

    basis: dict[int, list[int]] = {}
    position = 0
    for _ in range(header["constraints"]):
        for matrix in range(3):
            terms, = U32.unpack_from(data, position)
            position += U32.size
            end = position + terms * 36
            if end > length:
                raise ValueError(f"{path.name}: truncated sparse row")
            row = None
            while position < end:
                wire, = U32.unpack_from(data, position)
                coefficient = int.from_bytes(data[position + 4:position + 36], "little")
                position += 36
                if wire >= header["wires"] or coefficient >= P:
                    raise ValueError(f"{path.name}: invalid sparse row entry")
                if matrix == 0 and wire < k and coefficient and len(basis) < k:
                    if row is None:
                        row = [0] * k
                    row[wire] = (row[wire] + coefficient) % P
            if row is not None:
                insert(basis, row)
    if position != length:
        raise ValueError(f"{path.name}: constraint count does not match the binary")
    raw_rank = len(basis)

    # zkey_new.js appends A[c+i,i]=1 for the constant and each public wire.
    # B and C are zero there. The private A columns vanish on the same rows.
    for column in range(k):
        row = [0] * k
        row[column] = 1
        insert(basis, row)
    if len(basis) != k:
        raise ValueError(f"{path.name}: public QAP columns are dependent")
    return {
        "public_wires_excluding_constant": public,
        "raw_r1cs_a_public_rank": raw_rank,
        "qap_a_public_rank": len(basis),
        "qap_public_private_span_intersection_dimension": 0,
        "identity_rows": k,
        "first_identity_row": header["constraints"],
    }


def verify_zkey_padding(path: Path, result: dict) -> None:
    """Check the actual binary key's A rows against the interpolation model."""
    first = result["first_identity_row"]
    count = result["identity_rows"]
    found = set()
    with path.open("rb") as file:
        offset, length = sections(file, b"zkey", {1, 2}, path.stat().st_size)[4]
        file.seek(offset)
        terms, = U32.unpack(file.read(4))
        if length != 4 + 44 * terms:
            raise ValueError(f"{path.name}: invalid coefficient section")
        for i in range(0, terms, 16384):
            chunk = file.read(44 * min(16384, terms - i))
            for matrix, row, wire, packed in struct.iter_unpack("<III32s", chunk):
                if first <= row < first + count:
                    if matrix or row != first + wire or wire in found:
                        raise ValueError(f"{path.name}: wrong or repeated public identity coefficient")
                    if int.from_bytes(packed, "little") != MONTOGOMERY_ONE:
                        raise ValueError(f"{path.name}: public identity coefficient is not one")
                    found.add(wire)
    if found != set(range(count)):
        raise ValueError(f"{path.name}: public identity rows are incomplete")


def decimal(value: str) -> int:
    number = int(value)
    if not isinstance(value, str) or str(number) != value or not 0 <= number < Q:
        raise ValueError("Noncanonical BN254 base-field coordinate")
    return number


def g1(value: list) -> tuple[int, int]:
    x, y, z = map(decimal, value)
    if z != 1 or (y * y - x**3 - 3) % Q != 0:
        raise ValueError("Expected a nonzero affine BN254 G1 point")
    return x, y


def g2(value: list) -> tuple:
    x, y, z = (tuple(map(decimal, coordinate)) for coordinate in value)
    if len(x) != 2 or len(y) != 2 or z != (1, 0):
        raise ValueError("Expected a nonzero affine BN254 G2 point")
    return x, y


def verify_vkey(path: Path, public: int) -> dict:
    key = json.loads(path.read_text())
    if key["protocol"] != "groth16" or key["curve"] != "bn128" or key["nPublic"] != public:
        raise ValueError(f"{path.name}: key metadata disagrees with R1CS")
    g1(key["vk_alpha_1"])
    g2(key["vk_beta_2"])
    if g2(key["vk_gamma_2"]) == g2(key["vk_delta_2"]):
        raise ValueError(f"{path.name}: degenerate gamma and delta")
    points = [g1(point) for point in key["IC"]]
    if len(points) != public + 1 or len(set(points)) != len(points):
        raise ValueError(f"{path.name}: incorrect or repeated public key coefficients")
    return {"vkey_sha256": sha256(path), "gamma_differs_from_delta": True,
            "alpha_and_beta_nonzero": True, "distinct_ic_points": len(points)}


def audit(build: Path, keys: Path, zkeys: Path | None) -> dict:
    manifest = json.loads((build / "compiled_circuits_manifest.json").read_text())
    names = set(manifest["circuits"])
    if len(names) != 22 or names - BENCHMARKS != {
        path.stem.removesuffix("_vkey") for path in keys.glob("*_vkey.json")
    }:
        raise ValueError("The 22-mains and 20-key inventories disagree")
    output = {}
    for name in sorted(names - BENCHMARKS):
        row = manifest["circuits"][name]
        r1cs = build / name / f"{name}.r1cs"
        digest = sha256(r1cs)
        if digest != row["r1cs_sha256"]:
            raise ValueError(f"{name}: R1CS hash differs from build manifest")
        report = r1cs_rank(r1cs)
        report["r1cs_sha256"] = digest
        public = report["public_wires_excluding_constant"]
        if public != len(row["public_input_names"]) + len(row["public_output_names"]):
            raise ValueError(f"{name}: public wire count differs from build manifest")
        report.update(verify_vkey(keys / f"{name}_vkey.json", public))
        if zkeys is not None:
            zkey = zkeys / name / f"{name}.zkey"
            verify_zkey_padding(zkey, report)
            report["zkey_padding_verified"] = True
            report["zkey_sha256"] = sha256(zkey)
        output[name] = report
        print(f"{name}: QAP A rank {report['qap_a_public_rank']}/{public + 1}, "
              f"unaugmented A rank {report['raw_r1cs_a_public_rank']}, key checks pass", flush=True)
    count = sum(row["public_wires_excluding_constant"] for row in output.values())
    if count != 224:
        raise ValueError(f"Expected 224 public wires excluding constants, got {count}")
    return {"status": "PASS", "qap": "snarkjs 0.7.6 Groth16 padded A",
            "public_wires_excluding_constants": count, "relations": output}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--vkeys", type=Path, required=True)
    parser.add_argument("--zkeys", type=Path, help="Verify A padding in the actual binary proving keys")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    receipt = audit(args.build, args.vkeys, args.zkeys)
    with args.out.open("x") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
