"""Read the Circom R1CS binary header without scanner or log ambiguities."""

from pathlib import Path
from struct import unpack


def read_header(path: Path) -> dict:
    with path.open("rb") as source:
        if source.read(4) != b"r1cs":
            raise ValueError("bad R1CS magic")
        version, sections = unpack("<II", source.read(8))
        if version != 1:
            raise ValueError("unsupported R1CS version")
        for _ in range(sections):
            kind, length = unpack("<IQ", source.read(12))
            if kind != 1:
                source.seek(length, 1)
                continue
            width, = unpack("<I", source.read(4))
            if not 0 < width <= 128 or length != 32 + width:
                raise ValueError("invalid R1CS header")
            prime = int.from_bytes(source.read(width), "little")
            wires, outputs, inputs, private, labels, constraints = unpack("<4IQI", source.read(28))
            return {
                "field": prime, "wires": wires, "public_outputs": outputs,
                "public_inputs": inputs, "private_inputs": private,
                "labels": labels, "constraints": constraints,
            }
        raise ValueError("R1CS header missing")
