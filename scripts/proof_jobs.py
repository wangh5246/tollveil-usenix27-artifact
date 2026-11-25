"""Run the compiled witness calculator and Groth16 prover for one relation."""

import json
from pathlib import Path
import subprocess
import tempfile
from time import perf_counter

from potential_certificate import field_input


class ProofJob:
    def __init__(self, name: str, build: Path, keys: Path, public: list[str],
                 *, node: str = "node", prover: str = "rapidsnark",
                 native_witness: Path | None = None) -> None:
        self.public = public
        self.prover = prover
        self.zkey = keys / name / f"{name}.zkey"
        self.vkey = keys / name / f"{name}_vkey.json"
        self.js = build / name / f"{name}_js"
        self.node = node
        self.name = name
        self.native_witness = native_witness
        self.worker = None

    def __enter__(self):
        if self.native_witness is not None:
            if not self.native_witness.is_file():
                raise FileNotFoundError(self.native_witness)
            return self
        scripts = Path(__file__).resolve().parent
        self.worker = subprocess.Popen(
            [self.node, scripts / "batch_gen_witness.cjs", self.js / "witness_calculator.js",
             self.js / f"{self.name}.wasm"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        return self

    def __exit__(self, *_):
        if self.worker is None:
            return
        try:
            self.worker.stdin.close()
            self.worker.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.worker.kill()
            self.worker.wait()
        finally:
            self.worker.stdout.close()

    def prove(self, inputs: dict, output: Path, proof_id: str) -> tuple[dict, dict]:
        proof_path = output / f"{proof_id}_proof.json"
        public_path = output / f"{proof_id}_public.json"
        if proof_path.exists() or public_path.exists():
            raise FileExistsError(f"Duplicate output for {proof_id}")
        with tempfile.TemporaryDirectory(prefix="tollveil-witness-") as directory:
            wtns = Path(directory) / "witness.wtns"
            if self.native_witness is None:
                request = json.dumps({"input": field_input(inputs), "wtns_path": str(wtns)})
                self.worker.stdin.write(request + "\n")
                self.worker.stdin.flush()
                line = self.worker.stdout.readline()
                if not line:
                    raise RuntimeError(f"{self.name}: witness generator stopped")
                witness = json.loads(line)
                if not witness["ok"]:
                    raise RuntimeError(f"{self.name}: witness generator failed: {witness['error']}")
                witness_ms = witness["witness_ms"]
            else:
                input_path = Path(directory) / "input.json"
                input_path.write_text(json.dumps(field_input(inputs)))
                start = perf_counter()
                subprocess.run([self.native_witness, input_path, wtns], capture_output=True, check=True, timeout=120)
                witness_ms = (perf_counter() - start) * 1000
            start = perf_counter()
            subprocess.run([self.prover, self.zkey, wtns, proof_path, public_path],
                           capture_output=True, check=True, timeout=120)
            prove_ms = (perf_counter() - start) * 1000
        values = json.loads(public_path.read_text())
        if values != [str(inputs[field]) for field in self.public]:
            raise ValueError(f"{self.name}: public inputs differ from the compiled wire order")
        record = {
            "id": proof_id, "vkey": str(self.vkey), "proof_path": str(proof_path),
            "public_path": str(public_path),
        }
        timing = {
            "witness_ms": round(witness_ms, 3), "prove_ms": round(prove_ms, 3),
            "serialized_proof_public_bytes": proof_path.stat().st_size + public_path.stat().st_size,
        }
        return record, timing
