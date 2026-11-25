"""Synchronous client for the pinned, in-memory Groth16 verifier."""

import json
from pathlib import Path
from select import select
import shutil
import subprocess
import tempfile
from threading import Lock


class LiveGroth16Verifier:
    def __init__(self, registry: dict, *, timeout: float = 15.0) -> None:
        self.registry = registry
        self.timeout = timeout
        self._call_lock = Lock()
        self._request_id = 0

    def __enter__(self):
        cli = shutil.which("snarkjs")
        if cli is None:
            raise RuntimeError("snarkjs executable is unavailable")
        script = Path(__file__).resolve().parents[1] / "scripts/live_groth16_verifier_daemon.cjs"
        with tempfile.TemporaryDirectory(prefix="tollveil-verifier-") as directory:
            file = Path(directory) / "registry.json"
            file.write_text(json.dumps(self.registry))
            self._worker = subprocess.Popen(
                ["node", script, cli, file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            )
            try:
                ready = self._read()
                if ready != {"ready": True, "relations": sorted(self.registry)}:
                    raise ValueError("Groth16 verifier rejected its key registry")
            except BaseException:
                self.__exit__()
                raise
        return self

    def _read(self) -> dict:
        readable, _, _ = select([self._worker.stdout], [], [], self.timeout)
        if not readable:
            raise TimeoutError("Groth16 verifier did not respond")
        line = self._worker.stdout.readline()
        if not line:
            raise RuntimeError("Groth16 verifier exited")
        return json.loads(line)

    def verify(self, relation: str, public: tuple[str, ...], proof: dict) -> float:
        with self._call_lock:
            self._request_id += 1
            request = json.dumps(
                {"id": self._request_id, "relation": relation, "public": public, "proof": proof},
                separators=(",", ":"),
            )
            if len(request) > 32 * 1024:
                raise ValueError("Proof message is too large")
            self._worker.stdin.write(request + "\n")
            self._worker.stdin.flush()
            try:
                response = self._read()
            except BaseException:
                # A delayed response cannot be associated with the next transaction.
                self._worker.kill()
                raise
            if response.get("id") != self._request_id or response.get("verified") is not True:
                raise ValueError("Groth16 proof rejected")
            elapsed = response["pairing_ms"]
            if not isinstance(elapsed, (float, int)) or elapsed < 0:
                raise ValueError("Malformed Groth16 verifier response")
            return float(elapsed)

    def __exit__(self, *_):
        try:
            self._worker.stdin.close()
            self._worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._worker.kill()
            self._worker.wait()
        finally:
            self._worker.stdout.close()
