#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---fast}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== TollVeil Artifact Verification (mode: ${MODE}) ==="

if [[ "$MODE" == "--fast" ]]; then
  python3 scripts/verify_cleanroom.py
elif [[ "$MODE" == "--full-rebuild" ]]; then
  echo "[1/3] Running fast integrity, Groth16 verification, and manuscript asset regeneration..."
  python3 scripts/verify_cleanroom.py
  echo "[2/3] Checking deterministic 3x Circom compilation on bench_10k.circom..."
  if ! command -v circom >/dev/null 2>&1; then
    echo "ERROR: circom binary not found in PATH for --full-rebuild." >&2
    exit 1
  fi
  TMP_BUILD="$(mktemp -d)"
  trap 'rm -rf "$TMP_BUILD"' EXIT
  CIRCOM_LIB="${CIRCOMLIB_DIR:-}"
  LIB_FLAG=()
  if [[ -n "$CIRCOM_LIB" ]]; then
    LIB_FLAG=(-l "$CIRCOM_LIB")
  fi
  HASHES=()
  for t in 1 2 3; do
    mkdir -p "$TMP_BUILD/t$t"
    RAYON_NUM_THREADS=1 LC_ALL=C LANG=C TZ=UTC circom circuits/bench_10k.circom --r1cs --wasm --O1 --prime bn128 "${LIB_FLAG[@]}" -o "$TMP_BUILD/t$t" >/dev/null
    H="$(shasum -a 256 "$TMP_BUILD/t$t/bench_10k.r1cs" | awk '{print $1}')"
    HASHES+=("$H")
    echo "  Trial $t R1CS SHA-256: $H"
  done
  if [[ "${HASHES[0]}" != "${HASHES[1]}" || "${HASHES[1]}" != "${HASHES[2]}" ]]; then
    echo "ERROR: Non-deterministic Circom compilation detected!" >&2
    exit 1
  fi
  echo "[3/3] Deterministic 3/3 Circom compilation verified byte-identical."
else
  echo "Usage: bash run_all_checks.sh [--fast | --full-rebuild]" >&2
  exit 2
fi
