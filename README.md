# TollVeil Artifact: Streaming Zero-Knowledge Escrow for Privacy-Preserving Road-Usage Charging

This self-contained, anonymized artifact accompanies the paper *"TollVeil: Streaming Zero-Knowledge Escrow and Safe Early Releases for Privacy-Preserving Road-Usage Charging"*.

## Repository Structure

- `circuits/`: Complete Circom 2.1.9 sources for single-slot OBU streaming (`stream_slot_auth.circom`), full 396-cell Rome Bellman dual update/close (`causal/`), 64-gantry Taiwan TDCS M06A 3-class statutory corridor (`m06a/`), anchored-gap sublinear continuation (`gap/`), vertex-scaling benchmarks (`scale/`), and deterministic compiler test benches (`bench_10k.circom`, `bench_100k.circom`).
- `vkeys/`: Exported BN254 Groth16 verification keys for all compiled relations.
- `proofs/`: **329 independently verifiable real Groth16 proof/public-signal bundles** (`220` full 396-cell Rome holdout proofs + `108` Taiwan M06A freeway corridor proofs + `1` single-slot streaming proof) indexed by `proofs/manifest.json`.
- `protocol/`: Streaming SQLite CAS ledger, EdDSA-Poseidon / Ed25519 cryptography helpers, Bellman certificate builder, anchored-gap model, and Bayes-LP / stopping-time privacy engine.
- `scripts/`: End-to-end experiment runners, controlled ABBA harness, deterministic Circom wrapper, No-ZK offline/online baselines, and manuscript macro/figure/table regeneration scripts.
- `datasets/tdcs_m06a/`: Public Taiwan Freeway Bureau TDCS M06A schema, official gantry mileage tariff table (`341` gantries), and deterministic 2,000-trip evaluation slice.
- `receipts/`: Machine-verified JSON receipts backing every claim, table, and figure in the paper.
- `SHA256SUMS`: Cryptographic digest manifest over all repository artifacts.

## Quick Verification (`--fast`, ~10 seconds)

Prerequisites: `python3` (`numpy`, `matplotlib`), `node`, and `snarkjs` in `PATH`.

```bash
bash run_all_checks.sh --fast
```

This command verifies:
1. `SHA256SUMS` byte-level integrity across all packaged files.
2. Independent BN254 pairing verification (`snarkjs.groth16.verify`) of all **329** retained real Groth16 proofs (`220/220` Rome 396-cell + `108/108` Taiwan M06A + `1/1` single-slot stream).
3. Automated regeneration of all **82** receipt-bound manuscript macros, **4** vector PDF figures, and **4** `booktabs` LaTeX tables, asserting zero mismatch against `manuscript/expected_facts.json`.

## Full Deterministic Circuit Rebuild (`--full-rebuild`)

Prerequisites: `circom` (v2.1.9) and `circomlib` (`export CIRCOMLIB_DIR=/path/to/circomlib/circuits`).

```bash
bash run_all_checks.sh --full-rebuild
```

Proving keys (`.zkey`) and Powers of Tau (`.ptau`) files are intentionally excluded to keep the repository lightweight (`< 10 MB`, all files `< 50 MB`) and directly compatible with anonymous artifact hosting; they can be regenerated deterministically using `snarkjs groth16 setup`.

## Data Governance

Raw row-level CRAWDAD Rome taxi trajectories are excluded per their dataset license; see `DATA_PROVENANCE.md` for official acquisition instructions and deterministic taxi-ID 50/50 split reproduction.
