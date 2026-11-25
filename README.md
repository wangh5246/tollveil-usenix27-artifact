# TollVeil artifact v15.1

Snapshot identifier: `corridor-escrow-20261125`. The manuscript and its source are at `TollVeil.pdf` and `manuscript_source/`. The exact release files are indexed by `SHA256SUMS`. The PDF hash and build, key and proof inventory hashes are pinned in `receipts/gate_G7.json`.

## Verify the snapshot

Use Python 3.12, Node 22 or later, and Bash 3.2 or later. The full check also uses Circom 2.1.9 in `PATH`. Python and Node packages are version-pinned. Run these commands from the snapshot root.

```bash
python3.12 -m venv /tmp/tollveil-verify-env
/tmp/tollveil-verify-env/bin/python -m pip install -r requirements.txt
npm ci --ignore-scripts
export PYTHON=/tmp/tollveil-verify-env/bin/python
export PATH="$PWD/node_modules/.bin:$PATH"
/bin/bash run_all_checks.sh --fast
/bin/bash run_all_checks.sh --full-rebuild
```

Fast mode checks payload hashes, eight gate receipts, Groth16 pairings for the complete public proof inventory and deterministic regeneration of manuscript facts, tables and figures. Full mode adds 22 source builds with exact R1CS and WASM hashes, the public-column checks on all 20 compiled application QAPs, 2,000 locally reconstructed Taiwan holdout trips, and the exact synthetic and transport-model receipts. Set `TOLLVEIL_M06A_ARCHIVE` to a local copy of the pinned hourly file to replace the fetch. Set `TOLLVEIL_ROME_RAW` to a provider-authorized Rome text file or archive to add an optional byte-exact test of the 1,000 historical prepared blocks and the 856/55 derived cohorts.

The shipped ceremony receipts and full `zkey verify` logs bind the 20 key setups to their respective circuits. The local proving binaries and Powers of Tau are absent from the public payload. A new proof run uses separately generated proving keys and will have a new setup lineage. The QAP audit uses the public input rows appended by snarkjs. The release setup shares Phase-1 parameters, fixes the snarkjs gamma generator and has per-relation Phase-2 delta contributions.

## Local experiments

The source directory includes the precommit SQLite proof guard, timestamp-aligned fleet runner, stopping simulation, private-predecessor witness code, and matched signed baseline benchmark. Local archive acquisition, data pins and example preprocessing commands are in [DATA_PROVENANCE.md](DATA_PROVENANCE.md). Run `python scripts/replay_escrow.py --help` for the proof-gated runner or `python scripts/release_fleet.py --help` for the fleet comparison. These commands require locally generated proving material and the registered relation manifest. The public proof payload ships only proof and public signal pairs. Class, entry, time and admission metadata have the disclosure boundaries described in the manuscript.

The bundled Circomlib 2.0.5 source retains its upstream GPL-3.0 terms and copyright notice under [third_party/circomlib](third_party/circomlib).
