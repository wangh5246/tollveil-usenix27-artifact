# Data and reproducibility

## Rome

Use a copy acquired under the provider terms. The CRAWDAD record is [Bracciale et al., roma/taxi v. 2014-07-17](https://doi.org/10.15783/C7QC7M). Cite the contributors. The raw plaintext and frozen prepared SHA-256 values live in [source_pins.json](datasets/rome/source_pins.json).

```bash
python scripts/rome_preprocess.py \
    --raw "$ROME_SOURCE" --out /tmp/rome-cohort.json \
    --local-prepared "$ROME_LOCAL/prepared.jsonl" \
    --local-summary "$ROME_LOCAL/eligible.jsonl" \
    --local-selection "$ROME_LOCAL/selection.json"
```

Use a restricted local directory for all three row-level outputs. The importer streams semicolon-delimited GPS fixes, uses the embedded time-zone offset, cuts per-taxi segments when adjacent fixes are separated by more than 120 seconds and emits non-overlapping ten-fix blocks in the order the segments are closed by the input. It projects axes in metres, recenters each block's bounding box and quantizes to 100 m. The coefficients reproduce the frozen file exactly. The shifted and quantized shape is evaluated over a representative 500 m-cell Rome road-cost graph. This is a replay of projected route shapes and recorded times. It does not measure location accuracy or actual road-bill agreement.

Of the first 1,000 historical blocks, 142 are stationary at the evaluation scale and 2 are disconnected. The script applies the published hash order to split the 21 eligible taxi IDs into disjoint groups of 10, 10 and 1 (476, 337 and 43 blocks). The stratified proof selection reproduces 55 holdout blocks. The public HMAC commitments permit count, disjointness and subset checks. Keep the optional 32-byte reproduction key local to make those commitments repeatable under the same authorized inputs.

The packaged Rome road-cost matrix is reproducible from the pinned OSM PBF with `scripts/rome_graph.py` using Pyrosm 0.8.0, NumPy 1.26.4 and SciPy 1.16.2. Map data © [OpenStreetMap contributors](https://www.openstreetmap.org/copyright) under the Open Database License. Graph construction consumes OpenStreetMap topology.

## Taiwan

Source: [Freeway Bureau TDCS M06A](https://data.gov.tw/dataset/37760). The [archive and tariff pins](datasets/tdcs_m06a/source_pins.json) include the provider endpoint and hash-checked archive mirrors. The reproduced input is the hour starting at 08:00 on 2019-08-30, Asia/Taipei. The repository supplies the schema and the 2024/25 archived gantry rate table. Trip files remain local.

```bash
python scripts/run_phase6_m06a.py --verify-cohort \
    --source "$M06A_HOUR" --receipt /tmp/m06a-holdout.json \
    --expect receipts/v15_1/m06a_cohort.json
```

The first detection time assigns records to disjoint half-hour windows. Build the northern southbound directed graph using 08:00–08:30 observations. Rank test-window records from 08:30–09:00 by SHA-256 after requiring compatibility with that graph. Exactly 2,000 trip rows match the frozen selector and 36 are selected by class for the proof run. Optional `--local-csv` writes the selected bytes in source order. Store these rows outside this tree. The rate replay matches the sum of the supplied list prices and reports a separate per-trip diagnostic with a fresh allowance. Daily per-vehicle billing and bank reconciliation are outside the replay.

## Evidence scopes

Rome and M06A use simulated session keys, trusted enrollment and signed checkpoint or bulletin fixtures. The measured replays use archived route inputs. Proofs contain randomized commitments and public policy fields. The gap close, stop-solver sanity, network and LP cases are synthetic. The network numbers describe the stated Monte Carlo delay models. The two fleet experiments process each selected event in timestamp order inside a local escrow ledger.
