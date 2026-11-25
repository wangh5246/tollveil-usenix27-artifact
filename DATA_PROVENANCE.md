# Dataset Provenance and Acquisition

## 1. CRAWDAD Rome Taxi Dataset (Restricted Raw Input)
- **Citation:** L. Bracciale et al., *CRAWDAD dataset roma/taxi (v. 2014-07-17)*, DOI: `10.15783/C7QC7M`.
- **Policy:** Row-level raw GPS traces are governed by the CRAWDAD / IEEE DataPort access terms and are **not redistributed** in this artifact.
- **Reproduction:** Obtain the dataset from IEEE DataPort (`https://ieee-dataport.org/open-access/crawdad-romataxi`), place the preprocessed 8-slot blocks locally, and run `scripts/run_phase6_rome.py`. The driver-disjoint 50/50 split ranks unique taxi IDs by `SHA256("tollveil-v15/rome/split/v1/" + taxi_id)` (10 calibration taxis / 476 blocks; 10 unseen holdout taxis / 337 blocks; 0 overlap). All 220 de-identified public Groth16 proof bundles and verification keys are included in `proofs/rome396/` for immediate verification without requiring the raw GPS dataset.

## 2. Taiwan Freeway Bureau TDCS M06A (Open Government Data)
- **Source:** Taiwan Ministry of Transportation and Communications, Freeway Bureau, Open Government Data Dataset 37760 (`https://data.gov.tw/dataset/37760`), hourly archive `TDCS_M06A_20190830_080000.csv` (`SHA256: 9c3049209e2fac750636c6bf6245e4f19b71efaba15b0676a86d98b256bf5193`) and official gantry mileage tariff tables (`341` gantries, `tw_freeway_gantry_tariff_parsed.json`).
- **Included:** Public schema, official parsed gantry tariff table, deterministic 2,000-trip evaluation slice (`tdcs_m06a_20190830_080000_eval_2000.csv`), and all 108 verified Groth16 proof bundles in `proofs/m06a/`.
