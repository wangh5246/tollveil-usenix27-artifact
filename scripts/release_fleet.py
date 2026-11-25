#!/usr/bin/env python3
"""Score cumulative release transcripts and replay the same policies on SQLite."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, replace
import json
from pathlib import Path
from random import Random
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))

from circom_crypto import FIELD_P, InfraBroadcaster, OBUKeyPair
from compile_circuits import sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from live_groth16 import LiveGroth16Verifier
from release_privacy import History, MarkovPrior, score_release_views, within_group_weights
from replay_escrow import key_registry, prove_chunk, proof_json
from unified_causal_escrow import Enrollment, Policy, UnifiedCausalEscrowLedger


ARMS = ("hold", "single_slot4_bucket", "multi_slot_bucket", "exact")


def cumulative(caps: tuple[int, ...], arm: str, width: int) -> tuple[int, ...]:
    if len(caps) != 9 or tuple(sorted(caps)) != caps or caps[0] != 0 or width <= 0:
        raise ValueError("Malformed eight-slot release caps")
    result = [0] * 9
    for k in range(1, 8):
        if arm == "hold":
            continue
        if arm == "exact":
            result[k] = caps[k]
        elif arm == "single_slot4_bucket":
            if k >= 4:
                result[k] = caps[4] // width * width
        elif arm == "multi_slot_bucket":
            result[k] = caps[k] // width * width
        else:
            raise ValueError(f"Unknown release policy {arm}")
    result[8] = caps[8]
    return tuple(result)


def policy_scores(training, testing, vertex_count: int, requested_width: int | None):
    model = MarkovPrior((item.route for item in training), vertex_count)
    train_weights = within_group_weights(training, model, 2)
    if requested_width is None:
        cap_max = max(item.caps[4] for item in training)
        eligible = []
        for width in range(1, cap_max + 2):
            values = [cumulative(item.caps, "single_slot4_bucket", width) for item in training]
            score = score_release_views(training, train_weights, [row[1:8] for row in values])
            if score["outcomes_exceeding_five_pp"] == 0:
                eligible.append((sum(row[4] for row in values), -width))
        width = -max(eligible)[1]
    else:
        width = requested_width
    weights = within_group_weights(testing, model, 2)
    return width, {arm: score_release_views(
        testing, weights, [cumulative(item.caps, arm, width)[1:8] for item in testing],
    ) for arm in ARMS}


@dataclass
class Corridor:
    name: str
    profile: int
    vertices: int
    training: list
    testing: list
    timestamps: list
    selected: list[int]
    create_witness: object
    width: int | None


def rome_corridor(historical: list[dict]) -> Corridor:
    from causal_exactness import genesis
    from causal_profile import build
    from causal_witness import Certifier, Facts, Scenario
    from phase2_compare import rome_records
    from run_g4 import rome_histories
    from run_phase6_rome import load_holdout_blocks_with_taxi

    graph = build()
    certifier = Certifier(graph)
    cal, test, _ = rome_records()
    training = rome_histories(cal, graph)
    testing = rome_histories(test, graph)
    # The stopping benchmark's last decision still has a one-opening lag.
    # The fleet terminal statement opens the final slot before settling.
    testing = [replace(item, caps=(*item.caps[:8], item.terminal[0] - item.terminal[-1]))
               for item in testing]
    blocks, _ = load_holdout_blocks_with_taxi()
    timestamps = [row["timestamps"] for row in blocks]
    choices = {row["block_idx"] for row in historical}
    selected = [i for i, row in enumerate(blocks) if row["block_idx"] in choices]
    if len(selected) != len(historical):
        raise ValueError("Rome proof-selection denominators disagree")

    def create(index, arm, width):
        item = testing[index]
        sid = secrets.randbits(128)
        scenario = Scenario(graph, OBUKeyPair(secrets.token_bytes(32)), sid,
                            item.route, tuple(blocks[index]["d_true"]))
        state = genesis(scenario, certifier)
        clock = timestamps[index]
        enrolled = Enrollment(sid, graph.tag, "fleet", scenario.entry, 0, scenario.pk_commit, state.upper,
                                state.commit(scenario.identity, 0), 0, clock[0], clock[-1] + 1)
        release = cumulative(item.caps, arm, width)

        def step(k, previous):
            close = k == 8
            opened = 255 if close else (1 << (k - 1)) - 1
            witness, next_state = scenario.fill(
                Facts(k, opened, 0, 0), previous, k-1, enrolled.deposit, 2 if close else 1, certifier,
                early=close, release_delta=release[k] - release[k-1],
            )
            return witness, next_state

        return enrolled, state, step

    return Corridor("causal", graph.tag, len(graph.cells), training, testing, timestamps, selected, create, 2000)


def m06a_corridor(source: Path, tariff: Path, historical: list[dict] | None = None,
                  cohort: tuple | None = None) -> Corridor:
    from run_phase6_m06a import M06AScenario, build_northern_corridor_and_trips, forward_dp_check, trip_clock

    if cohort is None:
        graph, rows = build_northern_corridor_and_trips(source, tariff)
        choices = {row["row_idx"] for row in historical}
        observed = list(rows)
        Random(202611247).shuffle(observed)
        test_ids = {r["row_idx"] for r in observed[:2000]}
        training_rows = [r for r in rows if r["row_idx"] not in test_ids]
        testing_rows = [r for r in rows if r["row_idx"] in test_ids]
    else:
        graph, training_rows, testing_rows, choices = cohort

    def history(row):
        path = tuple(graph["idx"][node] for node in row["gantries"])
        path += (graph["exit_id"],) * (9 - len(path))
        vehicle_class = row["veh_class"]
        pins = {}
        entry = path[0]
        bounds = [forward_dp_check(graph, vehicle_class, entry, pins, 0)]
        for k in range(1, 9):
            pins[k-1] = path[k-1:k+1]
            bounds.append(forward_dp_check(graph, vehicle_class, entry, pins, 0))
        caps = tuple(bounds[0] - val for val in bounds)
        return History(path, caps, tuple(bounds), settlement_context=(vehicle_class,))

    training, testing = [history(r) for r in training_rows], [history(r) for r in testing_rows]
    timestamps = [trip_clock(row) for row in testing_rows]
    selected = [i for i, row in enumerate(testing_rows) if row["row_idx"] in choices]
    if len(selected) != len(choices):
        raise ValueError("M06A proof-selection denominators disagree")

    def create(index, arm, width):
        row, item = testing_rows[index], testing[index]
        clock = timestamps[index]
        sid = secrets.randbits(128)
        vehicle = row["veh_class"]
        scenario = M06AScenario(graph, OBUKeyPair(secrets.token_bytes(32)), sid, vehicle, list(item.route))
        deposit = item.terminal[0]
        initial = {"mask": 0, "count": 0, "upper": deposit, "returned": 0,
                   "salt": secrets.randbelow(FIELD_P), "checkpoint": scenario.header}
        enrolled = Enrollment(sid, graph["profile_tag"], "fleet", scenario.entry, vehicle, scenario.pk_commit,
                              deposit, scenario.state_commit(0, initial), 0, clock[0], clock[-1] + 1)
        release = cumulative(item.caps, arm, width)

        def step(k, previous):
            return scenario.build_step(2 if k == 8 else 1, k-1, previous, k, (1 << k)-1, 0, 0, deposit,
                                       early=k == 8, release_delta=release[k] - release[k-1])

        return enrolled, initial, step

    # The tariff is stored in tenths of a dollar. A bucket spans one TWD.
    return Corridor("m06a", graph["profile_tag"], graph["n"], training, testing, timestamps,
                    selected, create, 10)


def prove_policy(corridor: Corridor, arm: str, width: int, args, compiled, output: Path):
    cases = []
    for index in corridor.selected:
        enroll, initial, generate = corridor.create_witness(index, arm, width)
        cases.append((index, enroll, initial, generate, corridor.timestamps[index][1:]))

    def step(case, revision, prior):
        data, state = case[3](revision + 1, prior)
        return data, state, case[4][revision], 0

    with ThreadPoolExecutor(args.jobs) as executor:
        futures = [executor.submit(prove_chunk, cases[i::args.jobs], step, corridor.name,
                                   args.build, args.keys, compiled, output, False, args.native_build)
                   for i in range(min(args.jobs, len(cases)))]
        return sorted(item for job in futures for item in job.result())


def replay_policy(corridor: Corridor, arm: str, width: int, sessions, registry, output: Path):
    registrar, broadcaster = Ed25519PrivateKey.generate(), InfraBroadcaster()
    caps = {(entry.entry, entry.vehicle_class): entry.deposit for _, entry, _ in sessions}
    events = []
    for index, entry, steps in sessions:
        events.append((entry.started_at, 0, index, entry, None))
        events.extend((step["now"], step["revision"]+1, index, entry, step) for step in steps)
    peak = peak_open = opened = mid_reused = final_reused = 0
    mid_available = final_available = 0
    mid_credit = final_credit = admissions = 0
    with tempfile.TemporaryDirectory(prefix="tollveil-fleet-") as tmp, LiveGroth16Verifier(registry) as verifier:
        ledger = UnifiedCausalEscrowLedger(Path(tmp) / "fleet.db", verifier,
            {corridor.profile: Policy(corridor.name, 8, caps)}, registrar.public_key(), broadcaster.pubkey_hex)
        ledger.install_bulletin(broadcaster.publish_broadcast(corridor.profile, 0, 0))
        ledger.fund("fleet", 0)
        for _, _, index, enrollment, step in sorted(events, key=lambda event: event[:3]):
            if step is None:
                from_mid = min(enrollment.deposit, mid_available)
                from_final = min(enrollment.deposit - from_mid, final_available)
                mid_reused += from_mid
                final_reused += from_final
                mid_available -= from_mid
                final_available -= from_final
                top_up = enrollment.deposit - from_mid - from_final
                if top_up:
                    ledger.fund("fleet", top_up)
                ledger.register(enrollment, registrar.sign(enrollment.signed_message()))
                opened += 1
            else:
                proof = proof_json(step["proof_path"])
                call = {"sid": enrollment.sid, "revision": step["revision"], "now": step["now"],
                        "proof": proof, "refund_delta": step["refund_delta"]}
                release = cumulative(corridor.testing[index].caps, arm, width)
                k = step["revision"] + 1
                if step["refund_delta"] != release[k] - release[k-1]:
                    raise ValueError("Fleet release differs from the scored cumulative vector")
                if step["close"]:
                    result = ledger.admit_close(charge=step["charge"], **call)
                    final_available += result["refund_delta"]
                    final_credit += result["refund_delta"]
                    opened -= 1
                else:
                    result = ledger.admit_update(next_state=step["next_state"], **call)
                    mid_available += result["refund_delta"]
                    mid_credit += result["refund_delta"]
                admissions += 1
            account = ledger.account("fleet")
            if account["available"] != mid_available + final_available:
                raise ValueError("Reuse attribution disagrees with the ledger")
            peak = max(peak, account["locked"])
            peak_open = max(peak_open, opened)
        final = ledger.snapshot()
        assert all(s["closed"] and s["returned"] + s["charged"] == s["deposit"] for s in final["sessions"])
        assert opened == final["accounts"][0]["locked"] == 0
        assert admissions == len(final["admissions"]) == 8 * len(sessions)
    return {"settled_sessions": len(sessions), "precommit_verified_transitions": admissions,
            "peak_open_sessions": peak_open, "peak_locked_escrow": peak,
            "midtrip_credits_total": mid_credit, "final_refund_credits_total": final_credit,
            "midtrip_credits_reused": mid_reused, "final_credits_reused": final_reused,
            "externally_funded": final["accounts"][0]["funded"], "conservation_errors": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, choices=("rome", "m06a"))
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--historical-cohort", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-sha256")
    parser.add_argument("--tariff", type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--native-build", type=Path)
    parser.add_argument("--time-split", action="store_true")
    args = parser.parse_args()
    args.build, args.keys, args.out = (p.resolve() for p in (args.build, args.keys, args.out))
    if args.native_build:
        args.native_build = args.native_build.resolve()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    historical = json.loads(args.historical_cohort.read_text())["sessions"] if args.historical_cohort else None
    if args.suite == "rome":
        if historical is None:
            parser.error("Rome requires its proof-selection manifest")
        corridor = rome_corridor(historical)
    else:
        if args.time_split:
            from m06a_cohort import select

            if not all((args.source, args.tariff)):
                parser.error("--time-split requires the pinned source and tariff")
            graph, calibration, test, selected, _ = select(args.source, args.tariff)
            cohort = graph, calibration, test, {row["row_idx"] for row in selected}
            corridor = m06a_corridor(args.source, args.tariff, cohort=cohort)
        else:
            if not all((historical, args.source, args.source_sha256, args.tariff)) or sha256(args.source) != args.source_sha256:
                parser.error("M06A requires the pinned local source file, historical cohort, and tariff")
            corridor = m06a_corridor(args.source, args.tariff, historical)
    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be positive")
        corridor.selected = corridor.selected[:args.limit]
    if any(len(clock) != 9 or clock[0] == clock[-1] or tuple(sorted(clock)) != clock
           for clock in corridor.timestamps):
        raise ValueError("A cohort has invalid replay timestamps")
    record = {"suite": args.suite, "scope": "timestamp-aligned recorded cohort with synthetic credentials",
              "smoke": args.limit is not None, "scored_cases": len(corridor.testing),
              "witness_backend": "native" if args.native_build is not None else "wasm",
              "chronological_m06a_holdout": args.suite == "m06a" and args.time_split}
    width, metrics = policy_scores(corridor.training, corridor.testing, corridor.vertices, corridor.width)
    _, sample_metrics = policy_scores(corridor.training, [corridor.testing[i] for i in corridor.selected],
                                      corridor.vertices, width)
    record.update({"bucket_units": width, "privacy": metrics, "selected_case_privacy": sample_metrics})
    manifest = args.build / "compiled_circuits_manifest.json"
    compiled = json.loads(manifest.read_text())["circuits"]
    setup = json.loads((args.keys / "phase2_setup_manifest.json").read_text())
    if setup["compiler_build_manifest_sha256"] != sha256(manifest):
        raise ValueError("Wrong proving setup for replay build")
    names = {f"{corridor.name}_{suffix}" for suffix in ("update", "close")}
    registry = key_registry(args.keys, compiled, setup, names)
    args.out.mkdir()
    (args.out / "privacy.json").write_text(json.dumps(record, indent=2) + "\n")
    record["fleet"] = {}
    for arm in ARMS:
        output = args.out / arm
        output.mkdir()
        sessions = prove_policy(corridor, arm, width, args, compiled, output)
        result = replay_policy(corridor, arm, width, sessions, registry, output)
        record["fleet"][arm] = result
        (output / "fleet.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"{args.suite} {arm}: {result['precommit_verified_transitions']} admissions, "
              f"peak {result['peak_locked_escrow']} over {result['peak_open_sessions']} simultaneous trips", flush=True)
    hold = record["fleet"]["hold"]["peak_locked_escrow"]
    for result in record["fleet"].values():
        result["peak_reduction_from_hold"] = 1 - result["peak_locked_escrow"] / hold
    (args.out / "release_fleet.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
