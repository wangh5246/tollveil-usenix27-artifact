#!/usr/bin/env python3
"""Run proof-gated Rome, M06A, or gap escrow replays with signed fixtures."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import secrets
import sys
import tempfile
from threading import Barrier
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "protocol"))

from circom_crypto import FIELD_P, InfraBroadcaster, OBUKeyPair
from compile_circuits import sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from live_groth16 import LiveGroth16Verifier
from proof_jobs import ProofJob
from unified_causal_escrow import Enrollment, Policy, UnifiedCausalEscrowLedger


def key_registry(keys: Path, compiled: dict, setup: dict, names: set[str]) -> dict:
    registry = {}
    for name in names:
        row = setup["relations"][name]
        circuit = compiled[name]
        if row["r1cs_sha256"] != circuit["r1cs_sha256"] or row["zkey_verify_exit"] != 0:
            raise ValueError(f"{name}: key was not verified against the selected build")
        key = keys / name / f"{name}_vkey.json"
        registry[name] = {
            "path": str(key), "sha256": row["vkey_sha256"],
            "n_public": len(circuit["public_input_names"]) + len(circuit["public_output_names"]),
        }
    return registry


def open_job(stack: ExitStack, name: str, build: Path, keys: Path, compiled: dict,
             native_build: Path | None = None) -> ProofJob:
    column = compiled[name]
    return stack.enter_context(ProofJob(
        name, build, keys, column["public_output_names"] + column["public_input_names"],
        native_witness=native_build / f"{name}_cpp" / name if native_build is not None else None,
    ))


def rome_cases(historical: list[dict]):
    from causal_exactness import genesis
    from causal_profile import build
    from causal_witness import Certifier, Facts, Scenario
    from run_phase6_rome import load_holdout_blocks_with_taxi

    graph = build()
    certifier = Certifier(graph)
    positions = {cell: i for i, cell in enumerate(graph.cells)}
    block_rows, _ = load_holdout_blocks_with_taxi()
    by_block = {record["block_idx"]: record for record in block_rows}
    cases, caps = [], {}
    for index, selected in enumerate(historical):
        block = by_block[selected["block_idx"]]
        if len(block["raw_cells"]) != 9 or len(block["d_true"]) != 8:
            raise ValueError("Rome holdout block has the wrong cardinality")
        route = tuple(positions[cell] for cell in block["raw_cells"])
        scenario = Scenario(graph, OBUKeyPair(secrets.token_bytes(32)), secrets.randbits(128),
                            route, tuple(block["d_true"]))
        initial = genesis(scenario, certifier)
        caps[(scenario.entry, 0)] = initial.upper
        enrolled = Enrollment(scenario.sid, graph.tag, "fleet", scenario.entry, 0, scenario.pk_commit,
                              initial.upper, initial.commit(scenario.identity, 0), index + 1, index, index + 50)
        counts = [(10, Facts(2, 1, 0, 0)), (20, Facts(4, 3, 0, 0)), (30, Facts(6, 7, 0, 0))]
        if selected["fault_scenario"]:
            counts.append((55, Facts(8, 63, 64, 192)))
        else:
            counts.append((48 if index == 0 else 55, Facts(8, 255, 0, 0)))
        cases.append((index, enrolled, initial, scenario, counts))

    def step(case, revision, previous):
        _, enrollment, _, scenario, phases = case
        delay, facts = phases[revision]
        closing = revision == len(phases) - 1
        now = enrollment.started_at + delay
        data, successor = scenario.fill(facts, previous, revision, enrollment.deposit,
                                        2 if closing else 1, certifier, early=closing and now < enrollment.closes_at)
        return data, successor, now, facts.infra

    return graph.tag, Policy("causal", 8, caps), cases, step


def m06a_cases(historical: list[dict], source: Path, tariff: Path, cohort=None):
    from run_phase6_m06a import M06AScenario, build_northern_corridor_and_trips, forward_dp_check

    graph, trips = build_northern_corridor_and_trips(source, tariff) if cohort is None else cohort
    by_row = {record["row_idx"]: record for record in trips}
    cases, caps = [], {}
    for index, selected in enumerate(historical):
        trip = by_row[selected["row_idx"]]
        route = [graph["idx"][node] for node in trip["gantries"]]
        vehicle_class = trip["veh_class"]
        scenario = M06AScenario(graph, OBUKeyPair(secrets.token_bytes(32)), secrets.randbits(128),
                                vehicle_class, route)
        cap = forward_dp_check(graph, vehicle_class, route[0], {}, 0)
        caps[(scenario.entry, vehicle_class)] = cap
        initial = {"mask": 0, "count": 0, "upper": cap, "returned": 0,
                   "salt": secrets.randbelow(FIELD_P), "checkpoint": scenario.header}
        enrolled = Enrollment(scenario.sid, graph["profile_tag"], "fleet", scenario.entry, vehicle_class,
                              scenario.pk_commit, cap, scenario.state_commit(0, initial),
                              index + 1, index, index + 50)
        phases = [(10, 2, 3, 0, 0), (25, 5, 31, 0, 0), (48 if index == 0 else 55, 8, 255, 0, 0)]
        if selected["fault_waiver_trip"]:
            phases = [(10, 2, 3, 0, 0), (25, 5, 19, 12, 0), (55, 8, 243, 12, 4)]
        cases.append((index, enrolled, initial, scenario, phases))

    def step(case, revision, previous):
        _, enrollment, _, scenario, phases = case
        delay, count, opens, fault, mask = phases[revision]
        closing = revision == len(phases) - 1
        now = enrollment.started_at + delay
        data, successor = scenario.build_step(2 if closing else 1, revision, previous, count, opens,
                                              fault, mask, enrollment.deposit,
                                              early=closing and now < enrollment.closes_at)
        return data, successor, now, mask

    return graph["profile_tag"], Policy("m06a", 8, caps), cases, step


def prove_chunk(cases: list, step, family: str, build: Path, keys: Path, compiled: dict, out: Path,
                include_retry: bool = True, native_build: Path | None = None):
    results = []
    with ExitStack() as stack:
        jobs = {suffix: open_job(stack, f"{family}_{suffix}", build, keys, compiled, native_build)
                for suffix in ("update", "close")}
        for case in cases:
            index, enrollment, previous, _, phases = case
            steps = []
            for revision in range(len(phases)):
                before = perf_counter()
                data, previous, now, mask = step(case, revision, previous)
                preparation = (perf_counter() - before) * 1000
                suffix = "close" if data["relTag"] == 2 else "update"
                proof_id = f"{family}_{index:02d}_r{revision}_{suffix}"
                proof, timing = jobs[suffix].prove(data, out, proof_id)
                steps.append({
                    **proof, **timing, "preparation_ms": preparation, "close": suffix == "close",
                    "now": now, "mask": mask, "early": suffix == "close" and now < enrollment.closes_at,
                    "revision": revision, "next_state": data["nextState"],
                    "refund_delta": data["refundDelta"], "charge": data["charge"],
                })
                if suffix == "close" and index == 0 and include_retry:
                    retry, _ = jobs[suffix].prove(data, out, f"{proof_id}_retry")
                    steps[-1]["second_proof_path"] = retry["proof_path"]
            results.append((index, enrollment, steps))
            print(f"{family}: generated session {index + 1}", flush=True)
    return results


def unchanged_on_rejection(ledger, action) -> bool:
    before = ledger.snapshot()
    try:
        action()
    except ValueError:
        if ledger.snapshot() != before:
            raise RuntimeError("Rejected transition changed persisted escrow state")
        return True
    raise RuntimeError("Negative control was accepted")


def proof_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


def admit(ledger, enrollment: Enrollment, step: dict, proof: dict, *, now=None):
    args = {"sid": enrollment.sid, "revision": step["revision"], "refund_delta": step["refund_delta"],
            "now": now if now is not None else step["now"], "proof": proof}
    if step["close"]:
        return ledger.admit_close(charge=step["charge"], **args)
    return ledger.admit_update(next_state=step["next_state"], **args)


def admit_corridor(ledger, sessions, registrar, broadcaster) -> dict:
    ledger.fund("fleet", 0)
    events = []
    for index, enrollment, steps in sessions:
        ledger.install_bulletin(broadcaster.publish_broadcast(enrollment.profile, enrollment.epoch, steps[-1]["mask"]))
        events.append((enrollment.started_at, 0, index, enrollment, None))
        events.extend((step["now"], step["revision"] + 1, index, enrollment, step) for step in steps)
    negatives, records = {}, []
    peak_locked, reused = 0, 0
    for _, _, index, enrollment, step in sorted(events, key=lambda event: event[:3]):
        if step is None:
            if index == 0 and enrollment.deposit:
                inadequate = replace(enrollment, deposit=enrollment.deposit - 1)
                negatives["insufficient_deposit"] = unchanged_on_rejection(
                    ledger, lambda: ledger.register(inadequate, registrar.sign(inadequate.signed_message())),
                )
            available = ledger.account("fleet")["available"]
            reused += min(available, enrollment.deposit)
            if available < enrollment.deposit:
                ledger.fund("fleet", enrollment.deposit - available)
            ledger.register(enrollment, registrar.sign(enrollment.signed_message()))
        else:
            proof = proof_json(step["proof_path"])
            if index == 0 and step["revision"] == 0:
                altered = deepcopy(proof)
                altered["pi_a"][0] = str(int(altered["pi_a"][0]) + 1)
                negatives["altered_proof"] = unchanged_on_rejection(ledger, lambda: admit(ledger, enrollment, step, altered))
                different_key = proof_json(sessions[0][2][-1]["proof_path"])
                negatives["wrong_relation_key"] = unchanged_on_rejection(
                    ledger, lambda: admit(ledger, enrollment, step, different_key),
                )
                unauthorized = InfraBroadcaster().publish_broadcast(enrollment.profile, enrollment.epoch, 1)
                negatives["unauthorized_bulletin"] = unchanged_on_rejection(
                    ledger, lambda: ledger.install_bulletin(unauthorized),
                )
            if step["close"] and step["mask"] and "illegal_early_close" not in negatives:
                negatives["illegal_early_close"] = unchanged_on_rejection(
                    ledger, lambda: admit(ledger, enrollment, step, proof, now=enrollment.closes_at - 1),
                )
            if step.get("second_proof_path"):
                retry = proof_json(step["second_proof_path"])
                if proof == retry:
                    raise ValueError("The independently generated proof did not change")
                before = ledger.account("fleet")
                barrier = Barrier(2)

                def submit(candidate):
                    barrier.wait(timeout=10)
                    return admit(ledger, enrollment, step, candidate)

                with ThreadPoolExecutor(2) as pool:
                    receipt, duplicate = list(pool.map(submit, (proof, retry)))
                after = ledger.account("fleet")
                if duplicate != receipt or after["available"] - before["available"] != step["refund_delta"]:
                    raise RuntimeError("Concurrent close made a duplicate credit")
                negatives["concurrent_close"] = True
                snapshot = ledger.snapshot()
                if admit(ledger, enrollment, step, retry) != receipt or snapshot != ledger.snapshot():
                    raise RuntimeError("Retry did not return the original receipt")
                negatives["idempotent_new_proof"] = True
            else:
                receipt = admit(ledger, enrollment, step, proof)
            records.append({
                "id": step["id"], "relation": receipt["relation"], "early": step["early"],
                "proof_sha256": sha256(Path(step["proof_path"])), "public_sha256": sha256(Path(step["public_path"])),
                "statement_sha256": receipt["statement_sha256"], "refund_delta": receipt["refund_delta"],
                "admitted_proof_sha256": receipt["admitted_proof_sha256"],
                "charge": receipt["charged"], "remaining": receipt["remaining"],
                **{name: step[name] for name in ("preparation_ms", "witness_ms", "prove_ms", "serialized_proof_public_bytes")},
                "pairing_ms": receipt["pairing_ms"], "precommit_ms": receipt["precommit_ms"],
            })
        peak_locked = max(peak_locked, ledger.account("fleet")["locked"])
    snapshot = ledger.snapshot()
    for row in snapshot["sessions"]:
        if not row["closed"] or row["returned"] + row["charged"] != row["deposit"]:
            raise ValueError("A closed session violates conservation")
    if len(snapshot["admissions"]) != len(records) or snapshot["accounts"][0]["locked"]:
        raise RuntimeError("Missing admission or undisposed escrow")
    return {"sessions": len(sessions), "admissions": len(records), "negatives": negatives, "proofs": records,
            "peak_locked": peak_locked, "credited_margin_used_on_enrollment": reused,
            "final_account": snapshot["accounts"][0], "conservation_errors": 0}


def replay_gap(args, compiled, setup) -> dict:
    from gap_witness import ClosePair, Pair

    pair = Pair(16, secrets.randbits(128))
    closing = ClosePair.from_local_update(pair, infra=1, fault=1)
    update, certificate, close = pair.input(True), closing.input(2), closing.input(0)
    registrar, broadcaster = Ed25519PrivateKey.generate(), InfraBroadcaster()
    enrollment = Enrollment(pair.sid, pair.policy, "fleet", 0, 0, update["pkCommit"], update["deposit"],
                            update["oldRoot"], 1, 0, 10)
    jobs = {"gap_local_16": update, "gap_close_raw": certificate, "gap_close_digest": close}
    registry = key_registry(args.keys, compiled, setup, set(jobs))
    proofs, times = {}, {}
    with ExitStack() as stack:
        for name, witness in jobs.items():
            runner = open_job(stack, name, args.build, args.keys, compiled)
            proof, times[name] = runner.prove(witness, args.out, name)
            proofs[name] = proof
        verifier = stack.enter_context(LiveGroth16Verifier(registry))
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="tollveil-gap-ledger-")))
        ledger = UnifiedCausalEscrowLedger(tmp / "escrow.db", verifier,
            {pair.policy: Policy("gap", 16, {(0, 0): update["deposit"]})}, registrar.public_key(), broadcaster.pubkey_hex)
        ledger.fund("fleet", enrollment.deposit)
        ledger.register(enrollment, registrar.sign(enrollment.signed_message()))
        ledger.install_bulletin(broadcaster.publish_broadcast(pair.policy, 1, closing.infra))
        ledger.admit_update(sid=pair.sid, revision=0, next_state=update["newRoot"], refund_delta=update["deltaRefund"],
                            now=1, proof=proof_json(proofs["gap_local_16"]["proof_path"]))
        claim = {"sid": pair.sid, "revision": 1, "refund_delta": close["refund"], "now": 11,
                 "charge": close["charge"], "certified_digest": close["certifiedDigest"],
                 "proof": proof_json(proofs["gap_close_digest"]["proof_path"])}
        blocked = unchanged_on_rejection(ledger, lambda: ledger.admit_close(**claim))
        cert_receipt = ledger.certify_gap_close(
            sid=pair.sid, revision=1, digest=certificate["certifiedDigest"], charge=certificate["charge"],
            refund_delta=certificate["refund"], now=11, proof=proof_json(proofs["gap_close_raw"]["proof_path"]),
        )
        state = ledger.snapshot()["sessions"][0]
        if state["certified_digest"] != str(close["certifiedDigest"]) or state["certified_revision"] != 1:
            raise ValueError("Certified digest is absent from the persisted session")
        wrong_digest = {**claim, "certified_digest": (claim["certified_digest"] + 1) % FIELD_P}
        mismatch = unchanged_on_rejection(ledger, lambda: ledger.admit_close(**wrong_digest))
        start = perf_counter()
        close_receipt = ledger.admit_close(**claim)
        close_ms = (perf_counter() - start) * 1000
        closed = ledger.snapshot()["sessions"][0]
        if not closed["closed"] or closed["charged"] + closed["returned"] != enrollment.deposit:
            raise ValueError("Gap close violates conservation")
    cert_compute = times["gap_close_raw"]["witness_ms"] + times["gap_close_raw"]["prove_ms"]
    digest_compute = times["gap_close_digest"]["witness_ms"] + times["gap_close_digest"]["prove_ms"]
    return {
        "admissions": 2, "certifications": 1, "persisted_certified_digest": True,
        "negatives": {"uncertified_digest_close": blocked, "wrong_certified_digest": mismatch},
        "proofs": list(proofs.values()), "compute": times, "certification": cert_receipt,
        "digest_close": {"pairing_ms": close_receipt["pairing_ms"], "admission_ms": close_ms},
        "certify_and_close_total_ms": cert_compute + cert_receipt["elapsed_ms"] + digest_compute + close_ms,
        "digest_close_total_ms": digest_compute + close_ms, "conservation_errors": 0,
    }


def main(default: str | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    if default is None:
        parser.add_argument("--suite", required=True, choices=("rome", "m06a", "gap"))
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--historical-cohort", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-sha256")
    parser.add_argument("--tariff", type=Path)
    parser.add_argument("--time-split", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--limit", type=int, help="Run only a subset for a smoke check")
    args = parser.parse_args()
    suite = default or args.suite
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    args.build, args.keys, args.out = args.build.resolve(), args.keys.resolve(), args.out.resolve()
    manifest = args.build / "compiled_circuits_manifest.json"
    compiled = json.loads(manifest.read_text())["circuits"]
    setup = json.loads((args.keys / "phase2_setup_manifest.json").read_text())
    if setup["compiler_build_manifest_sha256"] != sha256(manifest):
        raise ValueError("The supplied key set is registered against a different build")
    args.out.mkdir()

    if suite == "gap":
        result = replay_gap(args, compiled, setup)
    else:
        cohort = None
        if suite == "m06a" and args.time_split:
            from m06a_cohort import select

            if not all((args.source, args.tariff)):
                parser.error("--time-split requires the pinned source and tariff")
            graph, _, test, selection, _ = select(args.source, args.tariff)
            cohort = graph, test
            historical = [{"row_idx": row["row_idx"], "fault_waiver_trip": i % 3 == 1}
                          for i, row in enumerate(selection)]
        elif args.historical_cohort:
            historical = json.loads(args.historical_cohort.read_text())["sessions"]
        else:
            parser.error("Provide a historical cohort or use --time-split for M06A")
        if len(historical) != {"m06a": 36, "rome": 55}[suite]:
            raise ValueError("Wrong historical proof cohort")
        if args.limit is not None:
            if args.limit < 1:
                parser.error("--limit must be positive")
            historical = historical[:args.limit]
        if suite == "rome":
            profile, policy, cases, step = rome_cases(historical)
        else:
            if cohort is None:
                if not all((args.source, args.source_sha256, args.tariff)):
                    parser.error("M06A requires the source file, its expected hash, and the tariff table")
                if sha256(args.source) != args.source_sha256:
                    raise ValueError("M06A source hash mismatch")
            profile, policy, cases, step = m06a_cases(historical, args.source, args.tariff, cohort)
        registry = key_registry(args.keys, compiled, setup, {f"{policy.family}_update", f"{policy.family}_close"})
        with ThreadPoolExecutor(args.jobs) as executor:
            workers = [executor.submit(prove_chunk, cases[i::args.jobs], step, policy.family, args.build,
                                       args.keys, compiled, args.out) for i in range(min(args.jobs, len(cases)))]
            sessions = sorted(session for worker in workers for session in worker.result())
        del cases
        registrar, broadcaster = Ed25519PrivateKey.generate(), InfraBroadcaster()
        with tempfile.TemporaryDirectory(prefix="tollveil-escrow-") as scratch, LiveGroth16Verifier(registry) as verifier:
            ledger = UnifiedCausalEscrowLedger(Path(scratch) / "escrow.db", verifier, {profile: policy},
                                               registrar.public_key(), broadcaster.pubkey_hex)
            result = admit_corridor(ledger, sessions, registrar, broadcaster)
        (args.out / "manifest.local.json").write_text(json.dumps([
            {name: step[name] for name in ("id", "vkey", "public_path", "proof_path")}
            for _, _, steps in sessions for step in steps
        ], indent=2) + "\n")
    result["suite"] = suite
    result["smoke"] = args.limit is not None
    result["chronological_m06a_holdout"] = suite == "m06a" and args.time_split
    result["build_manifest_sha256"] = sha256(manifest)
    (args.out / "ledger_receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{suite}: {result['admissions']} proof-gated admissions, {len(result['negatives'])} negative controls", flush=True)


if __name__ == "__main__":
    main()
