#!/usr/bin/env python3
"""Phase 6.2: Taiwan Freeway Bureau TDCS M06A multi-gantry corridor & statutory tariff evaluation + >=90 real Groth16 proofs."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from random import Random

import numpy as np

WORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORK / "scripts"))
sys.path.insert(0, str(WORK / "protocol"))

from circom_crypto import FIELD_P, InfraBroadcaster, InfraFaultBroadcast, OBUKeyPair, poseidon
from controlled_bench import parse_max_rss_bytes
from deterministic_circom import compile_once, verify_determinism
from potential_certificate import field_input
from r1cs_header import read_header

NODE_BIN = "/opt/homebrew/bin/node"
RAPIDSNARK_BIN = "rapidsnark"
SNARKJS_BIN = "/usr/local/bin/snarkjs"

M06A_DIR = WORK / "datasets/tdcs_m06a"
RAW_M06A_CSV = M06A_DIR / "TDCS_M06A_20190830_080000.csv"
TARIFF_JSON = M06A_DIR / "tw_freeway_gantry_tariff_parsed.json"

CIRCUIT_DIR = WORK / "circuits/m06a"
OUT_DIR = WORK / "receipts/phase6"
PROOF_DIR = OUT_DIR / "m06a_proofs"
RECEIPT_PATH = OUT_DIR / "m06a_freeway_corridor.json"

SLOTS = 8
PUBLIC = (
    "relTag", "sid", "revision", "profile", "vehClass", "entry", "pkCommit",
    "deposit", "infraMask", "prevState", "nextState", "refundDelta", "charge",
)

# Taiwan Freeway Bureau statutory class mapping:
# 31 (sedan) & 32 (light truck) -> Small (0)
# 41 (bus) & 42 (heavy truck)   -> Large (1)
# 5 (tractor-trailer)           -> Trailer (2)
VEH_CLASS_MAP = {"31": 0, "32": 0, "41": 1, "42": 1, "5": 2}
VEH_CLASS_NAME = {0: "small", 1: "large", 2: "trailer"}


def build_northern_corridor_and_trips() -> tuple[dict, list[dict]]:
    """Build a real multi-interchange Taiwan Freeway corridor (Northern Taiwan:
    Freeway No. 1 01F0005..01F1045, Wuyang Elevated 01H, Freeway No. 3 03F0000..03F1022,
    Freeway No. 3A 03A, Freeway No. 5 05F — southbound & northbound interchanges)
    from the pinned TDCS_M06A_20190830_080000.csv and official gantry tariff table."""
    tariffs = json.loads(TARIFF_JSON.read_text(encoding="utf-8"))

    def in_northern_freeway_corridor(gid: str) -> bool:
        if gid not in tariffs:
            return False
        # Northern Taiwan multi-freeway interchange corridor (Keelung–Taipei–Taoyuan–Hsinchu–Yilan)
        # Focus on southbound + northbound major Freeways 1 (01F <= 0750, 01H), 3 (03F <= 0698, 03A), 5 (05F)
        # Wait: let's select southbound ("S") Northern Taiwan freeways 01F (0..1045), 01H, 03F (0..1022), 03A, 05F
        # so the directed graph is an acyclic multi-interchange corridor with ~90–110 real gantries!
        prefix = gid[:3]
        km_str = gid[3:7]
        direction = gid[7:]
        if not km_str.isdigit():
            return False
        km = int(km_str)
        if direction != "S":
            return False
        if prefix == "01F" and km <= 1150:
            return True
        if prefix == "01H":
            return True
        if prefix == "03F" and km <= 1050:
            return True
        if prefix == "03A":
            return True
        if prefix == "05F":
            return True
        return False

    # Scan full pinned M06A CSV to collect real multi-gantry trips (4..8 gantries) inside this corridor
    trips = []
    edge_counts = Counter()
    gantry_set = set()
    with RAW_M06A_CSV.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row_idx, row in enumerate(reader):
            if len(row) < 8:
                continue
            vtype, _, _, _, _, trip_len_s, trip_end, traj_s = row[:8]
            if trip_end != "Y" or vtype not in VEH_CLASS_MAP:
                continue
            parts = [p.strip() for p in traj_s.split(";") if "+" in p]
            gantries = [p.split("+", 1)[1].strip() for p in parts]
            if not (4 <= len(gantries) <= SLOTS):
                continue
            if not all(in_northern_freeway_corridor(g) for g in gantries):
                continue
            # Ensure no repeated gantry in a single trip (strictly forward highway traversal)
            if len(set(gantries)) != len(gantries):
                continue
            vcls = VEH_CLASS_MAP[vtype]
            # Exact statutory gantry list-price sum in 0.1 TWD integer units
            g_fees = []
            g_kms = []
            for g in gantries:
                tinfo = tariffs[g]
                rate_key = ("rate_small_twd", "rate_large_twd", "rate_trailer_twd")[vcls]
                g_fees.append(int(round(float(tinfo[rate_key]) * 10)))
                g_kms.append(float(tinfo["mileage_km"]))
            trips.append({
                "row_idx": row_idx,
                "vtype": vtype,
                "veh_class": vcls,
                "gantries": gantries,
                "trip_length_km_reported": float(trip_len_s),
                "gantry_km_sum": round(sum(g_kms), 2),
                "gantry_fees_01twd": g_fees,
                "statutory_gantry_sum_01twd": sum(g_fees),
            })
            for g in gantries:
                gantry_set.add(g)
            for a, b in zip(gantries[:-1], gantries[1:]):
                edge_counts[(a, b)] += 1

    # Keep only edges observed at least twice (or all edges on retained trips) so every single retained trip
    # has 100% of its edges in the public corridor graph without artificial pruning!
    # Wait: keep ALL observed corridor edges among gantry_set? Let's check count of vertices & edges!
    # Filter to trips whose edges are well-supported (count >= 2) to exclude GPS/ETC glitch teleportations while
    # keeping >= 1,500 genuine multi-interchange trips!
    valid_edges = {e for e, cnt in edge_counts.items() if cnt >= 2}
    filtered_trips = [
        tr for tr in trips
        if all((a, b) in valid_edges for a, b in zip(tr["gantries"][:-1], tr["gantries"][1:]))
    ]
    used_gantries = sorted({g for tr in filtered_trips for g in tr["gantries"]})
    # Add virtual EXIT sink at index N - 1
    nodes = used_gantries + ["EXIT"]
    idx = {g: i for i, g in enumerate(nodes)}
    exit_id = len(nodes) - 1

    # Build sorted directed edge list: all supported gantry->gantry transitions + (u -> EXIT) for every gantry + (EXIT -> EXIT)
    edges_by_u = defaultdict(set)
    for (a, b) in valid_edges:
        if a in idx and b in idx:
            edges_by_u[idx[a]].add(idx[b])
    for u in range(exit_id):
        edges_by_u[u].add(exit_id)
    edges_by_u[exit_id].add(exit_id)

    edges = []
    out_offsets = [0]
    for u in range(len(nodes)):
        for v in sorted(edges_by_u[u]):
            edges.append([u, v])
        out_offsets.append(len(edges))

    fee_small, fee_large, fee_trailer = [], [], []
    for g in used_gantries:
        t = tariffs[g]
        fee_small.append(int(round(float(t["rate_small_twd"]) * 10)))
        fee_large.append(int(round(float(t["rate_large_twd"]) * 10)))
        fee_trailer.append(int(round(float(t["rate_trailer_twd"]) * 10)))
    fee_small.append(0)
    fee_large.append(0)
    fee_trailer.append(0)

    profile_payload = {
        "nodes": nodes,
        "edges": edges,
        "fee_small": fee_small,
        "fee_large": fee_large,
        "fee_trailer": fee_trailer,
    }
    profile_tag = int.from_bytes(
        hashlib.sha256(b"tollveil-v15-m06a-corridor-v1\0" + json.dumps(profile_payload, separators=(",", ":")).encode()).digest(),
        "big",
    ) % FIELD_P

    # Count real interchange-branching edges (e.g., 01F <-> 01H, 01F <-> 03F, 03F <-> 05F, 03F <-> 03A)
    interchange_edges = [
        (nodes[u], nodes[v]) for u, v in edges
        if v != exit_id and nodes[u][:3] != nodes[v][:3]
    ]

    corridor = {
        "nodes": nodes,
        "idx": idx,
        "exit_id": exit_id,
        "n": len(nodes),
        "bits": max(1, math.ceil(math.log2(len(nodes)))),
        "E": len(edges),
        "edges": edges,
        "out_offsets": out_offsets,
        "fee_small": fee_small,
        "fee_large": fee_large,
        "fee_trailer": fee_trailer,
        "profile_tag": profile_tag,
        "interchange_edges_count": len(interchange_edges),
        "interchange_edges_sample": interchange_edges[:10],
    }
    return corridor, filtered_trips


def eff_fees(corridor: dict, veh_class: int) -> list[int]:
    return (corridor["fee_small"], corridor["fee_large"], corridor["fee_trailer"])[veh_class]


def compute_bellman_upper(corridor: dict, veh_class: int, entry: int, pins: dict[int, tuple[int, int]], excused_mask: int) -> dict:
    """Exact backward DP producing primal maximizing path + dual Bellman potentials."""
    n = corridor["n"]
    fees = eff_fees(corridor, veh_class)
    edges = corridor["edges"]
    out_offsets = corridor["out_offsets"]

    phi = np.zeros((SLOTS + 1, n), dtype=np.int64)
    live = np.zeros((SLOTS + 1, n), dtype=np.int64)
    live[SLOTS, :] = 1
    choice = np.full((SLOTS, n), -1, dtype=np.int64)

    for i in reversed(range(SLOTS)):
        exc = (excused_mask >> i) & 1
        if i in pins:
            a, b = pins[i]
            if live[i + 1, b]:
                live[i, a] = 1
                phi[i, a] = phi[i + 1, b] + (0 if exc else fees[a])
                choice[i, a] = b
        else:
            for u in range(n):
                best = -1
                best_v = -1
                for e in range(out_offsets[u], out_offsets[u + 1]):
                    v = edges[e][1]
                    if live[i + 1, v]:
                        val = int(phi[i + 1, v]) + (0 if exc else fees[u])
                        if val > best:
                            best = val
                            best_v = v
                if best_v >= 0:
                    live[i, u] = 1
                    phi[i, u] = best
                    choice[i, u] = best_v

    if not live[0, entry]:
        raise ValueError("No legal path from entry")
    path = [entry]
    for i in range(SLOTS):
        nxt = int(choice[i, path[-1]])
        if nxt < 0:
            raise ValueError("Broken primal path")
        path.append(nxt)
    return {
        "maximum": path,
        "phi": phi.tolist(),
        "live": live.tolist(),
        "upper": int(phi[0, entry]),
    }


def forward_dp_check(corridor: dict, veh_class: int, entry: int, pins: dict[int, tuple[int, int]], excused_mask: int) -> int:
    """Independent forward DP for cross-checking Bellman upper bound."""
    n = corridor["n"]
    fees = eff_fees(corridor, veh_class)
    edges = corridor["edges"]
    NEG = -10**9
    cur = np.full(n, NEG, dtype=np.int64)
    cur[entry] = 0
    for i in range(SLOTS):
        nxt = np.full(n, NEG, dtype=np.int64)
        exc = (excused_mask >> i) & 1
        if i in pins:
            a, b = pins[i]
            if cur[a] >= 0:
                nxt[b] = max(nxt[b], cur[a] + (0 if exc else fees[a]))
        else:
            for u, v in edges:
                if cur[u] >= 0:
                    val = cur[u] + (0 if exc else fees[u])
                    if val > nxt[v]:
                        nxt[v] = val
        cur = nxt
    ans = int(cur.max())
    assert ans >= 0
    return ans


class M06ALedger:
    def __init__(self, db_path: Path, broadcaster_pubkey_hex: str) -> None:
        self.db_path = db_path
        self.broadcaster = broadcaster_pubkey_hex
        with sqlite3.connect(db_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS session (sid TEXT PRIMARY KEY, profile TEXT, veh_class INTEGER, "
                "entry INTEGER, pk TEXT, deposit INTEGER, state TEXT, epoch INTEGER, closes_at INTEGER, "
                "revision INTEGER NOT NULL DEFAULT 0, returned INTEGER NOT NULL DEFAULT 0, "
                "closed INTEGER NOT NULL DEFAULT 0, charged INTEGER NOT NULL DEFAULT 0)"
            )

    def register(self, sid: int, profile: int, veh_class: int, entry: int, pk_commit: int, deposit: int, genesis_state: int, epoch: int, closes_at: int) -> None:
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "INSERT INTO session(sid,profile,veh_class,entry,pk,deposit,state,epoch,closes_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (str(sid), str(profile), veh_class, entry, str(pk_commit), deposit, str(genesis_state), epoch, closes_at),
            )

    def apply(self, sid: int, revision: int, role: int, next_state: int, refund_delta: int, charge: int, now: int, bulletin: InfraFaultBroadcast | None = None) -> dict:
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            old = dict(db.execute("SELECT * FROM session WHERE sid=?", (str(sid),)).fetchone())
            assert old["revision"] == revision and old["closed"] == 0
            assert refund_delta >= 0 and charge >= 0
            if role == 1:
                assert charge == 0 and bulletin is None and now < old["closes_at"]
            else:
                assert next_state == 0 and now >= old["closes_at"] and bulletin is not None
                assert InfraBroadcaster.verify_broadcast(bulletin, self.broadcaster)
                assert bulletin.corridor_id == int(old["profile"]) and bulletin.epoch_id == old["epoch"]
                assert refund_delta + charge + old["returned"] == old["deposit"]
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                "UPDATE session SET state=?, revision=revision+1, returned=returned+?, closed=?, charged=? "
                "WHERE sid=? AND revision=? AND state=? AND closed=0",
                (str(next_state), refund_delta, int(role == 2), charge, str(sid), revision, old["state"]),
            )
            assert cur.rowcount == 1
            return dict(db.execute("SELECT * FROM session WHERE sid=?", (str(sid),)).fetchone())


def compile_and_setup_m06a(corridor: dict) -> dict:
    CIRCUIT_DIR.mkdir(parents=True, exist_ok=True)
    args_json = [
        corridor["n"],
        corridor["bits"],
        SLOTS,
        corridor["E"],
        corridor["edges"],
        corridor["out_offsets"],
        corridor["fee_small"],
        corridor["fee_large"],
        corridor["fee_trailer"],
        corridor["profile_tag"],
    ]
    builds = {}
    for rel, role in ((1, "update"), (2, "close")):
        wrapper = CIRCUIT_DIR / f"m06a_{role}.circom"
        wrapper.write_text(
            'pragma circom 2.1.9;\n'
            'include "m06a_corridor_template.circom";\n\n'
            f'component main {{public [{", ".join(PUBLIC)}]}} = M06ACorridor(\n'
            + ",\n".join("    " + json.dumps(a, separators=(",", ":")) for a in (*args_json, rel))
            + "\n);\n",
            encoding="utf-8",
        )
        bdir = CIRCUIT_DIR / f"build_{role}"
        bdir.mkdir(parents=True, exist_ok=True)

        # Deterministic 3/3 compile check via deterministic_circom.py
        det_receipt_path = OUT_DIR / f"det_compile_m06a_{role}.json"
        det = verify_determinism(
            circuit_path=wrapper,
            trials=3,
            opt="--O1",
            extra_libs=[CIRCUIT_DIR, WORK / "circuits/phase2"],
        )
        actual = compile_once(
            circuit_path=wrapper,
            out_dir=bdir,
            opt="--O1",
            extra_libs=[CIRCUIT_DIR, WORK / "circuits/phase2"],
            emit_sym=True,
        )
        assert det["all_identical"] and actual["r1cs_sha256"] == det["r1cs_sha256"] and actual["wasm_sha256"] == det["wasm_sha256"]
        det_receipt_path.write_text(json.dumps({"status": "PASS", "determinism_check": det, "compile": actual}, indent=2) + "\n")

        r1cs_path = bdir / f"m06a_{role}.r1cs"
        head = read_header(r1cs_path)
        n_constraints = head["constraints"]
        # Pick smallest adequate prepared ptau
        if n_constraints < (1 << 15):
            ptau = WORK / "circuits/ptau/prepared_p15.ptau"
        elif n_constraints < (1 << 17):
            ptau = WORK / "circuits/ptau/prepared_p17.ptau"
        elif n_constraints < (1 << 18):
            ptau = WORK / "circuits/ptau/prepared_p18.ptau"
        else:
            ptau = WORK / "circuits/causal/ptau/pot20_final.ptau"
            if not ptau.exists():
                ptau = Path("${WORKSPACE_ROOT}/experiments/waybill_refinement/v1/artifacts_server_20261010/pot22_prep.ptau")

        zkey_path = bdir / f"m06a_{role}.zkey"
        vkey_path = bdir / f"m06a_{role}_vkey.json"
        if not zkey_path.exists() or not vkey_path.exists():
            env = os.environ.copy()
            env["NODE_OPTIONS"] = "--max-old-space-size=8192"
            subprocess.run(
                [NODE_BIN, SNARKJS_BIN, "groth16", "setup", str(r1cs_path), str(ptau), str(zkey_path)],
                env=env, check=True, capture_output=True, text=True,
            )
            subprocess.run(
                [NODE_BIN, SNARKJS_BIN, "zkey", "export", "verificationkey", str(zkey_path), str(vkey_path)],
                env=env, check=True, capture_output=True, text=True,
            )

        builds[role] = {
            "wrapper": str(wrapper),
            "r1cs_path": str(r1cs_path),
            "wasm_path": str(bdir / f"m06a_{role}_js/m06a_{role}.wasm"),
            "calc_js": str(bdir / f"m06a_{role}_js/witness_calculator.js"),
            "zkey_path": str(zkey_path),
            "vkey_path": str(vkey_path),
            "constraints": n_constraints,
            "ptau_used": ptau.name,
            "r1cs_sha256": det["r1cs_sha256"],
            "wasm_sha256": det["wasm_sha256"],
            "deterministic_3x": True,
        }
        print(f"[M06A] Built & keyed m06a_{role}: {n_constraints} constraints (3/3 deterministic, ptau={ptau.name})")
    return builds


class M06AScenario:
    def __init__(self, corridor: dict, key: OBUKeyPair, sid: int, veh_class: int, gantry_nodes: list[int]) -> None:
        self.corridor = corridor
        self.key = key
        self.sid = sid
        self.veh_class = veh_class
        # Pad path to SLOTS + 1 vertices by appending EXIT sink
        exit_id = corridor["exit_id"]
        path = list(gantry_nodes)
        while len(path) < SLOTS + 1:
            path.append(exit_id)
        self.path = tuple(path[: SLOTS + 1])
        self.entry = self.path[0]
        self.key_salt = int.from_bytes(hashlib.sha256(f"ks-{sid}".encode()).digest(), "big") % FIELD_P
        self.pk_commit = key.pk_commit(self.key_salt)
        self.identity = poseidon([206001, sid, corridor["profile_tag"], veh_class, self.entry, self.pk_commit])
        self.leaf_salts = [
            int.from_bytes(hashlib.sha256(f"ls-{sid}-{i}".encode()).digest(), "big") % FIELD_P
            for i in range(SLOTS)
        ]
        self.header = poseidon([206003, self.identity, SLOTS])

    def state_commit(self, revision: int, mask: int, count: int, upper: int, returned: int, blinding: int) -> int:
        return poseidon([206002, self.identity, revision, mask, count, upper, returned, blinding])

    def build_step(self, rel: int, revision: int, prev: dict, passed: int, opened_mask: int, fault_mask: int, infra_mask: int, deposit: int) -> tuple[dict, dict]:
        digest = self.header
        past_arr, fault_arr, sealed_arr, opened_arr, ls_arr = [], [], [], [], []
        pins = {}
        for i in range(SLOTS):
            p = 1 if i < passed else 0
            f = (fault_mask >> i) & 1
            v = p - f
            o = (opened_mask >> i) & 1
            assert not (f and not p)
            assert not (o and not v)
            if v:
                leaf = poseidon([206010 + i, self.identity, self.path[i], self.path[i + 1], self.leaf_salts[i]])
            else:
                leaf = 0
            digest = poseidon([digest, p, f, leaf])
            past_arr.append(p)
            fault_arr.append(f)
            sealed_arr.append(leaf)
            opened_arr.append(o)
            ls_arr.append(self.leaf_salts[i] if o else 0)
            if o:
                pins[i] = (self.path[i], self.path[i + 1])

        sig = self.key.sign_field(digest)
        excused_mask = fault_mask & infra_mask
        bellman = compute_bellman_upper(self.corridor, self.veh_class, self.entry, pins, excused_mask)
        ref_u = forward_dp_check(self.corridor, self.veh_class, self.entry, pins, excused_mask)
        assert ref_u == bellman["upper"]
        upper = bellman["upper"]
        refund_delta = deposit - upper - prev["returned"]
        assert refund_delta >= 0
        new_salt = int.from_bytes(hashlib.sha256(f"st-{self.sid}-{revision+1}".encode()).digest(), "big") % FIELD_P
        nxt = {
            "mask": opened_mask,
            "count": passed,
            "upper": upper,
            "returned": prev["returned"] + refund_delta,
            "salt": new_salt,
        }
        next_state = self.state_commit(revision + 1, nxt["mask"], nxt["count"], nxt["upper"], nxt["returned"], nxt["salt"]) if rel == 1 else 0
        data = {
            "relTag": rel,
            "sid": self.sid,
            "revision": revision,
            "profile": self.corridor["profile_tag"],
            "vehClass": self.veh_class,
            "entry": self.entry,
            "pkCommit": self.pk_commit,
            "deposit": deposit,
            "infraMask": infra_mask,
            "prevState": self.state_commit(revision, prev["mask"], prev["count"], prev["upper"], prev["returned"], prev["salt"]),
            "nextState": next_state,
            "refundDelta": refund_delta,
            "charge": upper if rel == 2 else 0,
            "Ax": self.key.Ax,
            "Ay": self.key.Ay,
            "keySalt": self.key_salt,
            "R8x": sig.R8x,
            "R8y": sig.R8y,
            "S": sig.S,
            "oldMask": prev["mask"],
            "oldCount": prev["count"],
            "oldUpper": prev["upper"],
            "oldRefund": prev["returned"],
            "oldSalt": prev["salt"],
            "newSalt": new_salt,
            "past": past_arr,
            "fault": fault_arr,
            "sealed": sealed_arr,
            "opened": opened_arr,
            "leafSalt": ls_arr,
            "maximum": bellman["maximum"],
            "phi": bellman["phi"],
            "live": bellman["live"],
            "upper": upper,
        }
        return data, nxt


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PROOF_DIR.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()

    corridor, trips = build_northern_corridor_and_trips()
    print(f"[M06A] Northern multi-interchange corridor: {corridor['n']-1} real gantries + EXIT, {corridor['E']} directed edges ({corridor['interchange_edges_count']} cross-freeway interchange edges), {len(trips)} real multi-gantry trips.")
    assert len(trips) >= 1000

    # 1. Replay >= 1,500 real multi-gantry trips (deterministic slice of 2,000 if more, or all if <= 3,000)
    rng = Random(202611247)
    replay_trips = list(trips)
    if len(replay_trips) > 2000:
        rng.shuffle(replay_trips)
        replay_trips = sorted(replay_trips[:2000], key=lambda t: t["row_idx"])

    # Compute exact statutory fee alignment, contraction across prefixes, and fleet rolling margin pool!
    exact_matches = 0
    deposits_by_cls = defaultdict(list)
    fees_by_cls = defaultdict(list)
    locked_frac_exact = []
    # Statutory daily 20 km free allowance + >200 km long-distance tier diagnostic
    # Taiwan statutory base: Small 1.2 TWD/km (0.9 >200km), Large 1.5 TWD/km (1.12 >200km), Trailer 1.8 TWD/km (1.35 >200km)
    base_rate_per_km = {0: 1.2, 1: 1.5, 2: 1.8}
    statutory_20km_free_net = []

    fleet_trips_sim = []
    for tr in replay_trips:
        nodes_seq = [corridor["idx"][g] for g in tr["gantries"]]
        entry = nodes_seq[0]
        vcls = tr["veh_class"]
        d0 = forward_dp_check(corridor, vcls, entry, {}, 0)
        # Full path padded with EXIT
        padded = nodes_seq + [corridor["exit_id"]] * (SLOTS + 1 - len(nodes_seq))
        u_curve = [d0]
        for k in range(1, SLOTS + 1):
            pins = {i: (padded[i], padded[i + 1]) for i in range(k)}
            u_curve.append(forward_dp_check(corridor, vcls, entry, pins, 0))
        q_final = u_curve[SLOTS]
        if q_final == tr["statutory_gantry_sum_01twd"]:
            exact_matches += 1
        deposits_by_cls[vcls].append(d0)
        fees_by_cls[vcls].append(q_final)
        locked_frac_exact.append(1.0 - float(np.mean(u_curve[:SLOTS])) / d0)
        # Net statutory fee after 20 km free daily allowance
        km_billable = max(0.0, tr["gantry_km_sum"] - 20.0)
        net_twd = km_billable * base_rate_per_km[vcls]
        statutory_20km_free_net.append(net_twd)
        fleet_trips_sim.append({"deposit": d0, "u_curve": u_curve, "final_fee": q_final})

    assert exact_matches == len(replay_trips), f"Statutory mismatch: {exact_matches}/{len(replay_trips)}"

    # Fleet rolling margin across 20 concurrent freeway fleet vehicles
    avg_hold, avg_exact = [], []
    peak_hold, peak_exact = 0, 0
    for s in range(0, len(fleet_trips_sim) - 20 + 1):
        win = fleet_trips_sim[s : s + 20]
        hs = sum(w["deposit"] for w in win)
        es = sum(w["u_curve"][j % SLOTS] for j, w in enumerate(win))
        peak_hold = max(peak_hold, hs)
        peak_exact = max(peak_exact, es)
        avg_hold.append(hs)
        avg_exact.append(es)

    print(f"[M06A] Replayed {len(replay_trips)} real multi-gantry trips: {exact_matches}/{len(replay_trips)} (100%) exact statutory gantry fee match; fleet rolling margin reduction = {(1 - np.mean(avg_exact)/np.mean(avg_hold))*100:.2f}%.")

    # 2. Compile & setup M06A circuits deterministically
    builds = compile_and_setup_m06a(corridor)

    # 3. Pre-register 36 real M06A trips (stratified across Small / Large / Trailer classes!)
    # 36 trips × 3 steps (2 streaming updates + 1 close, including 12 trips with corroborated gantry-misread waiver) = 108 real Groth16 proofs (>= 90)!
    by_cls = defaultdict(list)
    for tr in replay_trips:
        by_cls[tr["veh_class"]].append(tr)
    rng_sel = Random(202611248)
    selected_trips = []
    # 24 small, 6 large, 6 trailer (or proportional if fewer)
    quotas = {0: 24, 1: 6, 2: 6}
    for cls_id, q in quotas.items():
        pool = list(by_cls[cls_id])
        rng_sel.shuffle(pool)
        selected_trips.extend(pool[: min(q, len(pool))])
    while len(selected_trips) < 36:
        selected_trips.append(by_cls[0][len(selected_trips)])
    selected_trips.sort(key=lambda t: t["row_idx"])
    assert len(selected_trips) == 36

    # Persistent witness generators
    def open_wg(role: str):
        b = builds[role]
        return subprocess.Popen(
            [NODE_BIN, str(WORK / "scripts/batch_gen_witness.cjs"), b["calc_js"], b["wasm_path"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )

    wg_upd = open_wg("update")
    wg_cls = open_wg("close")
    infra = InfraBroadcaster()
    obu_key = OBUKeyPair(hashlib.sha256(b"tollveil-v15-m06a-obu-key").digest())

    def gen_wtns(proc, data: dict, out_wtns: Path) -> float:
        assert proc.stdin and proc.stdout
        proc.stdin.write(json.dumps({"input": field_input(data), "wtns_path": str(out_wtns)}, separators=(",", ":")) + "\n")
        proc.stdin.flush()
        resp = json.loads(proc.stdout.readline())
        if not resp.get("ok"):
            raise RuntimeError(f"M06A witness failed: {resp.get('error')}")
        return float(resp["witness_ms"])

    verify_manifest = []
    proof_records = []
    session_summaries = []
    prove_upd_ms, prove_cls_ms = [], []
    rss_mb_all = []

    with tempfile.TemporaryDirectory(prefix="tollveil_p6_m06a_") as td:
        tmp = Path(td)
        ledger = M06ALedger(tmp / "m06a_ledger.sqlite", infra.pubkey_hex)
        try:
            for idx_t, tr in enumerate(selected_trips):
                nodes_seq = [corridor["idx"][g] for g in tr["gantries"]]
                vcls = tr["veh_class"]
                sid = 7_000_000 + tr["row_idx"]
                scen = M06AScenario(corridor, obu_key, sid, vcls, nodes_seq)
                d0 = forward_dp_check(corridor, vcls, scen.entry, {}, 0)
                init_salt = int.from_bytes(hashlib.sha256(f"st-{sid}-0".encode()).digest(), "big") % FIELD_P
                prev = {"mask": 0, "count": 0, "upper": d0, "returned": 0, "salt": init_salt}
                genesis_comm = scen.state_commit(0, 0, 0, d0, 0, init_salt)
                epoch_id = 500 + idx_t
                ledger.register(sid, corridor["profile_tag"], vcls, scen.entry, scen.pk_commit, d0, genesis_comm, epoch_id, 50)

                # 12 of 36 trips exercise corroborated gantry-misread outage at slot 2 (e.g., ETC antenna outage)
                # plus an uncorroborated OBU glitch at slot 3 (charged worst-case, 0 undercharge!)
                is_fault_trip = (idx_t % 3 == 1)
                if is_fault_trip:
                    steps = [
                        (1, 2, 0b00000011, 0, 0, 10),           # open gantries 0,1
                        (1, 5, 0b00010011, 0b00001100, 0, 25),  # open gantry 4, slots 2&3 faulted
                        (2, 8, 0b11110011, 0b00001100, 0b00000100, 55),  # slot 2 corroborated (waived), slot 3 uncorroborated
                    ]
                else:
                    steps = [
                        (1, 2, 0b00000011, 0, 0, 10),
                        (1, 5, 0b00011111, 0, 0, 25),
                        (2, 8, 0b11111111, 0, 0, 55),
                    ]

                for rev, (rel, passed, omask, fmask, imask, now_ts) in enumerate(steps):
                    role_name = "update" if rel == 1 else "close"
                    data, nxt = scen.build_step(rel, rev, prev, passed, omask, fmask, imask, d0)
                    wtns_path = tmp / f"m06a_{sid}_{rev}.wtns"
                    pid = f"m06a_t{idx_t:02d}_r{rev}_{role_name}"
                    proof_path = PROOF_DIR / f"{pid}_proof.json"
                    public_path = PROOF_DIR / f"{pid}_public.json"

                    w_ms = gen_wtns(wg_upd if rel == 1 else wg_cls, data, wtns_path)
                    tp0 = time.perf_counter()
                    pres = subprocess.run(
                        ["/usr/bin/time", "-l", RAPIDSNARK_BIN, builds[role_name]["zkey_path"], str(wtns_path), str(proof_path), str(public_path)],
                        capture_output=True, text=True, check=True,
                    )
                    p_ms = (time.perf_counter() - tp0) * 1000.0
                    rss_b = parse_max_rss_bytes(pres.stderr)
                    rss_mb = round(rss_b / (1024 * 1024), 2) if rss_b else None
                    if rss_mb:
                        rss_mb_all.append(rss_mb)
                    wtns_path.unlink(missing_ok=True)

                    pub_vec = json.loads(public_path.read_text())
                    assert pub_vec == [str(data[k]) for k in PUBLIC]
                    bulletin = infra.publish_broadcast(corridor["profile_tag"], epoch_id, imask) if rel == 2 else None
                    row_after = ledger.apply(sid, rev, rel, data["nextState"], data["refundDelta"], data["charge"], now_ts, bulletin)

                    if rel == 1:
                        prove_upd_ms.append(p_ms)
                    else:
                        prove_cls_ms.append(p_ms)

                    verify_manifest.append({
                        "id": pid,
                        "vkey": builds[role_name]["vkey_path"],
                        "public_path": str(public_path),
                        "proof_path": str(proof_path),
                    })
                    proof_records.append({
                        "id": pid,
                        "trip_idx": idx_t,
                        "veh_class": VEH_CLASS_NAME[vcls],
                        "revision": rev,
                        "role": role_name,
                        "upper_01twd": data["upper"],
                        "refund_delta_01twd": data["refundDelta"],
                        "charge_01twd": data["charge"],
                        "witness_ms": round(w_ms, 3),
                        "prove_ms": round(p_ms, 3),
                        "proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
                        "public_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
                    })
                    prev = nxt

                # Check statutory fee agreement on no-fault trips, and exact waiver behavior on fault trips
                final_charge = row_after["charged"]
                final_returned = row_after["returned"]
                conservation_err = (final_charge + final_returned) - d0
                assert conservation_err == 0
                if not is_fault_trip:
                    assert final_charge == tr["statutory_gantry_sum_01twd"]
                    waiver_diff = 0
                else:
                    # Without infra corroboration (imask=0), charge must be strictly higher (or equal if slot 2 was EXIT, which cannot happen since len>=4)
                    pins_close = {i: (scen.path[i], scen.path[i + 1]) for i in range(SLOTS) if (0b11110011 >> i) & 1}
                    no_waiver = forward_dp_check(corridor, vcls, scen.entry, pins_close, 0)
                    assert no_waiver > final_charge
                    waiver_diff = no_waiver - final_charge
                session_summaries.append({
                    "trip_idx": idx_t,
                    "row_idx": tr["row_idx"],
                    "veh_class": VEH_CLASS_NAME[vcls],
                    "gantry_count": len(tr["gantries"]),
                    "deposit_01twd": d0,
                    "statutory_gantry_sum_01twd": tr["statutory_gantry_sum_01twd"],
                    "charged_01twd": final_charge,
                    "returned_01twd": final_returned,
                    "conservation_error": conservation_err,
                    "fault_waiver_trip": is_fault_trip,
                    "corroborated_waiver_saving_01twd": waiver_diff,
                })
        finally:
            if wg_upd.stdin: wg_upd.stdin.close()
            if wg_cls.stdin: wg_cls.stdin.close()
            wg_upd.wait(timeout=15)
            wg_cls.wait(timeout=15)

        # Independent snarkjs verification of ALL 108 proofs
        mpath = tmp / "m06a_verify_manifest.json"
        mpath.write_text(json.dumps(verify_manifest))
        vres = subprocess.run(
            [NODE_BIN, str(WORK / "scripts/batch_verify_groth16.cjs"), SNARKJS_BIN, str(mpath)],
            capture_output=True, text=True, check=True,
        )
        v_summary = json.loads(vres.stdout)
        assert v_summary["all_verified"] and v_summary["passed"] == len(proof_records) == 108

        # CLI spot-check 4 proofs
        cli_ok = 0
        for item in verify_manifest[::27]:
            cres = subprocess.run(
                [NODE_BIN, SNARKJS_BIN, "groth16", "verify", item["vkey"], item["public_path"], item["proof_path"]],
                capture_output=True, text=True, check=True,
            )
            if "OK!" in cres.stdout:
                cli_ok += 1
        assert cli_ok == len(verify_manifest[::27])

    def stats(arr):
        a = np.asarray(arr, dtype=np.float64)
        q25, med, q75, p95 = np.percentile(a, [25, 50, 75, 95])
        return {"n": len(arr), "median_ms": round(float(med), 3), "iqr_ms": round(float(q75 - q25), 3), "p95_ms": round(float(p95), 3), "mean_ms": round(float(a.mean()), 3)}

    class_breakdown = {}
    for c_id, cname in VEH_CLASS_NAME.items():
        if deposits_by_cls[c_id]:
            class_breakdown[cname] = {
                "trips": len(deposits_by_cls[c_id]),
                "mean_deposit_twd": round(float(np.mean(deposits_by_cls[c_id])) / 10.0, 2),
                "mean_statutory_fee_twd": round(float(np.mean(fees_by_cls[c_id])) / 10.0, 2),
            }

    receipt = {
        "schema": "tollveil.v15.phase6.m06a_freeway_corridor.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS",
        "source_pin_receipt": str(WORK / "receipts/tdcs_m06a_sample_pin.json"),
        "corridor_topology": {
            "name": "Northern Taiwan Multi-Freeway Southbound Interchange Corridor (01F/01H/03F/03A/05F)",
            "real_gantries": corridor["n"] - 1,
            "vertices_with_exit_sink": corridor["n"],
            "directed_edges": corridor["E"],
            "cross_freeway_interchange_edges": corridor["interchange_edges_count"],
            "slots": SLOTS,
            "profile_tag": str(corridor["profile_tag"]),
        },
        "circuits": builds,
        "full_corridor_replay": {
            "trips_replayed": len(replay_trips),
            "statutory_fee_exact_matches": exact_matches,
            "statutory_fee_exact_match_rate": round(exact_matches / len(replay_trips), 6),
            "class_breakdown": class_breakdown,
            "mean_capital_freed_streaming_pct": round(float(np.mean(locked_frac_exact)) * 100.0, 2),
            "mean_net_fee_after_20km_free_twd": round(float(np.mean(statutory_20km_free_net)), 2),
            "fleet_rolling_margin_20_concurrent": {
                "mean_locked_hold_twd": round(float(np.mean(avg_hold)) / 10.0, 2),
                "mean_locked_streaming_twd": round(float(np.mean(avg_exact)) / 10.0, 2),
                "peak_locked_hold_twd": round(peak_hold / 10.0, 2),
                "peak_locked_streaming_twd": round(peak_exact / 10.0, 2),
                "working_capital_reduction_pct": round((1.0 - float(np.mean(avg_exact)) / float(np.mean(avg_hold))) * 100.0, 2),
            },
        },
        "real_proof_evaluation": {
            "trips_proved": len(selected_trips),
            "proofs_total": len(proof_records),
            "update_proofs": len(prove_upd_ms),
            "close_proofs": len(prove_cls_ms),
            "fault_waiver_trips": sum(1 for s in session_summaries if s["fault_waiver_trip"]),
            "nofault_statutory_exact_matches": sum(1 for s in session_summaries if not s["fault_waiver_trip"] and s["charged_01twd"] == s["statutory_gantry_sum_01twd"]),
            "all_verified_snarkjs": v_summary["all_verified"],
            "snarkjs_verified_count": v_summary["passed"],
            "snarkjs_cli_spot_checked": cli_ok,
            "sqlite_conservation_errors": sum(abs(s["conservation_error"]) for s in session_summaries),
            "update_prove_ms": stats(prove_upd_ms),
            "close_prove_ms": stats(prove_cls_ms),
            "verify_ms": stats([r["verify_ms"] for r in v_summary["results"]]),
            "prover_max_peak_rss_mb": max(rss_mb_all),
            "proof_dir": str(PROOF_DIR),
            "elapsed_total_seconds": round(time.perf_counter() - t_start, 2),
        },
        "sessions": session_summaries,
        "proof_hashes": {r["id"]: {"proof_sha256": r["proof_sha256"], "public_sha256": r["public_sha256"]} for r in proof_records},
    }
    RECEIPT_PATH.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"[M06A] DONE! {len(proof_records)} real M06A freeway proofs verified ({v_summary['passed']}/{v_summary['total']}, SQLite errors=0). Update median={receipt['real_proof_evaluation']['update_prove_ms']['median_ms']} ms, Close median={receipt['real_proof_evaluation']['close_prove_ms']['median_ms']} ms.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
