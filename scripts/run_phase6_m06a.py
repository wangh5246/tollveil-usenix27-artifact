#!/usr/bin/env python3
"""Taiwan M06A cohort and proof-gated corridor replay entry point."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import secrets
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np

WORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORK / "scripts"))
sys.path.insert(0, str(WORK / "protocol"))

from circom_crypto import FIELD_P, OBUKeyPair, poseidon


M06A_DIR = WORK / "datasets/tdcs_m06a"
RAW_M06A_CSV = M06A_DIR / "TDCS_M06A_20190830_080000.csv"
TARIFF_JSON = M06A_DIR / "tw_freeway_gantry_tariff_parsed.json"


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


def build_northern_corridor_and_trips(
    source: Path = RAW_M06A_CSV, tariff_path: Path = TARIFF_JSON, *,
    calibrate: tuple[str, str] | None = None, test: tuple[str, str] | None = None,
    calibration_rows: list | None = None,
) -> tuple[dict, list[dict]]:
    """Build a real multi-interchange Taiwan Freeway corridor (Northern Taiwan:
    Freeway No. 1 01F0005..01F1045, Wuyang Elevated 01H, Freeway No. 3 03F0000..03F1022,
    Freeway No. 3A 03A, Freeway No. 5 05F — southbound & northbound interchanges)
    from the pinned TDCS_M06A_20190830_080000.csv and official gantry tariff table."""
    tariffs = json.loads(tariff_path.read_text(encoding="utf-8"))

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

    if (calibrate is None) != (test is None) or (
        calibrate is not None and not calibrate[0] < calibrate[1] <= test[0] < test[1]
    ):
        raise ValueError("Expected disjoint chronological calibration and test intervals")
    # Build support solely from admitted calibration records in the time split.
    trips, testing = [], []
    edge_counts = Counter()
    with source.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row_idx, row in enumerate(reader):
            if len(row) < 8:
                continue
            vtype, started, _, ended, _, trip_len_s, trip_end, traj_s = row[:8]
            if trip_end != "Y" or vtype not in VEH_CLASS_MAP:
                continue
            is_calibration = calibrate is None or calibrate[0] <= started < calibrate[1]
            if not is_calibration and not test[0] <= started < test[1]:
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
            record = {
                "row_idx": row_idx,
                "vtype": vtype,
                "veh_class": vcls,
                "gantries": gantries,
                "first_detected": started,
                "last_detected": ended,
                "detection_times": tuple(p.split("+", 1)[0].strip() for p in parts),
                "trip_length_km_reported": float(trip_len_s),
                "gantry_km_sum": round(sum(g_kms), 2),
                "gantry_fees_01twd": g_fees,
                "statutory_gantry_sum_01twd": sum(g_fees),
            }
            if is_calibration:
                trips.append(record)
                edge_counts.update(zip(gantries[:-1], gantries[1:]))
            else:
                testing.append(record)

    # Retain whole trips whose transitions each have at least two calibration observations.
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
    if calibration_rows is not None:
        calibration_rows.extend(filtered_trips)
    if test is None:
        return corridor, filtered_trips
    accepted_edges = {(nodes[u], nodes[v]) for u, v in edges}
    return corridor, [trip for trip in testing if all(
        (a, b) in accepted_edges for a, b in zip(trip["gantries"][:-1], trip["gantries"][1:])
    )]


def trip_clock(trip: dict) -> tuple[int, ...]:
    """Use observed gantry times and put virtual EXIT padding at the last detection."""
    taipei = ZoneInfo("Asia/Taipei")

    def seconds(value):
        return int(datetime.fromisoformat(value).replace(tzinfo=taipei).timestamp())

    times = tuple(map(seconds, trip["detection_times"]))
    if (sorted(times) != list(times) or times[0] != seconds(trip["first_detected"])
            or times[-1] != seconds(trip["last_detected"]) or times[0] == times[-1]):
        raise ValueError("Gantry timestamp record is inconsistent")
    return times + (times[-1],) * (SLOTS + 1 - len(times))


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
        self.key_salt = secrets.randbelow(FIELD_P)
        self.pk_commit = key.pk_commit(self.key_salt)
        self.identity = poseidon([206001, sid, corridor["profile_tag"], veh_class, self.entry, self.pk_commit])
        self.leaf_salts = [secrets.randbelow(FIELD_P) for _ in range(SLOTS)]
        self.header = poseidon([206003, self.identity, SLOTS])

    def state_commit(self, revision: int, state: dict) -> int:
        return poseidon([
            206102, self.identity, revision, state["mask"], state["count"],
            state["upper"], state["returned"], state["salt"], state["checkpoint"],
        ])

    def build_step(self, rel: int, revision: int, prev: dict, passed: int, opened_mask: int,
                   fault_mask: int, infra_mask: int, deposit: int, *, early=False,
                   release_delta: int | None = None) -> tuple[dict, dict]:
        digest = self.header
        prefix = digest
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
            if i + 1 == passed:
                prefix = digest
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
        remaining_release = deposit - upper - prev["returned"]
        refund_delta = remaining_release if release_delta is None else release_delta
        if not 0 <= refund_delta <= remaining_release or (rel == 2 and refund_delta != remaining_release):
            raise ValueError("Release exceeds the causal certificate")
        new_salt = secrets.randbelow(FIELD_P)
        nxt = {
            "mask": opened_mask,
            "count": passed,
            "upper": upper,
            "returned": prev["returned"] + refund_delta,
            "salt": new_salt,
            "checkpoint": prefix,
        }
        next_state = self.state_commit(revision + 1, nxt) if rel == 1 else 0
        data = {
            "relTag": rel,
            "sid": self.sid,
            "revision": revision,
            "profile": self.corridor["profile_tag"],
            "vehClass": self.veh_class,
            "entry": self.entry,
            "pkCommit": self.pk_commit,
            "deposit": deposit,
            "infraMask": infra_mask | (int(early) << SLOTS),
            "prevState": self.state_commit(revision, prev),
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


if __name__ == "__main__":
    if "--verify-cohort" in sys.argv:
        from m06a_cohort import main
        main()
    else:
        from replay_escrow import main
        main("m06a")
