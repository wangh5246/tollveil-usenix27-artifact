#!/usr/bin/env python3
"""TollVeil v15 Phase 1: Streaming OBU ledger, coupled corridor solver,
rolling fleet AvailableMargin pool, and zero-leak public M_infra fault settlement.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from circom_crypto import (
    DOMAIN_FAULT,
    DOMAIN_SLOT,
    FIELD_P,
    STATUS_VALID,
    EdDSAPoseidonSig,
    InfraBroadcaster,
    InfraFaultBroadcast,
    OBUKeyPair,
    commit_state,
    poseidon,
    verify_eddsa_poseidon,
)

NODE_BIN = "/opt/homebrew/bin/node"
RAPIDSNARK_BIN = "rapidsnark"
SNARKJS_BIN = "/usr/local/bin/snarkjs"


class LedgerError(Exception):
    """Raised when a protocol invariant or authorization check rejects a transition."""


@dataclass(frozen=True)
class EdgeSpec:
    u: int
    v: int
    w_lo: int
    w_hi: int


class CoupledCorridorModel:
    """Exact coupled DAG shortest/longest-path solver over a layered corridor graph."""

    def __init__(
        self,
        corridor_id: int,
        n_slots: int,
        n_vertices: int,
        entry_vertices: set[int],
        exit_vertices: set[int],
        layer_edges: list[list[EdgeSpec]],
    ):
        assert len(layer_edges) == n_slots
        self.corridor_id = corridor_id
        self.n_slots = n_slots
        self.n_vertices = n_vertices
        self.entry_vertices = set(entry_vertices)
        self.exit_vertices = set(exit_vertices)
        self.layer_edges = layer_edges

    def coupled_bounds(
        self,
        opened_slots: dict[int, tuple[int, int, int]],
        excused_slots: set[int] | None = None,
    ) -> tuple[int, int]:
        """Compute exact coupled [L*, U*] over all compatible legal paths.

        opened_slots maps slot_idx -> (u_i, v_i, exact_fee_i).
        excused_slots is the corroborated roadside outage set M = F ∩ M_infra:
          excused slots preserve path connectivity (all legal edges remain traversable)
          and incur 0 terminal fee (roadside waiver).
        Uncorroborated missing/withheld slots (not in opened_slots and not in excused_slots)
        incur [w_lo, w_hi] over legal edges, so worst-case upper bound U* charges the
        maximum compatible path cost (zero extra discount).
        """
        excused = excused_slots or set()
        INF = 10**18
        dp_min = [INF] * self.n_vertices
        dp_max = [-INF] * self.n_vertices
        for v in self.entry_vertices:
            dp_min[v] = 0
            dp_max[v] = 0

        for i in range(self.n_slots):
            nxt_min = [INF] * self.n_vertices
            nxt_max = [-INF] * self.n_vertices
            if i in opened_slots:
                ou, ov, exact_fee = opened_slots[i]
                # Validate edge exists in layer_edges
                found = False
                for e in self.layer_edges[i]:
                    if e.u == ou and e.v == ov:
                        found = True
                        break
                if not found:
                    raise ValueError(f"Opened edge ({ou},{ov}) illegal in slot {i}")
                if dp_min[ou] < INF:
                    if dp_min[ou] + exact_fee < nxt_min[ov]:
                        nxt_min[ov] = dp_min[ou] + exact_fee
                    if dp_max[ou] + exact_fee > nxt_max[ov]:
                        nxt_max[ov] = dp_max[ou] + exact_fee
            else:
                is_excused = i in excused
                for e in self.layer_edges[i]:
                    if dp_min[e.u] == INF:
                        continue
                    c_lo = 0 if is_excused else e.w_lo
                    c_hi = 0 if is_excused else e.w_hi
                    cand_min = dp_min[e.u] + c_lo
                    cand_max = dp_max[e.u] + c_hi
                    if cand_min < nxt_min[e.v]:
                        nxt_min[e.v] = cand_min
                    if cand_max > nxt_max[e.v]:
                        nxt_max[e.v] = cand_max
            dp_min, dp_max = nxt_min, nxt_max

        valid_min = [dp_min[v] for v in self.exit_vertices if dp_min[v] < INF]
        valid_max = [dp_max[v] for v in self.exit_vertices if dp_max[v] > -INF]
        if not valid_min or not valid_max:
            raise ValueError("No feasible path consistent with opened slots")
        return min(valid_min), max(valid_max)

    def initial_bounds(self) -> tuple[int, int]:
        """t=0 bounds with ZERO future trajectory input and ZERO preset fault mask F."""
        return self.coupled_bounds(opened_slots={}, excused_slots=set())

    def terminal_charge(
        self,
        opened_slots: dict[int, tuple[int, int, int]],
        obu_fault_mask: int,
        infra_fault_mask: int,
    ) -> int:
        """Incentive-compatible terminal charge.

        Only slots corroborated by BOTH OBU hardware outage F AND public roadside broadcast
        M_infra (M = F ∩ M_infra) receive roadside waiver; any uncorroborated loss or
        withheld slot is charged at the worst-case compatible coupled upper bound U*.
        """
        excused = set()
        corroborated_mask = obu_fault_mask & infra_fault_mask
        for i in range(self.n_slots):
            if (corroborated_mask >> i) & 1:
                if i in opened_slots:
                    raise ValueError(f"Slot {i} already opened cannot be in fault mask")
                excused.add(i)
        _, u_final = self.coupled_bounds(opened_slots=opened_slots, excused_slots=excused)
        return u_final


class StreamSlotProverVerifier:
    """Wrapper around compiled StreamSlotAuth(8) Circom + rapidsnark + snarkjs verifier."""

    def __init__(self, build_dir: Path):
        self.build_dir = build_dir
        self.gen_witness_js = build_dir / "stream_slot_auth_js/generate_witness.js"
        self.wasm_path = build_dir / "stream_slot_auth_js/stream_slot_auth.wasm"
        self.zkey_path = build_dir / "stream_slot_auth.zkey"
        self.vkey_path = build_dir / "stream_slot_auth_vkey.json"
        for p in (self.gen_witness_js, self.wasm_path, self.zkey_path, self.vkey_path):
            if not p.exists():
                raise FileNotFoundError(f"Missing StreamSlotAuth artifact: {p}")

    def prove(self, witness_inputs: dict) -> tuple[dict, list[str], float]:
        with tempfile.TemporaryDirectory(prefix="slot_prove_") as td:
            tdp = Path(td)
            inp = tdp / "input.json"
            wtns = tdp / "witness.wtns"
            proof_p = tdp / "proof.json"
            pub_p = tdp / "public.json"
            inp.write_text(json.dumps({k: str(v) for k, v in witness_inputs.items()}), encoding="utf-8")

            t0 = time.perf_counter()
            wres = subprocess.run(
                [NODE_BIN, str(self.gen_witness_js), str(self.wasm_path), str(inp), str(wtns)],
                capture_output=True,
                text=True,
            )
            if wres.returncode != 0:
                raise ValueError(f"Witness generation rejected: {wres.stderr.strip() or wres.stdout.strip()}")

            pres = subprocess.run(
                [RAPIDSNARK_BIN, str(self.zkey_path), str(wtns), str(proof_p), str(pub_p)],
                capture_output=True,
                text=True,
            )
            if pres.returncode != 0:
                raise RuntimeError(f"rapidsnark failed: {pres.stderr.strip()}")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            proof = json.loads(proof_p.read_text(encoding="utf-8"))
            public_signals = json.loads(pub_p.read_text(encoding="utf-8"))
            return proof, public_signals, round(elapsed_ms, 3)

    def verify(self, proof: dict, public_signals: list[str]) -> bool:
        with tempfile.TemporaryDirectory(prefix="slot_verify_") as td:
            tdp = Path(td)
            proof_p = tdp / "proof.json"
            pub_p = tdp / "public.json"
            proof_p.write_text(json.dumps(proof), encoding="utf-8")
            pub_p.write_text(json.dumps(public_signals), encoding="utf-8")
            vres = subprocess.run(
                [NODE_BIN, SNARKJS_BIN, "groth16", "verify", str(self.vkey_path), str(pub_p), str(proof_p)],
                capture_output=True,
                text=True,
            )
            return vres.returncode == 0 and "OK!" in vres.stdout


class TollVeilStreamingLedger:
    """SQLite BEGIN IMMEDIATE atomic CAS ledger with fleet rolling AvailableMargin pool."""

    def __init__(self, db_path: Path | str, proof_verifier: Callable[[dict, list[str]], bool]):
        self.db_path = str(db_path)
        self.proof_verifier = proof_verifier
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=FULL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                available_margin INTEGER NOT NULL CHECK (available_margin >= 0),
                locked_escrow INTEGER NOT NULL CHECK (locked_escrow >= 0),
                total_charged INTEGER NOT NULL CHECK (total_charged >= 0),
                total_swept INTEGER NOT NULL CHECK (total_swept >= 0),
                sweep_fees_paid INTEGER NOT NULL CHECK (sweep_fees_paid >= 0),
                internal_transfer_fees_paid INTEGER NOT NULL DEFAULT 0 CHECK (internal_transfer_fees_paid = 0),
                version INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(account_id),
                corridor_id INTEGER NOT NULL,
                epoch_id INTEGER NOT NULL,
                n_slots INTEGER NOT NULL,
                model_root TEXT NOT NULL,
                tariff_root TEXT NOT NULL,
                pk_obu_commit TEXT NOT NULL,
                deposit_D INTEGER NOT NULL CHECK (deposit_D >= 0),
                release_quantum INTEGER NOT NULL CHECK (release_quantum >= 1),
                deadline_d INTEGER NOT NULL,
                grace_g INTEGER NOT NULL CHECK (grace_g >= 0),
                state_commit TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 0,
                cumulative_C INTEGER NOT NULL DEFAULT 0 CHECK (cumulative_C >= 0),
                cumulative_R INTEGER NOT NULL DEFAULT 0 CHECK (cumulative_R >= 0),
                status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED')),
                final_charge INTEGER,
                final_refund INTEGER,
                closed_mode TEXT,
                infra_fault_mask INTEGER
            );
            CREATE TABLE IF NOT EXISTS transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(session_id),
                from_rev INTEGER NOT NULL,
                to_rev INTEGER NOT NULL,
                prev_state_commit TEXT NOT NULL,
                new_state_commit TEXT NOT NULL,
                delta_C INTEGER NOT NULL,
                delta_R INTEGER NOT NULL,
                proof_sha256 TEXT NOT NULL UNIQUE,
                created_at_ns INTEGER NOT NULL
            );
            """
        )

    def close_db(self) -> None:
        self.conn.close()

    def snapshot_hash(self) -> str:
        """Deterministic digest of all ledger tables (used to prove zero pollution on rejected ops)."""
        with self._lock:
            snap = {
                "accounts": self.conn.execute("SELECT * FROM accounts ORDER BY account_id;").fetchall(),
                "sessions": self.conn.execute("SELECT * FROM sessions ORDER BY session_id;").fetchall(),
                "transitions": self.conn.execute(
                    "SELECT session_id, from_rev, to_rev, prev_state_commit, new_state_commit, delta_C, delta_R, proof_sha256 "
                    "FROM transitions ORDER BY id;"
                ).fetchall(),
            }
        return hashlib.sha256(json.dumps(snap, sort_keys=True).encode("utf-8")).hexdigest()

    def get_account(self, account_id: str) -> dict:
        row = self.conn.execute(
            "SELECT account_id, available_margin, locked_escrow, total_charged, total_swept, sweep_fees_paid, internal_transfer_fees_paid, version "
            "FROM accounts WHERE account_id = ?;",
            (account_id,),
        ).fetchone()
        if row is None:
            raise LedgerError(f"Unknown account: {account_id}")
        keys = [
            "account_id", "available_margin", "locked_escrow", "total_charged",
            "total_swept", "sweep_fees_paid", "internal_transfer_fees_paid", "version",
        ]
        return dict(zip(keys, row))

    def get_session(self, session_id: int) -> dict:
        row = self.conn.execute(
            "SELECT session_id, account_id, corridor_id, epoch_id, n_slots, model_root, tariff_root, "
            "pk_obu_commit, deposit_D, release_quantum, deadline_d, grace_g, state_commit, revision, "
            "cumulative_C, cumulative_R, status, final_charge, final_refund, closed_mode, infra_fault_mask "
            "FROM sessions WHERE session_id = ?;",
            (str(session_id),),
        ).fetchone()
        if row is None:
            raise LedgerError(f"Unknown session: {session_id}")
        keys = [
            "session_id", "account_id", "corridor_id", "epoch_id", "n_slots", "model_root", "tariff_root",
            "pk_obu_commit", "deposit_D", "release_quantum", "deadline_d", "grace_g", "state_commit", "revision",
            "cumulative_C", "cumulative_R", "status", "final_charge", "final_refund", "closed_mode", "infra_fault_mask",
        ]
        return dict(zip(keys, row))

    def fund_account(self, account_id: str, amount: int) -> dict:
        if amount <= 0:
            raise LedgerError("Funding amount must be positive")
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self.conn.execute(
                    "SELECT available_margin FROM accounts WHERE account_id = ?;", (account_id,)
                ).fetchone()
                if cur is None:
                    self.conn.execute(
                        "INSERT INTO accounts (account_id, available_margin, locked_escrow, total_charged, total_swept, sweep_fees_paid, internal_transfer_fees_paid, version) "
                        "VALUES (?, ?, 0, 0, 0, 0, 0, 1);",
                        (account_id, amount),
                    )
                else:
                    self.conn.execute(
                        "UPDATE accounts SET available_margin = available_margin + ?, version = version + 1 WHERE account_id = ?;",
                        (amount, account_id),
                    )
                self.conn.execute("COMMIT;")
            except Exception:
                self.conn.execute("ROLLBACK;")
                raise
        return self.get_account(account_id)

    def register(
        self,
        *,
        account_id: str,
        session_id: int,
        corridor_id: int,
        epoch_id: int,
        n_slots: int,
        model_root: int,
        tariff_root: int,
        pk_obu_commit: int,
        init_state_commit: int,
        deposit_D: int,
        u0_star: int,
        release_quantum: int,
        deadline_d: int,
        grace_g: int,
        now_ts: int,
    ) -> dict:
        """t=0 corridor-entry registration: ZERO future trajectory inputs, ZERO preset fault mask F.
        Locks deposit_D from account's rolling AvailableMargin pool with 0 internal transfer fee.
        """
        if deposit_D < u0_star or deposit_D <= 0:
            raise LedgerError(f"Insufficient deposit_D={deposit_D} < U0*={u0_star}")
        if release_quantum < 1:
            raise LedgerError("release_quantum must be >= 1")
        if deadline_d <= now_ts or grace_g < 0:
            raise LedgerError("Invalid deadline/grace window")

        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                acc = self.conn.execute(
                    "SELECT available_margin FROM accounts WHERE account_id = ?;", (account_id,)
                ).fetchone()
                if acc is None:
                    raise LedgerError(f"Unknown account: {account_id}")
                if acc[0] < deposit_D:
                    raise LedgerError(f"Insufficient available_margin={acc[0]} for deposit_D={deposit_D}")
                exists = self.conn.execute(
                    "SELECT 1 FROM sessions WHERE session_id = ?;", (str(session_id),)
                ).fetchone()
                if exists is not None:
                    raise LedgerError(f"Duplicate session_id: {session_id}")

                self.conn.execute(
                    "UPDATE accounts SET available_margin = available_margin - ?, locked_escrow = locked_escrow + ?, version = version + 1 "
                    "WHERE account_id = ? AND available_margin >= ?;",
                    (deposit_D, deposit_D, account_id, deposit_D),
                )
                if self.conn.total_changes == 0:
                    raise LedgerError("Concurrent margin contention")

                self.conn.execute(
                    """
                    INSERT INTO sessions (
                        session_id, account_id, corridor_id, epoch_id, n_slots,
                        model_root, tariff_root, pk_obu_commit, deposit_D,
                        release_quantum, deadline_d, grace_g, state_commit,
                        revision, cumulative_C, cumulative_R, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 'OPEN');
                    """,
                    (
                        str(session_id), account_id, corridor_id, epoch_id, n_slots,
                        str(model_root), str(tariff_root), str(pk_obu_commit), deposit_D,
                        release_quantum, deadline_d, grace_g, str(init_state_commit),
                    ),
                )
                self.conn.execute("COMMIT;")
            except Exception:
                self.conn.execute("ROLLBACK;")
                raise
        return self.get_session(session_id)

    def update(
        self,
        *,
        session_id: int,
        expected_revision: int,
        prev_state_commit: int,
        new_state_commit: int,
        delta_C: int,
        delta_R: int,
        proof: dict,
        public_signals: list[str],
        now_ts: int,
    ) -> dict:
        """Streaming single-slot update with Groth16 proof verification and atomic CAS.
        Immediately credits delta_R to account AvailableMargin with 0 internal fee.
        """
        if delta_C < 0 or delta_R < 0:
            raise LedgerError("Negative delta_C or delta_R rejected")
        if len(public_signals) != 10:
            raise LedgerError(f"Expected 10 public signals, got {len(public_signals)}")

        # Pre-fetch authoritative session before expensive ZK verify
        sess_pre = self.get_session(session_id)
        if sess_pre["status"] != "OPEN":
            raise LedgerError("Session already closed")
        if now_ts > sess_pre["deadline_d"]:
            raise LedgerError("Update after deadline rejected")
        if expected_revision != sess_pre["revision"]:
            raise LedgerError(f"Stale revision {expected_revision} != {sess_pre['revision']}")
        if str(prev_state_commit) != sess_pre["state_commit"]:
            raise LedgerError("Predecessor state_commit mismatch (replay or fork)")
        if str(new_state_commit) == str(prev_state_commit):
            raise LedgerError("No-op state_commit transition rejected")
        if delta_R % sess_pre["release_quantum"] != 0:
            raise LedgerError(f"delta_R={delta_R} violates release_quantum={sess_pre['release_quantum']}")
        if sess_pre["cumulative_C"] + delta_C + sess_pre["cumulative_R"] + delta_R > sess_pre["deposit_D"]:
            raise LedgerError("Solvency violation: C + R > deposit_D")

        # Authoritative public signal binding (never trust caller restatements)
        expected_pub = [
            str(sess_pre["session_id"]),
            str(sess_pre["corridor_id"]),
            str(sess_pre["model_root"]),
            str(sess_pre["tariff_root"]),
            str(sess_pre["pk_obu_commit"]),
            str(sess_pre["deposit_D"]),
            str(sess_pre["state_commit"]),
            str(new_state_commit),
            str(delta_C),
            str(delta_R),
        ]
        if [str(x) for x in public_signals] != expected_pub:
            raise LedgerError("Public signals do not match authoritative session parameters")

        # Verify Groth16 proof BEFORE acquiring write lock
        if not self.proof_verifier(proof, expected_pub):
            raise LedgerError("Groth16 proof verification failed")

        proof_sha = hashlib.sha256(
            json.dumps({"proof": proof, "pub": expected_pub}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                dup = self.conn.execute(
                    "SELECT 1 FROM transitions WHERE proof_sha256 = ?;", (proof_sha,)
                ).fetchone()
                if dup is not None:
                    raise LedgerError("Proof replay detected")

                cur = self.conn.execute(
                    "SELECT status, revision, state_commit, cumulative_C, cumulative_R, deposit_D, account_id "
                    "FROM sessions WHERE session_id = ?;",
                    (str(session_id),),
                ).fetchone()
                if cur is None or cur[0] != "OPEN":
                    raise LedgerError("Session not open at commit time")
                if cur[1] != expected_revision or cur[2] != str(prev_state_commit):
                    raise LedgerError("CAS conflict: session advanced concurrently")
                new_C = cur[3] + delta_C
                new_R = cur[4] + delta_R
                if new_C + new_R > cur[5]:
                    raise LedgerError("Solvency invariant failed at commit")

                self.conn.execute(
                    "UPDATE sessions SET state_commit = ?, revision = revision + 1, cumulative_C = ?, cumulative_R = ? "
                    "WHERE session_id = ? AND revision = ? AND status = 'OPEN';",
                    (str(new_state_commit), new_C, new_R, str(session_id), expected_revision),
                )
                # Zero-fee immediate credit of delta_R to fleet rolling AvailableMargin pool
                self.conn.execute(
                    "UPDATE accounts SET available_margin = available_margin + ?, "
                    "locked_escrow = locked_escrow - ?, total_charged = total_charged + ?, version = version + 1 "
                    "WHERE account_id = ? AND locked_escrow >= ?;",
                    (delta_R, delta_C + delta_R, delta_C, cur[6], delta_C + delta_R),
                )
                self.conn.execute(
                    "INSERT INTO transitions (session_id, from_rev, to_rev, prev_state_commit, new_state_commit, delta_C, delta_R, proof_sha256, created_at_ns) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    (str(session_id), expected_revision, expected_revision + 1, str(prev_state_commit), str(new_state_commit), delta_C, delta_R, proof_sha, time.time_ns()),
                )
                self.conn.execute("COMMIT;")
            except Exception:
                self.conn.execute("ROLLBACK;")
                raise
        return self.get_session(session_id)

    def close_session(
        self,
        *,
        session_id: int,
        expected_revision: int,
        mode: str,
        final_charge: int,
        pending_mask: int,
        L_final: int,
        U_final: int,
        state_salt: int,
        fault_mask: int = 0,
        obu_fault_sig: EdDSAPoseidonSig | None = None,
        obu_pk: tuple[int, int] | None = None,
        pk_salt: int | None = None,
        infra_bcast: InfraFaultBroadcast | None = None,
        expected_broadcaster_pubkey: str | None = None,
        now_ts: int = 0,
    ) -> dict:
        """Close session (EARLY_EXACT or EXPIRY_FAULT) with CAS anti-double-close.
        Verifies state commitment opening, OBU fault signature (ensuring no valid opened slot
        is overwritten by F), and public M_infra Ed25519 signature.
        """
        if mode not in ("EARLY_EXACT", "EXPIRY_FAULT"):
            raise LedgerError(f"Unsupported close mode: {mode}")

        sess = self.get_session(session_id)
        if sess["status"] != "OPEN":
            raise LedgerError("Double-close rejected: session already CLOSED")
        if expected_revision != sess["revision"]:
            raise LedgerError(f"Close stale revision {expected_revision} != {sess['revision']}")

        # Verify state_commit opens to claimed (pending_mask, L_final, U_final, C, R, state_salt)
        recomputed_commit = commit_state(
            session_id=int(sess["session_id"]),
            corridor_id=sess["corridor_id"],
            pending_mask=pending_mask,
            L=L_final,
            U=U_final,
            C=sess["cumulative_C"],
            R=sess["cumulative_R"],
            salt=state_salt,
        )
        if str(recomputed_commit) != sess["state_commit"]:
            raise LedgerError("Close state_commit opening mismatch")

        effective_infra_mask = 0
        if mode == "EARLY_EXACT":
            if pending_mask != 0 or fault_mask != 0:
                raise LedgerError("EARLY_EXACT requires all slots opened (pending_mask=0, fault_mask=0)")
            if L_final != U_final or final_charge != L_final:
                raise LedgerError("EARLY_EXACT requires L_final == U_final == final_charge")
        else:
            if now_ts > sess["deadline_d"] + sess["grace_g"]:
                raise LedgerError("Close past deadline + grace window rejected")
            # Every faulted slot MUST still be in pending_mask (cannot overwrite an already-opened valid slot!)
            if (fault_mask & (~pending_mask)) != 0:
                raise LedgerError("Forged fault_mask attempts to cover already-opened valid slot")
            if obu_fault_sig is None or obu_pk is None or pk_salt is None:
                raise LedgerError("EXPIRY_FAULT requires OBU fault-set signature and pk opening")
            # Verify OBU pk opens pk_obu_commit
            if str(poseidon([obu_pk[0], obu_pk[1], pk_salt])) != sess["pk_obu_commit"]:
                raise LedgerError("OBU pk does not open session pk_obu_commit")
            expected_msg = poseidon([DOMAIN_FAULT, int(sess["session_id"]), fault_mask])
            if obu_fault_sig.M != expected_msg or not verify_eddsa_poseidon(obu_pk[0], obu_pk[1], obu_fault_sig):
                raise LedgerError("Invalid OBU EdDSA-Poseidon fault-set signature")

            if infra_bcast is not None:
                if expected_broadcaster_pubkey is None:
                    raise LedgerError("Missing expected broadcaster pubkey")
                if not InfraBroadcaster.verify_broadcast(infra_bcast, expected_broadcaster_pubkey):
                    raise LedgerError("Invalid public M_infra broadcast signature")
                if infra_bcast.corridor_id != sess["corridor_id"] or infra_bcast.epoch_id != sess["epoch_id"]:
                    raise LedgerError("Public M_infra broadcast corridor/epoch mismatch")
                effective_infra_mask = infra_bcast.infra_fault_mask

            # Incentive-compatible charge bound: if NO corroborated roadside outage (F & M_infra == 0),
            # terminal charge MUST be >= U_final (zero uncorroborated discount!)
            corroborated = fault_mask & effective_infra_mask
            if corroborated == 0 and final_charge < U_final:
                raise LedgerError(
                    f"Uncorroborated fault undercharge rejected: final_charge={final_charge} < U_final={U_final}"
                )

        if final_charge < sess["cumulative_C"]:
            raise LedgerError("final_charge < already-collected cumulative_C")
        if final_charge > sess["deposit_D"] - sess["cumulative_R"]:
            raise LedgerError("Solvency violation at close: final_charge + cumulative_R > deposit_D")

        rem_charge = final_charge - sess["cumulative_C"]
        final_refund = sess["deposit_D"] - final_charge
        rem_refund = final_refund - sess["cumulative_R"]
        if rem_charge < 0 or rem_refund < 0:
            raise LedgerError("Accounting conservation violation")

        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self.conn.execute(
                    "SELECT status, revision, account_id, deposit_D, cumulative_C, cumulative_R "
                    "FROM sessions WHERE session_id = ?;",
                    (str(session_id),),
                ).fetchone()
                if cur is None or cur[0] != "OPEN":
                    raise LedgerError("Concurrent double-close rejected at CAS")
                if cur[1] != expected_revision:
                    raise LedgerError("Revision changed concurrently before close")

                self.conn.execute(
                    "UPDATE sessions SET status = 'CLOSED', revision = revision + 1, "
                    "cumulative_C = ?, cumulative_R = ?, final_charge = ?, final_refund = ?, "
                    "closed_mode = ?, infra_fault_mask = ? "
                    "WHERE session_id = ? AND status = 'OPEN' AND revision = ?;",
                    (
                        final_charge, final_refund, final_charge, final_refund,
                        mode, effective_infra_mask, str(session_id), expected_revision,
                    ),
                )
                self.conn.execute(
                    "UPDATE accounts SET available_margin = available_margin + ?, "
                    "locked_escrow = locked_escrow - ?, total_charged = total_charged + ?, version = version + 1 "
                    "WHERE account_id = ? AND locked_escrow >= ?;",
                    (rem_refund, rem_charge + rem_refund, rem_charge, cur[2], rem_charge + rem_refund),
                )
                self.conn.execute("COMMIT;")
            except Exception:
                self.conn.execute("ROLLBACK;")
                raise
        return self.get_session(session_id)

    def sweep_to_bank(self, account_id: str, amount: int, bank_fee: int) -> dict:
        """Periodic external bank sweep: only external sweeps pay bank_fee."""
        if amount <= bank_fee or bank_fee < 0:
            raise LedgerError("Invalid bank sweep amount or fee")
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                acc = self.conn.execute(
                    "SELECT available_margin FROM accounts WHERE account_id = ?;", (account_id,)
                ).fetchone()
                if acc is None or acc[0] < amount:
                    raise LedgerError("Insufficient available_margin for bank sweep")
                self.conn.execute(
                    "UPDATE accounts SET available_margin = available_margin - ?, "
                    "total_swept = total_swept + ?, sweep_fees_paid = sweep_fees_paid + ?, version = version + 1 "
                    "WHERE account_id = ?;",
                    (amount, amount - bank_fee, bank_fee, account_id),
                )
                self.conn.execute("COMMIT;")
            except Exception:
                self.conn.execute("ROLLBACK;")
                raise
        return self.get_account(account_id)
