"""Atomic escrow transitions for the v15 causal proof interface."""

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Callable

from circom_crypto import FIELD_P, InfraBroadcaster, InfraFaultBroadcast


@dataclass(frozen=True)
class Enrollment:
    sid: int
    profile: int
    entry: int
    key_commitment: int
    deposit: int
    genesis: int
    epoch: int
    closes_at: int


class CausalLedger:
    """The authority supplies enrollment and signed corridor bulletins.

    The ledger owns input order, public values, and settlement accounting.
    A retry may supply a fresh proof for the same statement. The session
    revision prevents that statement from being applied twice.
    """

    def __init__(self, path: Path, verifier: Callable[[int, list, dict], bool],
                 broadcaster: str) -> None:
        self.path = path
        self.verify = verifier
        self.broadcaster = broadcaster
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS session (sid TEXT PRIMARY KEY, profile TEXT, "
                "entry INTEGER, pk TEXT, deposit INTEGER, state TEXT, epoch INTEGER, "
                "closes_at INTEGER, revision INTEGER NOT NULL DEFAULT 0, "
                "returned INTEGER NOT NULL DEFAULT 0, closed INTEGER NOT NULL DEFAULT 0, "
                "charged INTEGER NOT NULL DEFAULT 0)"
            )

    @staticmethod
    def field(x) -> int:
        if type(x) is not int or not 0 <= x < FIELD_P:
            raise ValueError("noncanonical scalar")
        return x

    def register_trusted(self, x: Enrollment, exact_causal_cap: int) -> None:
        for item in (x.sid,x.profile,x.key_commitment,x.genesis):
            self.field(item)
        if not 0 <= x.entry < 396 or not 0 <= exact_causal_cap <= x.deposit < 2**32:
            raise ValueError("invalid enrollment")
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO session(sid,profile,entry,pk,deposit,state,epoch,closes_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (str(x.sid),str(x.profile),x.entry,str(x.key_commitment),x.deposit,
                 str(x.genesis),x.epoch,x.closes_at),
            )

    def current(self, sid: int) -> dict:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            row = db.execute("SELECT * FROM session WHERE sid=?", (str(self.field(sid)),)).fetchone()
        if row is None:
            raise ValueError("unknown session")
        return dict(row)

    def apply(self, *, sid: int, revision: int, role: int, proof: dict,
              next_state: int, refund_delta: int, charge: int, now: int,
              bulletin: InfraFaultBroadcast | None = None) -> dict:
        old=self.current(sid)
        if old["revision"]!=revision or old["closed"]:
            raise ValueError("stale or closed session")
        if type(revision) is not int or not 0 <= revision < 2**32-1:
            raise ValueError("invalid revision")
        if (type(refund_delta) is not int or type(charge) is not int or
            min(refund_delta,charge)<0 or refund_delta+charge+old["returned"]>old["deposit"]):
            raise ValueError("invalid amounts")
        if role==1:
            if charge or bulletin is not None or now>=old["closes_at"]:
                raise ValueError("invalid update authority")
            mask=0
        elif role==2:
            if next_state or now<old["closes_at"] or bulletin is None:
                raise ValueError("close requires epoch bulletin and terminal time")
            if (bulletin.corridor_id!=int(old["profile"]) or bulletin.epoch_id!=old["epoch"] or
                not InfraBroadcaster.verify_broadcast(bulletin,self.broadcaster)):
                raise ValueError("invalid corridor bulletin")
            mask=bulletin.infra_fault_mask
            if not 0<=mask<2**8 or refund_delta+charge+old["returned"]!=old["deposit"]:
                raise ValueError("invalid final accounting")
        else:
            raise ValueError("unknown relation")
        self.field(next_state)
        public=list(map(str,[role,sid,revision,old["profile"],old["entry"],old["pk"],old["deposit"],
                            mask,old["state"],next_state,refund_delta,charge]))
        if not self.verify(role,public,proof):
            raise ValueError("invalid proof")
        with sqlite3.connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            cas=db.execute(
                "UPDATE session SET state=?,revision=revision+1,returned=returned+?,closed=?,charged=? "
                "WHERE sid=? AND revision=? AND state=? AND closed=0",
                (str(next_state),refund_delta,int(role==2),charge,str(sid),revision,old["state"]),
            )
            if cas.rowcount!=1:
                raise ValueError("compare-and-swap rejected stale statement")
        return self.current(sid)
