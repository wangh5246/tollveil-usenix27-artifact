"""Proof-gated escrow and fleet account updates under one SQLite transaction."""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from time import perf_counter
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from circom_crypto import FIELD_P, InfraBroadcaster, InfraFaultBroadcast
from live_groth16 import LiveGroth16Verifier


ACCOUNT_LIMIT = 1 << 60
ENROLLMENT_DOMAIN = b"tollveil-causal-escrow-registration-v2\x00"


def json_bytes(record) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def bounded(value: int, upper: int) -> int:
    if type(value) is not int or not 0 <= value < upper:
        raise ValueError("Out-of-range or noncanonical value")
    return value


@dataclass(frozen=True)
class Enrollment:
    sid: int
    profile: int
    account: str
    entry: int
    vehicle_class: int
    pk_commit: int
    deposit: int
    genesis: int
    epoch: int
    started_at: int
    closes_at: int

    def signed_message(self) -> bytes:
        return ENROLLMENT_DOMAIN + json_bytes(asdict(self))


@dataclass(frozen=True)
class Policy:
    family: str
    slots: int
    initial_upper: dict[tuple[int, int], int]


class UnifiedCausalEscrowLedger:
    def __init__(self, path: Path, verifier: LiveGroth16Verifier, policies: dict[int, Policy],
                 registrar: Ed25519PublicKey, broadcaster_key_hex: str) -> None:
        if not isinstance(verifier, LiveGroth16Verifier):
            raise TypeError("A live Groth16 verifier is required")
        self.path = path
        self.verifier = verifier
        self.policies = {
            profile: Policy(policy.family, policy.slots, MappingProxyType(dict(policy.initial_upper)))
            for profile, policy in policies.items()
        }
        for policy in self.policies.values():
            valid = (policy.family in {"causal", "m06a"} and policy.slots == 8) or (
                policy.family == "gap" and policy.slots == 16
            )
            if not valid:
                raise ValueError("Policy has no matching update and close relations")
        self.registrar = registrar
        self.broadcaster_key_hex = broadcaster_key_hex
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    account TEXT PRIMARY KEY, funded INTEGER NOT NULL, available INTEGER NOT NULL,
                    locked INTEGER NOT NULL, charged INTEGER NOT NULL,
                    CHECK (available >= 0 AND locked >= 0 AND charged >= 0),
                    CHECK (funded = available + locked + charged)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY, profile TEXT NOT NULL, account TEXT NOT NULL REFERENCES accounts,
                    entry INTEGER NOT NULL, vehicle_class INTEGER NOT NULL, pk_commit TEXT NOT NULL,
                    deposit INTEGER NOT NULL, state TEXT NOT NULL, epoch INTEGER NOT NULL,
                    started_at INTEGER NOT NULL, closes_at INTEGER NOT NULL,
                    last_accepted_at INTEGER NOT NULL, enrollment_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0, returned INTEGER NOT NULL DEFAULT 0,
                    closed INTEGER NOT NULL DEFAULT 0, charged INTEGER NOT NULL DEFAULT 0,
                    certified_digest TEXT, certified_statement TEXT, certified_revision INTEGER
                );
                CREATE TABLE IF NOT EXISTS bulletins (
                    profile TEXT NOT NULL, epoch INTEGER NOT NULL, mask INTEGER NOT NULL, signature TEXT NOT NULL,
                    PRIMARY KEY (profile, epoch)
                );
                CREATE TABLE IF NOT EXISTS admissions (
                    sid TEXT NOT NULL REFERENCES sessions, revision INTEGER NOT NULL,
                    intent TEXT NOT NULL, relation TEXT NOT NULL, statement TEXT NOT NULL, receipt TEXT NOT NULL,
                    PRIMARY KEY (sid, revision)
                );
            """)

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def fund(self, account: str, amount: int) -> None:
        bounded(amount, ACCOUNT_LIMIT)
        with self._transaction() as db:
            result = db.execute(
                "INSERT INTO accounts VALUES (?,?,?,0,0) ON CONFLICT(account) DO UPDATE SET "
                "funded=funded+excluded.funded, available=available+excluded.available "
                "WHERE funded+excluded.funded<?",
                (account, amount, amount, ACCOUNT_LIMIT),
            )
            if result.rowcount != 1:
                raise ValueError("Fleet funding limit would be exceeded")

    def register(self, enrollment: Enrollment, authority_signature: bytes) -> None:
        self.registrar.verify(authority_signature, enrollment.signed_message())
        x = enrollment
        for field in (x.sid, x.profile, x.pk_commit, x.genesis):
            bounded(field, FIELD_P)
        for field in (x.epoch, x.started_at, x.closes_at):
            bounded(field, 1 << 63)
        bounded(x.entry, 1 << 31)
        bounded(x.vehicle_class, 3)
        bounded(x.deposit, 1 << 32)
        policy = self.policies.get(x.profile)
        cap = policy.initial_upper.get((x.entry, x.vehicle_class)) if policy else None
        if cap is None or not 0 <= cap <= x.deposit or x.started_at >= x.closes_at:
            raise ValueError("Invalid genesis or deposit under registered policy")
        with self._transaction() as db:
            transferred = db.execute(
                "UPDATE accounts SET available=available-?, locked=locked+? WHERE account=? AND available>=?",
                (x.deposit, x.deposit, x.account, x.deposit),
            )
            if transferred.rowcount != 1:
                raise ValueError("Insufficient available margin")
            db.execute(
                "INSERT INTO sessions(sid,profile,account,entry,vehicle_class,pk_commit,deposit,state,"
                "epoch,started_at,closes_at,last_accepted_at,enrollment_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(x.sid), str(x.profile), x.account, x.entry, x.vehicle_class, str(x.pk_commit), x.deposit,
                 str(x.genesis), x.epoch, x.started_at, x.closes_at, x.started_at,
                 sha256(x.signed_message() + authority_signature).hexdigest()),
            )

    def install_bulletin(self, bulletin: InfraFaultBroadcast) -> None:
        policy = self.policies.get(bounded(bulletin.corridor_id, FIELD_P))
        bounded(bulletin.epoch_id, 1 << 63)
        if policy is None:
            raise ValueError("Unknown bulletin scope")
        bounded(bulletin.infra_fault_mask, 1 << policy.slots)
        if not InfraBroadcaster.verify_broadcast(bulletin, self.broadcaster_key_hex):
            raise ValueError("Invalid bulletin signature")
        with self._transaction() as db:
            scope = (str(bulletin.corridor_id), bulletin.epoch_id)
            row = db.execute("SELECT mask,signature FROM bulletins WHERE profile=? AND epoch=?", scope).fetchone()
            signed = (bulletin.infra_fault_mask, bulletin.signature_hex)
            if row is None:
                db.execute("INSERT INTO bulletins VALUES (?,?,?,?)", (*scope, *signed))
            elif tuple(row) != signed:
                raise ValueError("A different bulletin is already registered for this epoch")

    def _mask(self, db, row) -> int:
        bulletin = db.execute(
            "SELECT mask,signature FROM bulletins WHERE profile=? AND epoch=?", (row["profile"], row["epoch"])
        ).fetchone()
        if bulletin is None:
            raise ValueError("No authorized bulletin for this terminal statement")
        signed = InfraFaultBroadcast(int(row["profile"]), row["epoch"], bulletin["mask"],
                                     bulletin["signature"], self.broadcaster_key_hex)
        if not InfraBroadcaster.verify_broadcast(signed, self.broadcaster_key_hex):
            raise ValueError("Registered bulletin signature failed")
        return signed.infra_fault_mask

    @staticmethod
    def _session(db, sid: int):
        row = db.execute("SELECT * FROM sessions WHERE sid=?", (str(bounded(sid, FIELD_P)),)).fetchone()
        if row is None:
            raise ValueError("Unknown escrow session")
        return row

    @staticmethod
    def _prior(row, revision: int, now: int) -> None:
        bounded(now, 1 << 63)
        if row["closed"] or row["revision"] != revision or now < row["last_accepted_at"]:
            raise ValueError("Stale or closed escrow session")

    @staticmethod
    def _gap_close_vector(row, mask: int, charge: int, refund_delta: int, digest: int, arm: int) -> tuple[str, ...]:
        return tuple(map(str, (
            205210 + arm, row["sid"], row["revision"], row["profile"], row["pk_commit"], row["state"],
            row["deposit"], row["returned"], mask, charge, refund_delta, digest,
        )))

    def certify_gap_close(self, *, sid: int, revision: int, digest: int, charge: int,
                          refund_delta: int, now: int, proof: dict, stateful: bool = False) -> dict:
        bounded(digest, FIELD_P)
        bounded(charge, 1 << 32)
        bounded(refund_delta, 1 << 32)
        bounded(revision, (1 << 32) - 1)
        start = perf_counter()
        with self._transaction() as db:
            row = self._session(db, sid)
            self._prior(row, revision, now)
            if self.policies[int(row["profile"])].family != "gap" or now < row["closes_at"]:
                raise ValueError("Gap certification requires completion of the registered epoch")
            if refund_delta + charge + row["returned"] != row["deposit"]:
                raise ValueError("Terminal amounts violate conservation")
            arm = 1 if stateful else 2
            relation = "gap_close_stateful" if stateful else "gap_close_raw"
            public = self._gap_close_vector(row, self._mask(db, row), charge, refund_delta, digest, arm)
            pairing_ms = self.verifier.verify(relation, public, proof)
            encoded = json_bytes(public).decode("ascii")
            if row["certified_digest"] is not None and row["certified_statement"] != encoded:
                raise ValueError("Different close statement already certified for this revision")
            db.execute("UPDATE sessions SET certified_digest=?, certified_revision=?, certified_statement=? WHERE sid=?",
                       (str(digest), revision, encoded, row["sid"]))
        return {"relation": relation, "pairing_ms": pairing_ms, "elapsed_ms": (perf_counter() - start) * 1000}

    def admit_update(self, *, sid: int, revision: int, next_state: int, refund_delta: int,
                     now: int, proof: dict) -> dict:
        return self._admit(sid, revision, 1, next_state, refund_delta, 0, None, now, proof)

    def admit_close(self, *, sid: int, revision: int, refund_delta: int, charge: int,
                    now: int, proof: dict, certified_digest: int | None = None) -> dict:
        return self._admit(sid, revision, 2, 0, refund_delta, charge, certified_digest, now, proof)

    def _admit(self, sid: int, revision: int, role: int, next_state: int, refund_delta: int,
               charge: int, certified_digest: int | None, now: int, proof: dict) -> dict:
        bounded(revision, (1 << 32) - 1)
        bounded(next_state, FIELD_P)
        bounded(refund_delta, 1 << 32)
        bounded(charge, 1 << 32)
        bounded(now, 1 << 63)
        if certified_digest is not None:
            bounded(certified_digest, FIELD_P)
        intent = json_bytes((role, next_state, refund_delta, charge, certified_digest)).decode("ascii")
        start = perf_counter()
        with self._transaction() as db:
            row = self._session(db, sid)
            recorded = db.execute("SELECT * FROM admissions WHERE sid=? AND revision=?", (row["sid"], revision)).fetchone()
            if recorded is not None:
                if recorded["intent"] != intent:
                    raise ValueError("Conflicting statement at an already accepted revision")
                self.verifier.verify(recorded["relation"], tuple(json.loads(recorded["statement"])), proof)
                return json.loads(recorded["receipt"])

            self._prior(row, revision, now)
            closed = role == 2
            remaining = row["deposit"] - row["returned"] - refund_delta - charge
            if remaining < 0 or (closed and remaining != 0):
                raise ValueError("Amounts violate escrow conservation")
            if not closed and (not next_state or now >= row["closes_at"]):
                raise ValueError("Update requires an open interval and nonzero successor")
            suffix = "close" if closed else "update"
            policy = self.policies[int(row["profile"])]
            mask = self._mask(db, row) if closed else 0
            if policy.family == "gap":
                if closed:
                    if now < row["closes_at"] or row["certified_revision"] != revision or (
                        certified_digest is None or row["certified_digest"] != str(certified_digest)
                    ):
                        raise ValueError("Missing certification for the active gap digest")
                    relation = "gap_close_digest"
                    public = self._gap_close_vector(row, mask, charge, refund_delta, certified_digest, 0)
                    if list(public[1:]) != json.loads(row["certified_statement"])[1:]:
                        raise ValueError("Digest close differs from the certified statement")
                else:
                    relation = f"gap_local_{policy.slots}"
                    public = tuple(map(str, (205101, sid, revision, row["profile"], row["pk_commit"],
                                             row["state"], next_state, row["deposit"], row["returned"], refund_delta)))
            else:
                if certified_digest is not None:
                    raise ValueError("Unexpected certificate for a full-corridor proof")
                relation = f"{policy.family}_{suffix}"
                if closed and now < row["closes_at"]:
                    mask |= 1 << policy.slots
                vehicle = (row["vehicle_class"],) if policy.family == "m06a" else ()
                public = tuple(map(str, (role, sid, revision, row["profile"], *vehicle, row["entry"],
                                         row["pk_commit"], row["deposit"], mask, row["state"],
                                         next_state, refund_delta, charge)))

            # BEGIN IMMEDIATE already holds the writer reservation. Proof failure
            # or a dead verifier rolls this transaction back before any balance change.
            pairing_ms = self.verifier.verify(relation, public, proof)
            cas = db.execute(
                "UPDATE sessions SET state=?, returned=returned+?, revision=revision+1, closed=?, charged=?, "
                "last_accepted_at=? WHERE sid=? AND revision=? AND state=? AND closed=0",
                (str(next_state), refund_delta, int(closed), charge, now, row["sid"], revision, row["state"]),
            )
            if cas.rowcount != 1:
                raise ValueError("Compare-and-swap failed")
            db.execute("UPDATE accounts SET available=available+?, locked=locked-?, charged=charged+? WHERE account=?",
                       (refund_delta, refund_delta + charge, charge, row["account"]))
            receipt = {
                "sid": row["sid"], "revision": revision + 1, "closed": closed, "resolved_at": now,
                "refund_delta": refund_delta, "charged": charge, "remaining": remaining,
                "relation": relation, "statement_sha256": sha256(json_bytes(public)).hexdigest(),
                "admitted_proof_sha256": sha256(json_bytes(proof)).hexdigest(),
                "pairing_ms": pairing_ms, "precommit_ms": (perf_counter() - start) * 1000,
            }
            db.execute("INSERT INTO admissions VALUES (?,?,?,?,?,?)",
                       (row["sid"], revision, intent, relation, json_bytes(public).decode(), json_bytes(receipt).decode()))
        return receipt

    def snapshot(self) -> dict:
        with self._transaction() as db:
            return {
                table: [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in ("accounts", "sessions", "bulletins", "admissions")
            }

    def account(self, account: str) -> dict:
        with self._transaction() as db:
            row = db.execute("SELECT * FROM accounts WHERE account=?", (account,)).fetchone()
            if row is None:
                raise ValueError("Unknown fleet account")
            return dict(row)
