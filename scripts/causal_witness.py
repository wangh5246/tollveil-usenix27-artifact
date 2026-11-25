"""Construct causal checkpoints and maximum-path certificates."""

from dataclasses import dataclass
import secrets

import numpy as np

from causal_profile import CausalProfile, SHORT, LONG
from circom_crypto import FIELD_P, OBUKeyPair, poseidon


def salt() -> int:
    return secrets.randbelow(FIELD_P)


@dataclass(frozen=True)
class Facts:
    passed: int
    mask: int
    infra: int
    fault: int


@dataclass(frozen=True)
class State:
    opened: int
    passed: int
    upper: int
    returned: int
    blinding: int

    def commit(self, identity: int, revision: int) -> int:
        return poseidon([205002, identity, revision, self.opened, self.passed,
                         self.upper, self.returned, self.blinding])


class Scenario:
    """Test OBU exposing only checkpoint facts that have arrived at this revision."""

    def __init__(self, profile: CausalProfile, key: OBUKeyPair, sid: int,
                 path: tuple[int, ...], distances: tuple[int, ...]) -> None:
        self.p = profile
        self.key = key
        self.sid = sid
        self.path = path
        self.distances = distances
        self.entry = path[0]
        self.key_salt = salt()
        self.pk_commit = key.pk_commit(self.key_salt)
        self.identity = poseidon([205001, sid, profile.tag, self.entry, self.pk_commit])
        self.leaf_salts = [salt() for _ in profile.hi]
        self._checkpoints = {}
        self._tickets = {}
        # The secret measurement commitments are sealed solely by the
        # simulated OBU. The checkpoint drops every future ticket.
        self._checkpoint_start = poseidon([205003, self.identity, len(profile.hi)])

    def slot_ticket(self, i: int) -> tuple[int, int, int]:
        if i not in self._tickets:
            u, v = self.path[i:i+2]
            d = self.distances[i]
            if v not in self.p.long[u] or not 0 <= d <= LONG:
                raise ValueError("measurement outside registered support")
            wide = int(v not in self.p.short[u])
            ceiling = LONG if wide else SHORT
            if d > ceiling:
                raise ValueError("short distance exceeds calibrated cap")
            self._tickets[i] = (wide, ceiling,
                poseidon([205010+i, self.identity, u, v, d, self.leaf_salts[i]]))
        return self._tickets[i]

    def checkpoint(self, count: int, fault: int) -> tuple[tuple, object]:
        cache = count, fault
        if cache not in self._checkpoints:
            digest = self._checkpoint_start
            records = []
            if fault >> count:
                raise ValueError("future fault")
            for i in range(len(self.p.hi)):
                past = int(i < count)
                failed = (fault >> i) & 1
                wide, upper, leaf = self.slot_ticket(i) if past and not failed else (1, LONG, 0)
                record = past, failed, wide, upper, leaf
                digest = poseidon([digest, *record])
                records.append(record)
            self._checkpoints[cache] = (tuple(zip(*records)), self.key.sign_field(digest))
        return self._checkpoints[cache]

    def fill(self, facts: Facts, previous: State, revision: int, deposit: int,
             rel: int, certificate: "Certifier") -> tuple[dict, State]:
        (past, fault, tiers, caps, committed), sig = self.checkpoint(facts.passed, facts.fault)
        opened = [(facts.mask >> i) & 1 for i in range(len(past))]
        pins = {i: (self.path[i], self.path[i+1], self.distances[i]) for i, flagged in enumerate(opened) if flagged}
        computed = certificate.witness(self.entry, tiers, caps, pins, facts.fault & facts.infra)
        upper = computed.pop("upper")
        delta = deposit - upper - previous.returned
        successor = State(facts.mask, facts.passed, upper, previous.returned + delta, salt())
        data = {
            "relTag": rel, "sid": self.sid, "revision": revision, "profile": self.p.tag,
            "entry": self.entry, "pkCommit": self.pk_commit, "deposit": deposit,
            "infraredMask": facts.infra, "prevState": previous.commit(self.identity, revision),
            "nextState": successor.commit(self.identity, revision+1) if rel == 1 else 0,
            "refundDelta": delta, "charge": upper if rel == 2 else 0,
            "Ax": self.key.Ax, "Ay": self.key.Ay, "keySalt": self.key_salt,
            "R8x": sig.R8x, "R8y": sig.R8y, "S": sig.S, "oldMask": previous.opened,
            "oldCount": previous.passed, "oldUpper": previous.upper,
            "oldRefund": previous.returned, "oldSalt": previous.blinding, "newSalt": successor.blinding,
            "past": list(past), "fault": list(fault), "isLongGap": list(tiers),
            "cap": list(caps), "sealed": list(committed), "opened": opened,
            "measured": [d if opened[i] else 0 for i,d in enumerate(self.distances)],
            "leafSalt": [leaf if opened[i] else 0 for i,leaf in enumerate(self.leaf_salts)],
            "upper": upper, **computed,
        }
        return data, successor


def pad(groups: tuple) -> np.ndarray:
    return np.array([list(group) + [-1]*(3-len(group)) for group in groups])


class Certifier:
    def __init__(self, profile: CausalProfile) -> None:
        self.p = profile
        self.row = pad(profile.rows)
        self.col = pad(profile.cols)
        self.sources = np.arange(len(profile.cells))
        self.sinks = np.flatnonzero(profile.sink)
        self.short_pairs = tuple(
            np.array([value for u, row in enumerate(profile.short) for v in row for value in ((u,v),)]).T
        )
        self.long_pairs = tuple(
            np.array([(u,v) for u, row in enumerate(profile.long) for v in row]).T
        )
        self.high = np.array(profile.hi)

    def witness(self, entry: int, tiers: tuple, caps: tuple, pins: dict, excused: int) -> dict:
        steps = len(tiers)
        n = len(self.p.cells)
        phi = np.zeros((steps+1, n), dtype=np.int64)
        live = np.zeros((steps+1, n), dtype=np.int64)
        live[-1] = 1
        row = np.zeros((steps-1, 400), dtype=np.int64)
        row_live = np.zeros_like(row)
        box = np.zeros((steps-1, n), dtype=np.int64)
        clique = np.zeros(steps-1, dtype=np.int64)
        choice = np.full((steps, n), -1, dtype=np.int64)
        for i in reversed(range(steps)):
            suffix = np.where(live[i+1], phi[i+1], -1)
            if i < steps-1:
                horizontal = np.append(suffix, -1)[self.row]
                x_winners = horizontal.argmax(1)
                x_idx = self.row[np.arange(400), x_winners]
                h_max = horizontal.max(1)
                row[i] = np.maximum(h_max, 0)
                row_live[i] = h_max >= 0
                vertical = np.append(h_max, -1)[self.col]
                y_winners = self.col[self.sources, vertical.argmax(1)]
                v_max = vertical.max(1)
                box[i] = np.maximum(v_max, 0)
                clique[i] = max(0, suffix.max())
            if i in pins:
                a, b, d = pins[i]
                if suffix[b] < 0:
                    continue
                live[i,a] = 1
                phi[i,a] = suffix[b] + d*self.p.rates[i][a]
                choice[i,a] = b
            else:
                if tiers[i]:
                    chosen = np.full(n, suffix.argmax())
                elif i == steps-1:
                    chosen = self.sources.copy()
                else:
                    chosen = x_idx[y_winners].copy()
                chosen[self.sinks] = self.sinks
                possible = (chosen >= 0) & (suffix[chosen] >= 0)
                paid_cap = 0 if (excused >> i) & 1 else caps[i]
                live[i] = possible
                phi[i, possible] = suffix[chosen[possible]] + paid_cap*self.high[i, possible]
                choice[i, possible] = chosen[possible]
        path = [entry]
        for i in range(steps):
            next_cell = int(choice[i,path[-1]])
            if next_cell < 0:
                raise ValueError("no path through the causal observations")
            path.append(next_cell)
        return {"maximum": path, "phi": phi.tolist(), "live": live.tolist(),
                "rowHub": row.tolist(), "rowLive": row_live.tolist(),
                "boxHub": box.tolist(), "cliqueHub": clique.tolist(), "upper": int(phi[0,entry])}

    def forward(self, entry: int, tiers: tuple, caps: tuple, pins: dict, excused: int) -> int:
        """Independent edge-list forward DP. No use of hubs or suffix states."""
        unreachable = -1_000_000_000
        current = np.full(len(self.sources), unreachable, dtype=np.int64)
        current[entry] = 0
        for i, (tier, cap) in enumerate(zip(tiers, caps, strict=True)):
            following = np.full_like(current, unreachable)
            if i in pins:
                a,b,d = pins[i]
                pairs = self.p.long if tier else self.p.short
                if b in pairs[a] and current[a] >= 0:
                    following[b] = current[a] + d*self.p.rates[i][a]
            else:
                a,b = self.long_pairs if tier else self.short_pairs
                keep = current[a] >= 0
                ca,cb = a[keep], b[keep]
                fee = 0 if (excused >> i) & 1 else cap*self.high[i,ca]
                np.maximum.at(following, cb, current[ca]+fee)
            current = following
        answer = int(current.max())
        if answer < 0:
            raise ValueError("no path in independent reference")
        return answer
