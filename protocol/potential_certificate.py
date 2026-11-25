"""Build and check finite layered-graph Bellman certificates for Circom."""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import secrets

from circom_crypto import FIELD_P, poseidon


PUBLIC = ("session", "profile", "entry", "evidence", "summary")


@dataclass(frozen=True)
class Tariff:
    low_distance: int
    high_distance: int
    low_rate: tuple[int, ...]
    high_rate: tuple[int, ...]
    exact_rate: tuple[int, ...]


@dataclass(frozen=True)
class Profile:
    rows: tuple[tuple[int, ...], ...]
    tariff: tuple[Tariff, ...]
    exits: tuple[int, ...]

    @property
    def n(self) -> int:
        return len(self.rows)

    @property
    def slots(self) -> int:
        return len(self.tariff)

    @property
    def max_total(self) -> int:
        return sum(t.high_distance * max(t.high_rate) for t in self.tariff)

    @property
    def slack_bits(self) -> int:
        # Feasible suffixes cost in [0,M]. The unreachable fillers begin at
        # ±(M+1), and can pick up at most M along a suffix.
        return (2 * self.max_total + 1).bit_length()

    def validate(self) -> None:
        if self.n < 2 or not self.tariff or not self.exits:
            raise ValueError("need at least two vertices, one slot, and one exit")
        for row in (*self.rows, self.exits):
            if row != tuple(sorted(set(row))) or any(not 0 <= v < self.n for v in row):
                raise ValueError("vertices must be sorted, unique and in range")
        for t in self.tariff:
            if not (0 <= t.low_distance <= t.high_distance < (1 << 32)):
                raise ValueError("invalid distance cap")
            if any(len(rate) != self.n for rate in (t.low_rate, t.high_rate, t.exact_rate)):
                raise ValueError("one rate per vertex is required")
            if any(not 0 <= lo <= rate <= hi for lo, rate, hi in zip(
                t.low_rate, t.exact_rate, t.high_rate, strict=True
            )):
                raise ValueError("invalid rate band")
        if self.max_total >= (1 << 32):
            raise ValueError("amount exceeds settlement width")
        # Bounds used in the modular-to-integer lifting argument. Each edge
        # contributes at most one range-checked slack, even inside a block.
        if self.max_total + self.slots * ((1 << self.slack_bits) - 1) >= FIELD_P:
            raise ValueError("potential path sum may wrap in the field")

    @property
    def tag(self) -> int:
        encoded = json.dumps({
            "rows": self.rows,
            "tariff": [vars(t) for t in self.tariff],
            "exits": self.exits,
        }, sort_keys=True, separators=(",", ":")).encode()
        return int.from_bytes(sha256(b"TollVeil/v15/envelope-profile/v1\0" + encoded).digest(), "big") % FIELD_P

    def groups(self) -> tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]:
        blocks = tuple(dict.fromkeys(self.rows))
        indices = {row: i for i, row in enumerate(blocks)}
        return tuple(indices[row] for row in self.rows), blocks

    def write_wrapper(self, path: Path) -> None:
        self.validate()
        groups, blocks = self.groups()
        targets: list[int] = []
        offsets = [0]
        for row in blocks:
            targets.extend(row)
            offsets.append(len(targets))
        params = (
            self.n, self.slots, (self.n - 1).bit_length(),
            len(blocks), len(targets), groups, targets, offsets,
            [t.low_rate for t in self.tariff], [t.high_rate for t in self.tariff],
            [t.exact_rate for t in self.tariff],
            [t.low_distance for t in self.tariff], [t.high_distance for t in self.tariff],
            [int(v in self.exits) for v in range(self.n)],
            max(1, max(t.high_distance for t in self.tariff).bit_length()),
            self.slack_bits, max(1, self.max_total.bit_length()), self.tag,
        )
        path.write_text(
            'pragma circom 2.1.9;\ninclude "potential.circom";\n\n'
            + f'component main {{public [{", ".join(PUBLIC)}]}} = Envelope(\n'
            + ',\n'.join('    ' + json.dumps(p, separators=(',', ':')) for p in params)
            + '\n);\n',
            encoding="utf-8",
        )


def backward(profile: Profile, entry: int, opened: dict[int, tuple[int, int, int]],
             maximize: bool) -> tuple[int, list[int], list[list[int]], list[list[int]]]:
    """Solve suffix DP and complete the potential at dead-end vertices."""
    if not 0 <= entry < profile.n or any(not 0 <= i < profile.slots for i in opened):
        raise ValueError("entry or slot index out of range")
    extremum = max if maximize else min
    filler = (-1 if maximize else 1) * (profile.max_total + 1)
    groups, blocks = profile.groups()
    potentials = [[0] * profile.n for _ in range(profile.slots + 1)]
    step_hubs = [[0] * len(blocks) for _ in range(profile.slots)]
    choices = [[-1] * profile.n for _ in range(profile.slots)]
    potentials[-1] = [0 if v in profile.exits else filler for v in range(profile.n)]
    for i in reversed(range(profile.slots)):
        t = profile.tariff[i]
        suffix = potentials[i + 1]
        if i in opened:
            a, b, d = opened[i]
            if (not 0 <= a < profile.n or b not in profile.rows[a]
                    or not t.low_distance <= d <= t.high_distance):
                raise ValueError("illegal opened edge or distance")
            potentials[i] = [filler] * profile.n
            potentials[i][a] = suffix[b] + d * t.exact_rate[a]
            choices[i][a] = b
            continue
        best = [
            extremum(targets, key=suffix.__getitem__) if targets else -1
            for targets in blocks
        ]
        step_hubs[i] = [suffix[b] if b >= 0 else filler for b in best]
        rate = t.high_rate if maximize else t.low_rate
        distance = t.high_distance if maximize else t.low_distance
        for a, group in enumerate(groups):
            choices[i][a] = best[group]
            potentials[i][a] = step_hubs[i][group] + distance * rate[a]

    a = entry
    path = [a]
    for chosen in choices:
        a = chosen[a]
        if a < 0:
            raise ValueError("no route through opened edges")
        path.append(a)
    if a not in profile.exits:
        raise ValueError("no route reaches an allowed exit")
    return potentials[0][entry], path, potentials, step_hubs


def witness(profile: Profile, session: int, entry: int,
            opened: dict[int, tuple[int, int, int]]) -> dict:
    lower, p_min, pot_min, hub_min = backward(profile, entry, opened, False)
    upper, p_max, pot_max, hub_max = backward(profile, entry, opened, True)
    salt_e = secrets.randbelow(FIELD_P)
    salt_s = secrets.randbelow(FIELD_P)
    scope = poseidon([204201, session, profile.tag, entry])
    evidence = poseidon([204202, scope, salt_e])
    flags = [int(i in opened) for i in range(profile.slots)]
    anchors = [opened.get(i, (0, 0, 0)) for i in range(profile.slots)]
    for flag, edge in zip(flags, anchors, strict=True):
        evidence = poseidon([evidence, flag, *edge])
    summary = poseidon([204203, scope, evidence, lower, upper, salt_s])
    return {
        "session": session, "profile": profile.tag, "entry": entry,
        "evidence": evidence, "summary": summary, "open": flags,
        "source": [a for a, _, _ in anchors], "destination": [b for _, b, _ in anchors],
        "measured": [d for _, _, d in anchors], "evidenceSalt": salt_e,
        "maximum": p_max, "minimum": p_min, "lowerPotential": pot_min,
        "upperPotential": pot_max, "lowerHub": hub_min, "upperHub": hub_max,
        "lower": lower, "upper": upper, "summarySalt": salt_s,
    }


def field_input(value: int | list | dict) -> str | list | dict:
    """Encode signed potential representatives canonically for the WASM input."""
    if isinstance(value, dict):
        return {key: field_input(item) for key, item in value.items()}
    if isinstance(value, list):
        return [field_input(item) for item in value]
    return str(value % FIELD_P)
