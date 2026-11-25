"""Frozen full-domain diagnostic profile and deterministic synthetic generator."""

from math import hypot
import os
from pathlib import Path
from random import Random

import numpy as np

from potential_certificate import Profile, Tariff

ARTIFACT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("TOLLVEIL_PRIVATE_INPUT_ROOT", ARTIFACT))
ROAD = Path(os.environ.get("TOLLVEIL_ROME_ROAD_MATRIX",
                           ARTIFACT / "datasets/rome/cell_dist.npy"))


def rome_rate(cell: int, period: int) -> tuple[int, int, int]:
    cx, cy = cell % 20, cell // 20
    dx, dy = abs(cx - 9.5), abs(cy - 9.5)
    radius = hypot(dx, dy)
    if period == 0:
        if dx <= 1.6 and dy <= 1.6:
            return 34, 48, 42
        if radius <= 3.5:
            return 18, 30, 24
        if radius <= 5.5:
            return 6, 14, 10
        return 1, 5, 3
    if dx <= 1.6 and dy <= 1.6:
        return 30, 44, 38
    if any(abs(c - line) <= 1 for c in (cx, cy) for line in (5, 14)):
        return 24, 38, 32
    if radius <= 4:
        return 12, 22, 16
    return 2, 7, 4


def rome_long() -> tuple[Profile, tuple[int, ...]]:
    road = np.load(ROAD)
    finite = np.isfinite(road)
    cells = tuple(map(int, np.flatnonzero((finite.sum(0) > 1) | (finite.sum(1) > 1))))
    if len(cells) != 396:
        raise ValueError("unexpected Rome model domain")
    reachable = finite[np.ix_(cells, cells)]
    rows = tuple(tuple(map(int, np.flatnonzero(row))) for row in reachable)
    # A pre-trip long-band diagnostic only. This does not replace the legacy
    # per-slot geometric cutoff of the main G2 evaluation.
    tariffs = tuple(
        Tariff(0, 1500, *map(tuple, zip(*(rome_rate(c, i % 2) for c in cells))))
        for i in range(8)
    )
    return Profile(rows, tariffs, tuple(range(len(cells)))), cells



def rome_minimum_activation() -> Profile:
    """Smallest R8 distance band: nominal d=1, exact interval [0,2]."""
    profile, cells = rome_long()
    rows = []
    for a, allowed in enumerate(profile.rows):
        ua, va = divmod(cells[a], 20)
        # The minimum cutoff is 120 m. The next nonzero gap is 500 m.
        rows.append(tuple(b for b in allowed
                          if abs(ua - cells[b] // 20) <= 1
                          and abs(va - cells[b] % 20) <= 1))
    tariff = tuple(Tariff(0, 2, t.low_rate, t.high_rate, t.exact_rate)
                   for t in profile.tariff)
    return Profile(tuple(rows), tariff, profile.exits)

def synthetic_profile() -> Profile:
    rows = ((0, 1, 2), (0, 1, 2), (1, 2, 3), (2, 3), (), (5,))
    t = Tariff(1, 7, (2, 3, 2, 5, 1, 1), (6, 7, 5, 8, 3, 2), (3, 4, 3, 7, 2, 1))
    s = Tariff(2, 8, (3, 2, 6, 2, 2, 1), (5, 4, 8, 9, 4, 2), (4, 3, 7, 4, 3, 1))
    return Profile(rows, (t, s, t, s), (1, 3, 5))


def synthetic_openings(profile: Profile, count: int = 200):
    rng = Random(20261124)
    for _ in range(count):
        while True:
            entry = rng.choice((0, 1, 2, 3, 5))
            path = [entry]
            for _ in profile.tariff:
                path.append(rng.choice(profile.rows[path[-1]]))
            if path[-1] in profile.exits:
                break
        edges = [
            (a, b, rng.randint(t.low_distance, t.high_distance))
            for a, b, t in zip(path[:-1], path[1:], profile.tariff, strict=True)
        ]
        order = rng.sample(range(profile.slots), profile.slots)
        yield entry, edges, order


if __name__ == "__main__":
    circuits = Path(__file__).resolve().parents[1] / "circuits/phase2"
    profile, _ = rome_long()
    profile.write_wrapper(circuits / "rome396_long.circom")
    synthetic_profile().write_wrapper(circuits / "synthetic.circom")
    rome_minimum_activation().write_wrapper(circuits / "rome396_min_activation.circom")
