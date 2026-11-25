"""Four-slot segments with registered waypoint anchors and edge-dependent tariffs."""

from functools import lru_cache
from random import Random
from typing import Iterable

import numpy as np

GAP = 4
VERTICES = 24
MAX_FEE = 63


@lru_cache(maxsize=GAP)
def fees(slot: int) -> np.ndarray:
    a, b = np.indices((VERTICES, VERTICES))
    table = 1 + (13*a + 9*b + 7*slot + 3*a*b) % MAX_FEE
    return table


def fixture(n: int) -> tuple[tuple[int, ...], ...]:
    if n <= 0 or n % GAP:
        raise ValueError("fixture requires full gaps")
    rng = Random(20261124 + n)
    return tuple(
        (0, *(rng.randrange(VERTICES) for _ in range(GAP-1)), 0)
        for _ in range(n//GAP)
    )


def pins(path: tuple[int, ...], mask: int) -> tuple[tuple[int, int], ...]:
    return tuple((path[i], path[i+1]) if (mask>>i)&1 else (0,0) for i in range(GAP))


def endpoints(path: tuple[int, ...], mask: int, maximize: bool,
              waived: int = 0) -> int:
    if mask & waived or not 0 <= (mask | waived) < (1<<GAP):
        raise ValueError("incompatible fault and opening masks")
    sentinel = -10**6 if maximize else 10**6
    current = np.full(VERTICES, sentinel, dtype=np.int64)
    current[0] = 0
    extremum = np.max if maximize else np.min
    for i in range(GAP):
        cost = fees(i) if not ((waived>>i)&1) else np.zeros_like(fees(i))
        if (mask>>i)&1:
            a, b = path[i:i+2]
            nxt = np.full(VERTICES, sentinel, dtype=np.int64)
            if current[a] != sentinel:
                nxt[b] = current[a] + cost[a,b]
        else:
            nxt = extremum(
                np.where(current[:,None] != sentinel, current[:,None] + cost, sentinel),
                axis=0,
            )
        current = nxt
    if current[0] == sentinel:
        raise ValueError("no route respecting waypoints")
    return int(current[0])


def whole_bounds(routes: tuple, mask: int) -> tuple[int,int]:
    if not 0 <= mask < (1<<(GAP*len(routes))):
        raise ValueError("invalid opening mask")
    lower = upper = 0
    for k, path in enumerate(routes):
        subset = (mask>>(GAP*k)) & ((1<<GAP)-1)
        lower += endpoints(path, subset, maximize=False)
        upper += endpoints(path, subset, maximize=True)
    return lower, upper


def prepared_bounds(routes: tuple) -> Iterable[tuple[int,int,int]]:
    """Compute all subsets using exact independently anchored gap sums."""
    small = [tuple(whole_bounds((path,), mask) for mask in range(1<<GAP)) for path in routes]
    for mask in range(1<<(GAP*len(routes))):
        lo = hi = 0
        for k, table in enumerate(small):
            l,u = table[(mask>>(GAP*k)) & ((1<<GAP)-1)]
            lo += l
            hi += u
        yield mask,lo,hi
