"""Pinned public graph and tariff, with exact 2-D decomposition checks."""

from dataclasses import dataclass
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
import json

from phase2_profiles import rome_long
from potential_certificate import FIELD_P

WORK = Path(__file__).resolve().parents[1]
SHORT = 128
LONG = 400
PUBLIC = (
    "relTag", "sid", "revision", "profile", "entry", "pkCommit", "deposit",
    "infraredMask", "prevState", "nextState", "refundDelta", "charge",
)


@dataclass(frozen=True)
class CausalProfile:
    cells: tuple
    sink: tuple
    rates: tuple
    hi: tuple
    rows: tuple
    cols: tuple
    cover: tuple
    short: tuple
    long: tuple
    widths: tuple
    tag: int


def build() -> CausalProfile:
    static, cells = rome_long()
    pos = {c: i for i, c in enumerate(cells)}
    n = len(cells)
    sinks = tuple(int(row == (u,)) for u, row in enumerate(static.rows))
    if sum(sinks) != 2 or any(row != tuple(range(n)) for u, row in enumerate(static.rows) if not sinks[u]):
        raise ValueError("unexpected long-band structure")
    rows = []
    for c in range(400):
        y, x = divmod(c, 20)
        rows.append(tuple(pos[y*20 + xx] for xx in (x-1, x, x+1)
                          if 0 <= xx < 20 and y*20 + xx in pos))
    cols = []
    short = []
    for u, c in enumerate(cells):
        y, x = divmod(c, 20)
        centers = tuple(yy*20+x for yy in (y-1, y, y+1)
                        if 0 <= yy < 20 and rows[yy*20+x])
        cols.append(centers if not sinks[u] else ())
        short.append(tuple(v for v in static.rows[u]
                           if max(abs(cells[v]//20-y), abs(cells[v]%20-x)) <= 1))
        if not sinks[u] and set(short[-1]) != {v for h in centers for v in rows[h]}:
            raise ValueError("separable relation differs from direct geometry")
    # Cover all destinations by a small grid of existing nonsink box hubs.
    # Replace an absent center by as many neighbors as the cover requires.
    cover = []
    uncovered = set(range(n))
    for y in (1, 4, 7, 10, 13, 16, 19):
        for x in (1, 4, 7, 10, 13, 16, 19):
            u = pos.get(y*20+x)
            if u is not None and not sinks[u]:
                cover.append(u)
                uncovered.difference_update(short[u])
    while uncovered:
        u = max((u for u in range(n) if not sinks[u]),
                key=lambda u: len(uncovered.intersection(short[u])))
        reached = uncovered.intersection(short[u])
        if not reached:
            raise ValueError("box cover misses a destination")
        uncovered.difference_update(reached)
        cover.append(u)
    rates = tuple(t.exact_rate for t in static.tariff)
    hi = tuple(t.high_rate for t in static.tariff)
    # Potential values in each suffix are all in [0, suffix fee cap].
    maximum = [LONG*max(r) for r in hi]
    widths = tuple(sum(maximum[i+1:]).bit_length() for i in range(len(hi)-1))
    global_cap = sum(maximum)
    if global_cap >= 1 << 18 or 3*len(hi)*(1<<18)+global_cap >= FIELD_P:
        raise ValueError("arithmetic widths unsafe")
    tag = int.from_bytes(sha256(b"tollveil-v15-causal-v1\\0"+json.dumps(
        (cells, static.rows, short, rates, hi, SHORT, LONG), separators=(",",":"),
    ).encode()).digest(), "big") % FIELD_P
    return CausalProfile(cells, sinks, rates, hi, tuple(rows), tuple(cols),
                         tuple(cover), tuple(short), static.rows, widths, tag)


def packed_rows(groups: tuple) -> tuple[list, list]:
    edges = [[0, 0]]
    offsets = [1]
    for u, group in enumerate(groups):
        edges.extend([u, v] for v in group)
        offsets.append(len(edges))
    edges[0][0] = len(edges)-1
    return edges, offsets


if __name__ == "__main__":
    p = build()
    row_edges, row_offsets = packed_rows(p.rows)
    col_edges, col_offsets = packed_rows(p.cols)
    print(f"short edges {sum(map(len, p.short))}, X links {row_edges[0][0]}, "
          f"Y links {col_edges[0][0]}, clique links {len(p.cover)}, widths {p.widths}")
    args = (len(p.cells), len(p.hi), [c % 20 for c in p.cells], [c//20 for c in p.cells],
            p.sink, row_edges, row_offsets, col_edges, col_offsets, [len(p.cover), *p.cover],
            p.rates, p.hi, SHORT, LONG, p.widths, p.tag)
    for tag, role in enumerate(("update","close"), 1):
        path = WORK / "circuits/causal" / f"causal_{role}.circom"
        path.write_text('pragma circom 2.1.9;\ninclude "causal_upper.circom";\n\n'
                        + f'component main {{public [{", ".join(PUBLIC)}]}} = CausalUpper(\n'
                        + ",\n".join("    " + json.dumps(x,separators=(",",":")) for x in (*args, tag))
                        + "\n);\n")
