#!/usr/bin/env python3
"""Rebuild the published Rome cell distance matrix from the pinned OSM extract."""

import argparse
import json
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import dijkstra

from compile_circuits import sha256
from rome_preprocess import CELL, CITY, LATITUDE, LONGITUDE, RADIUS


def build(pbf: Path) -> tuple[np.ndarray, dict]:
    from pyrosm import OSM

    nodes, edges = OSM(str(pbf)).get_network(network_type="driving", nodes=True)
    x = np.radians(nodes["lon"].to_numpy() - LONGITUDE) * RADIUS * np.cos(np.radians(LATITUDE)) + CITY/2
    y = np.radians(nodes["lat"].to_numpy() - LATITUDE) * RADIUS + CITY/2
    grid = CITY//CELL
    tiles = np.clip((y//CELL).astype(int),0,grid-1)*grid + np.clip((x//CELL).astype(int),0,grid-1)
    mapped = dict(zip(nodes["id"].to_numpy(), tiles, strict=True))
    links = {}
    for u,v,length in zip(edges["u"], edges["v"], edges["length"], strict=True):
        a,b = mapped[u], mapped[v]
        if a != b:
            links[a,b] = min(float(length), links.get((a,b), float("inf")))
    left,right = zip(*links)
    graph = csr_matrix((list(links.values()),(left,right)),shape=(grid**2,grid**2))
    matrix = dijkstra(graph,directed=True)
    return matrix, {"nodes":len(nodes),"directed_road_edges":len(edges),"folded_edges":len(links)}


def main():
    root = Path(__file__).resolve().parents[1] / "datasets/rome"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pbf", type=Path, default=root/"rome_10km.osm.pbf")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    pinned = json.loads((root/"source_pins.json").read_text())
    if sha256(args.pbf) != pinned["road_osm_pbf_sha256"]:
        raise SystemExit("Wrong source OSM extract")
    graph, report = build(args.pbf)
    with args.out.open("xb") as stream:
        np.save(stream,graph)
    digest = sha256(args.out)
    if digest != pinned["road_matrix_sha256"]:
        raise SystemExit("Rebuilt road matrix differs from the release")
    print(json.dumps(report | {"sha256":digest}, sort_keys=True))


if __name__ == "__main__":
    main()
