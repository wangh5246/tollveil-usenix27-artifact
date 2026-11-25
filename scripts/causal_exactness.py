"""Verify 200 synthetic cases and every held-out Rome prefix."""

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
from random import Random
import subprocess
from time import perf_counter

from causal_profile import LONG, PUBLIC, WORK, build
from causal_witness import Certifier, Facts, Scenario, State, salt
from circom_crypto import FIELD_P, OBUKeyPair
from phase2_compare import rome_records
from potential_certificate import field_input


class Calculator:
    def __init__(self, role: str, native: bool = False) -> None:
        base = WORK / f"circuits/causal/build_{role}-r3"
        stem = f"causal_{role}"
        sym = base / f"{stem}.sym"
        reads = (*PUBLIC, "upper" if role == "update" else "charge")
        requested = {f"main.{name}" for name in reads}
        wires = {}
        with sym.open() as symbols:
            for line in symbols:
                _, index, _, name = line.strip().split(",", 3)
                if name in requested:
                    wires[name] = int(index)
                    if len(wires) == len(requested):
                        break
        self.labels = (*PUBLIC, "upper")
        selected = [wires[f"main.{name}"] for name in reads]
        if any(index < 0 for index in selected) or selected[:len(PUBLIC)] != list(range(1,len(PUBLIC)+1)):
            raise ValueError("compiled public and upper wires do not match")
        js = base / f"{stem}_js"
        if native:
            binary = WORK / "circuits/causal/native_update/causal_update_cpp"
            cmd = [binary/"causal_native_wire_server", binary/f"{stem}.dat"]
        else:
            cmd = ["/opt/homebrew/bin/node", WORK/"scripts/causal_check.cjs",
                   js/"witness_calculator.js", js/f"{stem}.wasm"]
        self.p = subprocess.Popen(
            [*cmd, *map(str, selected)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )

    def check(self, data: dict, valid: bool = True) -> None:
        assert self.p.stdin is not None and self.p.stdout is not None
        self.p.stdin.write(json.dumps(field_input(data), separators=(",",":")) + "\n")
        self.p.stdin.flush()
        result = json.loads(self.p.stdout.readline())
        ok = result.get("wires") == [str(data[name]) for name in self.labels] if valid else result.get("rejected") is True
        if not ok:
            raise ValueError("unexpected causal wire verification result")

    def close(self) -> None:
        self.p.stdin.close()
        if self.p.wait(timeout=10) != 0:
            raise ValueError("calculator failed")


def genesis(scenario: Scenario, certifier: Certifier) -> State:
    n = len(scenario.p.hi)
    upper = certifier.forward(scenario.entry, (1,)*n, (LONG,)*n, {}, 0)
    return State(0, 0, upper, 0, salt())


def verify_trace(scenario: Scenario, cert: Certifier, calculator: Calculator,
                 counts: Counter) -> None:
    prev = genesis(scenario, cert)
    deposit = prev.upper
    for count in range(9):
        # One-slot opening lag exercises authenticated unopened distance
        # bands as well as the unknown-future band in the same trace.
        mask = (1 << max(0,count-1)) - 1
        info = Facts(count, mask, 0, 0)
        data, successor = scenario.fill(info, prev, count, deposit, 1, cert)
        edges = {i:(scenario.path[i],scenario.path[i+1],scenario.distances[i])
                 for i in range(8) if (mask >> i) & 1}
        expected = cert.forward(scenario.entry, tuple(data["isLongGap"]),
                                tuple(data["cap"]), edges, 0)
        if expected != data["upper"]:
            raise ValueError("independent causal path maximum differs")
        if count==0:
            if expected != deposit or data["refundDelta"] != 0:
                raise ValueError("registered deposit differs from causal maximum")
            counts["genesis_exact"] += 1
        calculator.check(data)
        counts["equal"] += 1
        counts["compiled_witness_wire_checks"] += 1
        counts["authenticated_unopened_short"] += sum(
            int(past and not opened and not long)
            for past, opened, long in zip(data["past"], data["opened"], data["isLongGap"], strict=True)
        )
        counts["authenticated_unopened_long"] += sum(
            int(past and not opened and long)
            for past, opened, long in zip(data["past"], data["opened"], data["isLongGap"], strict=True)
        )
        prev = successor
    counts["traces"] += 1


def negatives(profile, key, cert) -> dict:
    source = next(i for i,sink in enumerate(profile.sink) if not sink)
    route = (source,)*9
    s = Scenario(profile, key, 900_001, route, (7,)*8)
    g = genesis(s, cert)
    c = Calculator("update")
    close = Calculator("close")
    try:
        base, next_state = s.fill(Facts(1,0,0,0), g, 0, g.upper, 1, cert)
        c.check(base)
        bad = {}
        def changes(name, **fields):
            bad[name] = base | fields

        lower = base["upper"]-1
        delta = base["refundDelta"]+1
        forged = State(0,1,lower,delta,base["newSalt"])
        changes("upper_minus_one", upper=lower, refundDelta=delta,
                nextState=forged.commit(s.identity,1))
        path = base["maximum"].copy()
        entry = base["entry"]
        path[1] = next(v for v in profile.long[entry] if v not in profile.short[entry])
        changes("illegal_short_path", maximum=path)
        hubs = deepcopy(base["rowHub"])
        hubs[0][0] = FIELD_P-1
        changes("negative_field_slack", rowHub=hubs)
        changes("cross_session_checkpoint", sid=s.sid+1)
        changes("wrong_predecessor", prevState=base["prevState"]+1)
        caps = base["cap"].copy()
        caps[0]+=1
        changes("signed_cap_alteration", cap=caps)
        past = base["past"].copy()
        past[2] = 1
        changes("signed_future_activation", past=past)
        faults = base["fault"].copy()
        faults[0] = 1
        changes("fake_obu_fault", fault=faults)
        for variant in bad.values():
            c.check(variant, valid=False)
        t = Scenario(profile,key,900_002,route,(7,)*8)
        valid_fault, _ = t.fill(Facts(8,0b1101,0b0010,0b0010),genesis(t,cert),0,g.upper,2,cert)
        close.check(valid_fault)
        close.check(valid_fault | {"infraredMask":0}, valid=False)
        return {"update": list(bad), "close": ["removed_infra_corroboration"],
                "all_rejected": True, "bonafide_nonempty_waiver_witness": True}
    finally:
        c.close()
        close.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("rome","synthetic","negative"))
    ap.add_argument("out",type=Path)
    ap.add_argument("--limit",type=int)
    ap.add_argument("--native",action="store_true")
    ap.add_argument("--worker",type=int,default=0)
    ap.add_argument("--workers",type=int,default=1)
    args=ap.parse_args()

    profile=build()
    key=OBUKeyPair(__import__("secrets").token_bytes(32))
    cert=Certifier(profile)
    timer=perf_counter()
    if args.mode=="negative":
        result=negatives(profile,key,cert)
    else:
        counts=Counter()
        calc=Calculator("update",native=args.native)
        try:
            if args.mode=="rome":
                _, test, split=rome_records()
                indexes={v:i for i,v in enumerate(profile.cells)}
                for j,(raw,dist,_) in enumerate(test):
                    if args.limit is not None and j>=args.limit:
                        break
                    if j%args.workers!=args.worker:
                        continue
                    route=tuple(indexes[v] for v in raw)
                    s=Scenario(profile,key,1_000_000+j,route,tuple(dist))
                    for i in range(len(dist)):
                        s.slot_ticket(i)
                        counts["included_real_edges"]+=1
                    verify_trace(s,cert,calc,counts)
                result=split | dict(counts)
            else:
                rng=Random(20261124)
                number=200 if args.limit is None else args.limit
                for j in range(number):
                    route=[rng.randrange(len(profile.cells))]
                    ds=[]
                    for i in range(8):
                        pairs=profile.short if rng.random()<0.85 else profile.long
                        a=route[-1]
                        b=rng.choice(pairs[a])
                        route.append(b)
                        ds.append(rng.randint(0,128 if b in profile.short[a] else LONG))
                    if j%args.workers==args.worker:
                        verify_trace(Scenario(profile,key,2_000_000+j,tuple(route),tuple(ds)),cert,calc,counts)
                result=dict(counts)
        finally:
            calc.close()
    result["compiled_calculator"] = "Circom C++" if args.native else "Circom WASM"
    result["elapsed_seconds"]=round(perf_counter()-timer,4)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
