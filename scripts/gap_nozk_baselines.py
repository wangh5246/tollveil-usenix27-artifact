"""Executable online source and exhaustive offline-table G3 baselines."""

import argparse
from contextlib import nullcontext
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from statistics import median
from struct import Struct
from time import perf_counter

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gap_model import GAP, MAX_FEE, VERTICES, fees, fixture, prepared_bounds, whole_bounds

RECORD = Struct("<9s32sQIII")
SHAPES = (4,8,12,16,20)
VERSION = b"TVNoZKv15"


@dataclass(frozen=True)
class Source:
    routes: tuple
    sid: int
    policy: bytes
    key: Ed25519PrivateKey

    @classmethod
    def enroll(cls, n: int):
        model = {
            "slots": n, "vertices": VERTICES, "gap": GAP,
            "max_fee": MAX_FEE, "start_and_end_vertex": 0,
            "edge_fees": [fees(i).tolist() for i in range(GAP)],
        }
        canonical = json.dumps(model,sort_keys=True,separators=(",",":")).encode()
        return cls(fixture(n), 3000+n, sha256(canonical).digest(),Ed25519PrivateKey.generate())

    def sign(self, mask: int, lower: int, upper: int) -> bytes:
        message = RECORD.pack(VERSION,self.policy,self.sid,mask,lower,upper)
        return message+self.key.sign(message)

    def online(self, mask: int) -> bytes:
        return self.sign(mask,*whole_bounds(self.routes,mask))


def verify(key: Ed25519PublicKey, wire: bytes, policy: bytes,sid: int,
           mask: int) -> tuple[int,int]:
    if len(wire) != RECORD.size+64:
        raise ValueError("invalid signed row length")
    record,signature = wire[:RECORD.size],wire[RECORD.size:]
    key.verify(signature,record)
    version,p,scoped_sid,scoped_mask,lower,upper = RECORD.unpack(record)
    if (version,p,scoped_sid,scoped_mask) != (VERSION,policy,sid,mask) or lower>upper:
        raise ValueError("incorrect signed row scope")
    return lower,upper


def lookup(table: Path, mask: int, count: int) -> bytes:
    if not 0 <= mask < count:
        raise ValueError("offline query mask out of range")
    width = RECORD.size+64
    with table.open("rb") as f:
        f.seek(mask*width)
        return f.read(width)


def run(n: int, table: Path | None = None) -> dict:
    source = Source.enroll(n)
    public = source.key.public_key()
    full = (1<<n)-1
    probes = {0,1,full//3,full//2,full}
    online = []
    sample = {}
    for mask in sorted(probes):
        began = perf_counter()
        signed = source.online(mask)
        online.append(1000*(perf_counter()-began))
        sample[mask] = verify(public,signed,source.policy,source.sid,mask)
    total = size = 0
    signed_rows = sha256()
    began = perf_counter()
    with (table.open("xb") if table is not None else nullcontext()) as sink:
        for mask, lower, upper in prepared_bounds(source.routes):
            row = source.sign(mask,lower,upper)
            if mask in probes:
                assert verify(public,row,source.policy,source.sid,mask)==sample[mask]
            if sink is not None:
                sink.write(row)
            signed_rows.update(row)
            total += 1
            size += len(row)
    elapsed = perf_counter()-began
    assert total == (1<<n) and size == total*(RECORD.size+64)

    if table is not None:
        assert table.stat().st_size==size
        for mask in probes:
            assert verify(public,lookup(table,mask,total),source.policy,source.sid,mask)==sample[mask]
        with table.open("rb") as f:
            assert sha256_iter(f)==signed_rows.hexdigest()

    sample_record = source.online(1)
    negative = []
    for wire,policy,sid,mask in (
        (sample_record[:-1]+bytes([sample_record[-1]^1]),source.policy,source.sid,1),
        (sample_record,source.policy,source.sid+1,1),
        (sample_record,b"\x00"*32,source.sid,1),
        (sample_record,source.policy,source.sid,0),
        (sample_record[:-1],source.policy,source.sid,1),
    ):
        try:
            verify(public,wire,policy,sid,mask)
        except (ValueError,InvalidSignature):
            negative.append(True)
        else:
            negative.append(False)
    return {
        "slots":n,"signed_offline_rows":total,"encoded_signed_bytes":size,
        "signature_bytes":64*total,"online_signed_request_median_ms":median(online),
        "offline_precompute_and_sign_seconds":elapsed, "offline_encoding":"canonical binary rows",
        "offline_stream_sha256":signed_rows.hexdigest(),"online_offline_agreement_probes":len(probes),
        "negative_verified":sum(negative),"negative_total":len(negative),
        "table_material": "indexed local binary table" if table is not None else "streamed signed rows",
        "table_path": str(table.resolve()) if table is not None else None,
        "tested_indexed_lookups": len(probes) if table is not None else 0,
        "verifier_public_key_hex":public.public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
        "session_policy_digest":source.policy.hex(), "session_id":source.sid,
        "source_signature":"Ed25519 over session, policy, opened subset and coupled bounds",
        "scope":"synthetic edge-rate corridor with waypoint anchors every four slots",
    }


def sha256_iter(file) -> str:
    digest=sha256()
    for page in iter(lambda: file.read(1024*1024), b""):
        digest.update(page)
    return digest.hexdigest()


if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out",type=Path)
    ap.add_argument("--materialize",action="store_true")
    a=ap.parse_args()
    a.out.mkdir(parents=True,exist_ok=True)
    for n in SHAPES:
        p=a.out/f"nozk_n{n}.json"
        if p.exists():
            continue
        data=run(n,a.out/f"table_n{n}.bin" if a.materialize else None)
        with p.open("x") as f:
            f.write(json.dumps(data,indent=2)+"\n")
        print(f"n={n}: signed {data['signed_offline_rows']:,} rows, {data['encoded_signed_bytes']:,} bytes",flush=True)
