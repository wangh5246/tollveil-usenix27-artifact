#!/usr/bin/env python3
"""Exact circomlib-compatible BN254 Poseidon, BabyJubjub EdDSA-Poseidon (OBU),
and Ed25519 (public roadside M_infra broadcaster) primitives for TollVeil v15.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# BN254 scalar field prime (SNARK_SCALAR_FIELD)
FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# BabyJubjub twisted Edwards parameters (exact match with circomlib/circuits/babyjub.circom)
BJ_A = 168700
BJ_D = 168696
BJ_SUBORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041
BJ_BASE8 = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)

# Protocol domain tags (shared with stream_slot_auth.circom)
DOMAIN_SLOT = 1001
DOMAIN_FAULT = 1002
STATUS_VALID = 1
DOMAIN_INFRA_BROADCAST = b"TOLLVEIL_V15_INFRA_FAULT_BROADCAST_v1"

POSEIDON_CONSTANTS_PATH = Path(
    "${WORKSPACE_ROOT}/.worktrees/waybill_formal/node_modules/circomlib/circuits/poseidon_constants.circom"
)
N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]


def _extract_circom_array(text: str, func_name: str, t: int):
    fn_pat = rf"function\s+{func_name}\s*\(t\)\s*\{{(.*?)\n\}}"
    m_fn = re.search(fn_pat, text, flags=re.S)
    if not m_fn:
        raise ValueError(f"Function {func_name} not found in poseidon_constants.circom")
    body = m_fn.group(1)
    # Match `if (t==<t>)` or `else if (t==<t>)`
    branch_pat = rf"if\s*\(\s*t\s*==\s*{t}\s*\)\s*\{{\s*return\s*(\[.*?\]);\s*\}}"
    m_br = re.search(branch_pat, body, flags=re.S)
    if not m_br:
        raise ValueError(f"{func_name}({t}) branch not found")
    raw = m_br.group(1)
    # Replace hex literals with decimal ints for json.loads
    dec = re.sub(r"0x[0-9a-fA-F]+", lambda m: str(int(m.group(0), 16)), raw)
    return json.loads(dec)


@lru_cache(maxsize=16)
def _load_poseidon_params(t: int):
    text = POSEIDON_CONSTANTS_PATH.read_text(encoding="utf-8")
    C = [x % FIELD_P for x in _extract_circom_array(text, "POSEIDON_C", t)]
    S = [x % FIELD_P for x in _extract_circom_array(text, "POSEIDON_S", t)]
    M = [[x % FIELD_P for x in row] for row in _extract_circom_array(text, "POSEIDON_M", t)]
    P = [[x % FIELD_P for x in row] for row in _extract_circom_array(text, "POSEIDON_P", t)]
    return C, S, M, P


def _sigma(x: int) -> int:
    x2 = (x * x) % FIELD_P
    x4 = (x2 * x2) % FIELD_P
    return (x4 * x) % FIELD_P


def _mix(state: list[int], M: list[list[int]]) -> list[int]:
    t = len(state)
    out = []
    for i in range(t):
        acc = 0
        for j in range(t):
            acc = (acc + M[j][i] * state[j]) % FIELD_P
        out.append(acc)
    return out


def _mix_s(state: list[int], S: list[int], r: int) -> list[int]:
    t = len(state)
    base = (t * 2 - 1) * r
    lc = 0
    for i in range(t):
        lc = (lc + S[base + i] * state[i]) % FIELD_P
    out = [lc]
    for i in range(1, t):
        out.append((state[i] + state[0] * S[base + t + i - 1]) % FIELD_P)
    return out


def poseidon(inputs: list[int], initial_state: int = 0) -> int:
    """Bit-exact equivalent of circomlib's `Poseidon(len(inputs))`."""
    n_inputs = len(inputs)
    if not (1 <= n_inputs <= 16):
        raise ValueError(f"Unsupported Poseidon arity: {n_inputs}")
    t = n_inputs + 1
    n_rounds_f = 8
    n_rounds_p = N_ROUNDS_P[t - 2]
    C, S, M, P = _load_poseidon_params(t)

    state = [initial_state % FIELD_P] + [int(x) % FIELD_P for x in inputs]
    # ark[0]
    state = [(state[j] + C[j]) % FIELD_P for j in range(t)]

    # First half full rounds (r = 0 .. nRoundsF/2 - 2)
    for r in range(n_rounds_f // 2 - 1):
        state = [_sigma(x) for x in state]
        off = (r + 1) * t
        state = [(state[j] + C[off + j]) % FIELD_P for j in range(t)]
        state = _mix(state, M)

    # Middle full round with P matrix
    state = [_sigma(x) for x in state]
    off = (n_rounds_f // 2) * t
    state = [(state[j] + C[off + j]) % FIELD_P for j in range(t)]
    state = _mix(state, P)

    # Partial rounds
    p_base = (n_rounds_f // 2 + 1) * t
    for r in range(n_rounds_p):
        state[0] = (_sigma(state[0]) + C[p_base + r]) % FIELD_P
        state = _mix_s(state, S, r)

    # Second half full rounds (r = 0 .. nRoundsF/2 - 2)
    f2_base = (n_rounds_f // 2 + 1) * t + n_rounds_p
    for r in range(n_rounds_f // 2 - 1):
        state = [_sigma(x) for x in state]
        off = f2_base + r * t
        state = [(state[j] + C[off + j]) % FIELD_P for j in range(t)]
        state = _mix(state, M)

    # Final sigma + MixLast(s=0)
    state = [_sigma(x) for x in state]
    acc = 0
    for j in range(t):
        acc = (acc + M[j][0] * state[j]) % FIELD_P
    return acc


# ---- BabyJubjub curve arithmetic ----

def bj_is_on_curve(pt: tuple[int, int]) -> bool:
    x, y = pt[0] % FIELD_P, pt[1] % FIELD_P
    lhs = (BJ_A * x * x + y * y) % FIELD_P
    rhs = (1 + BJ_D * x * x * y * y) % FIELD_P
    return lhs == rhs


def bj_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    beta = (x1 * y2) % FIELD_P
    gamma = (y1 * x2) % FIELD_P
    delta = (BJ_D * x1 * x2 * y1 * y2) % FIELD_P
    x3 = ((beta + gamma) * pow((1 + delta) % FIELD_P, -1, FIELD_P)) % FIELD_P
    y3 = (((y1 * y2 - BJ_A * x1 * x2) % FIELD_P) * pow((1 - delta) % FIELD_P, -1, FIELD_P)) % FIELD_P
    return (x3, y3)


def bj_mul(pt: tuple[int, int], scalar: int) -> tuple[int, int]:
    s = scalar % BJ_SUBORDER
    acc = (0, 1)
    base = pt
    while s > 0:
        if s & 1:
            acc = bj_add(acc, base)
        base = bj_add(base, base)
        s >>= 1
    return acc


def hash_to_field(*parts: str | int | bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, bytes):
            h.update(p)
        else:
            h.update(str(p).encode("utf-8"))
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % FIELD_P


@dataclass(frozen=True)
class EdDSAPoseidonSig:
    R8x: int
    R8y: int
    S: int
    M: int


class OBUKeyPair:
    """Hardware OBU BabyJubjub EdDSA-Poseidon signer compatible with circomlib EdDSAPoseidonVerifier."""

    def __init__(self, seed: bytes):
        digest = hashlib.sha512(seed).digest()
        # Private scalar in [1, BJ_SUBORDER - 1]
        self._s0 = (int.from_bytes(digest[:32], "little") % (BJ_SUBORDER - 1)) + 1
        self._nonce_key = digest[32:]
        # Public key A = s0 * BASE8 (lies in prime-order subgroup, so 8*A = (8*s0 mod l)*BASE8 != 0)
        self.Ax, self.Ay = bj_mul(BJ_BASE8, self._s0)
        assert bj_is_on_curve((self.Ax, self.Ay))

    def pk_commit(self, pk_salt: int) -> int:
        return poseidon([self.Ax, self.Ay, pk_salt % FIELD_P])

    def sign_field(self, msg_field: int) -> EdDSAPoseidonSig:
        M = msg_field % FIELD_P
        # Deterministic RFC-8032-style nonce from (nonce_key, M)
        r_bytes = hashlib.sha512(self._nonce_key + M.to_bytes(32, "big")).digest()
        r = (int.from_bytes(r_bytes, "little") % (BJ_SUBORDER - 1)) + 1
        R8x, R8y = bj_mul(BJ_BASE8, r)
        h = poseidon([R8x, R8y, self.Ax, self.Ay, M])
        # Verification checks: S * BASE8 == R8 + h * (8 * A) == (r + h * 8 * s0) * BASE8
        S = (r + h * 8 * self._s0) % BJ_SUBORDER
        return EdDSAPoseidonSig(R8x=R8x, R8y=R8y, S=S, M=M)

    def sign_slot(self, session_id: int, slot_idx: int, u_i: int, v_i: int, d_i: int) -> EdDSAPoseidonSig:
        msg = poseidon([DOMAIN_SLOT, session_id, slot_idx, u_i, v_i, d_i, STATUS_VALID])
        return self.sign_field(msg)

    def sign_fault_mask(self, session_id: int, fault_mask: int) -> EdDSAPoseidonSig:
        msg = poseidon([DOMAIN_FAULT, session_id, fault_mask])
        return self.sign_field(msg)


def verify_eddsa_poseidon(Ax: int, Ay: int, sig: EdDSAPoseidonSig) -> bool:
    """Mirror of circomlib EdDSAPoseidonVerifier()."""
    if not (0 <= sig.S < BJ_SUBORDER):
        return False
    if not bj_is_on_curve((Ax, Ay)) or not bj_is_on_curve((sig.R8x, sig.R8y)):
        return False
    # 8 * A (3 doublings)
    a2 = bj_add((Ax, Ay), (Ax, Ay))
    a4 = bj_add(a2, a2)
    a8 = bj_add(a4, a4)
    if a8[0] == 0:
        return False
    h = poseidon([sig.R8x, sig.R8y, Ax, Ay, sig.M])
    rhs = bj_add((sig.R8x, sig.R8y), bj_mul(a8, h))
    lhs = bj_mul(BJ_BASE8, sig.S)
    return lhs == rhs


def commit_state(
    session_id: int,
    corridor_id: int,
    pending_mask: int,
    L: int,
    U: int,
    C: int,
    R: int,
    salt: int,
) -> int:
    """State commitment matching StreamSlotAuth circuit."""
    return poseidon([session_id, corridor_id, pending_mask, L, U, C, R, salt])


# ---- Public roadside / infrastructure fault broadcaster (Ed25519) ----

@dataclass(frozen=True)
class InfraFaultBroadcast:
    """Public signed broadcast M_infra keyed ONLY on (corridor_id, epoch_id).
    Never receives or embeds any vehicle session_id, inner state, or revision.
    """
    corridor_id: int
    epoch_id: int
    infra_fault_mask: int
    signature_hex: str
    broadcaster_pubkey_hex: str

    def canonical_bytes(self) -> bytes:
        payload = json.dumps(
            {
                "domain": DOMAIN_INFRA_BROADCAST.decode("ascii"),
                "corridor_id": self.corridor_id,
                "epoch_id": self.epoch_id,
                "infra_fault_mask": self.infra_fault_mask,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return payload


class InfraBroadcaster:
    """Stateless public infrastructure outage broadcaster (zero per-vehicle interaction)."""

    def __init__(self, seed: bytes | None = None):
        if seed is not None:
            key_bytes = hashlib.sha256(seed).digest()
            self._priv = Ed25519PrivateKey.from_private_bytes(key_bytes)
        else:
            self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self.pubkey_hex = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def publish_broadcast(self, corridor_id: int, epoch_id: int, infra_fault_mask: int) -> InfraFaultBroadcast:
        draft = InfraFaultBroadcast(
            corridor_id=corridor_id,
            epoch_id=epoch_id,
            infra_fault_mask=infra_fault_mask,
            signature_hex="",
            broadcaster_pubkey_hex=self.pubkey_hex,
        )
        sig = self._priv.sign(draft.canonical_bytes())
        return InfraFaultBroadcast(
            corridor_id=corridor_id,
            epoch_id=epoch_id,
            infra_fault_mask=infra_fault_mask,
            signature_hex=sig.hex(),
            broadcaster_pubkey_hex=self.pubkey_hex,
        )

    @staticmethod
    def verify_broadcast(bcast: InfraFaultBroadcast, expected_pubkey_hex: str) -> bool:
        if bcast.broadcaster_pubkey_hex != expected_pubkey_hex:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_pubkey_hex))
            pub.verify(bytes.fromhex(bcast.signature_hex), bcast.canonical_bytes())
            return True
        except Exception:
            return False
