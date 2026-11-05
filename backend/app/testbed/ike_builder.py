"""Byte-exact builders for IKEv1 (ISAKMP) and IKEv2 messages.

Built by hand with ``struct`` (instead of Scapy's layers) so that the wire
format is fully under our control and matches RFC 2408/2409/7296 exactly.
Encrypted payloads (SK / IKEv1 encrypted body) are emitted as random bytes of
the correct length for the negotiated cipher - exactly what a passive sensor
would see on the wire.
"""
from __future__ import annotations

import os
import struct

from app.analyzer.constants import DH_KE_LEN, T_DH, T_ENCR, T_INTEG, T_PRF

# ----------------------------------------------------------------- IKEv2 ----


def v2_transform(ttype: int, tid: int, key_len: int | None = None, last: bool = False) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_len) if key_len else b""
    length = 8 + len(attrs)
    return struct.pack("!BBHBBH", 0 if last else 3, 0, length, ttype, 0, tid) + attrs


def v2_proposal(num: int, proto: int, transforms: list[tuple], spi: bytes = b"", last: bool = True) -> bytes:
    body = b""
    for i, t in enumerate(transforms):
        body += v2_transform(*t, last=(i == len(transforms) - 1))
    length = 8 + len(spi) + len(body)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, length, num, proto, len(spi), len(transforms)) + spi + body


def v2_ike_transforms(enc: int, key_len: int | None, prf: int, integ: int | None, dh: int) -> list[tuple]:
    t = [(T_ENCR, enc, key_len), (T_PRF, prf, None)]
    if integ:
        t.append((T_INTEG, integ, None))
    t.append((T_DH, dh, None))
    return t


def _payloads(chain: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """chain = [(payload_type, body), ...] -> (first_type, bytes)."""
    out = b""
    for i, (_ptype, body) in enumerate(chain):
        nxt = chain[i + 1][0] if i + 1 < len(chain) else 0
        out += struct.pack("!BBH", nxt, 0, 4 + len(body)) + body
    return (chain[0][0] if chain else 0), out


def v2_message(ispi: bytes, rspi: bytes, exch: int, flags: int, msg_id: int, chain: list[tuple[int, bytes]]) -> bytes:
    first, body = _payloads(chain)
    return struct.pack("!8s8sBBBBII", ispi, rspi, first, 0x20, exch, flags, msg_id, 28 + len(body)) + body


def v2_sk_blob(plain_len: int, iv: int, icv: int, block: int) -> bytes:
    """Encrypted (SK) payload body: IV | ciphertext (padded) | ICV."""
    padded = plain_len + 1
    padded += (-padded) % block
    return os.urandom(iv + padded + icv)


def v2_notify(ntype: int, data: bytes = b"", proto: int = 0) -> bytes:
    return struct.pack("!BBH", proto, 0, ntype) + data


def v2_ke(group: int) -> bytes:
    return struct.pack("!HH", group, 0) + os.urandom(DH_KE_LEN.get(group, 256))


# ----------------------------------------------------------------- IKEv1 ----


def v1_attr(atype: int, value: int) -> bytes:
    if value <= 0xFFFF:
        return struct.pack("!HH", 0x8000 | atype, value)
    return struct.pack("!HHI", atype, 4, value)


def v1_sa(transforms: list[dict]) -> bytes:
    """SA payload body (DOI + situation + proposal payload w/ transforms)."""
    tbody = b""
    for i, attrs in enumerate(transforms):
        a = b"".join(v1_attr(k, v) for k, v in attrs.items())
        nxt = 3 if i + 1 < len(transforms) else 0
        inner = struct.pack("!BBH", i + 1, 1, 0) + a  # transform#, KEY_IKE, reserved
        tbody += struct.pack("!BBH", nxt, 0, 4 + len(inner)) + inner
    prop_inner = struct.pack("!BBBB", 1, 1, 0, len(transforms)) + tbody
    prop = struct.pack("!BBH", 0, 0, 4 + len(prop_inner)) + prop_inner
    return struct.pack("!II", 1, 1) + prop


def v1_message(ispi: bytes, rspi: bytes, exch: int, flags: int, msg_id: int, chain: list[tuple[int, bytes]]) -> bytes:
    first, body = _payloads(chain)
    return struct.pack("!8s8sBBBBII", ispi, rspi, first, 0x10, exch, flags, msg_id, 28 + len(body)) + body


def v1_encrypted(ispi: bytes, rspi: bytes, exch: int, msg_id: int, first: int, plain_len: int, block: int) -> bytes:
    padded = plain_len + ((-plain_len) % block)
    body = os.urandom(padded)
    return struct.pack("!8s8sBBBBII", ispi, rspi, first, 0x10, exch, 0x01, msg_id, 28 + len(body)) + body


def v1_id(id_type: int, data: bytes) -> bytes:
    return struct.pack("!BBH", id_type, 17, 500) + data
