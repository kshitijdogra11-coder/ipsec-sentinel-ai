"""Bounds-checked IKEv1 (ISAKMP) and IKEv2 message dissector."""
from __future__ import annotations

import struct
from typing import Any

from .constants import (
    DH_GROUPS, IKEV1_AUTH, IKEV1_ENCR, IKEV1_EXCHANGE, IKEV1_HASH, IKEV1_PAYLOAD, IKEV2_ENCR,
    IKEV2_EXCHANGE, IKEV2_INTEG, IKEV2_NOTIFY, IKEV2_PAYLOAD, IKEV2_PRF, VENDOR_IDS,
)

MAX_PAYLOADS = 64


def looks_like_ike(data: bytes) -> bool:
    if len(data) < 28:
        return False
    ver = data[17]
    if ver not in (0x10, 0x20):
        return False
    length = struct.unpack("!I", data[24:28])[0]
    return 28 <= length <= 65535 and data[18] in (1, 2, 4, 5, 6, 32, 33, 34, 35, 36, 37)


def _vendor(vid: bytes) -> str:
    h = vid.hex()
    for k, name in VENDOR_IDS.items():
        if h.startswith(k):
            return name
    return f"unknown ({h[:16]}…)"


def _v2_sa(body: bytes) -> list[dict]:
    props, off = [], 0
    while off + 8 <= len(body) and len(props) < 16:
        more, _r, plen, num, proto, spisz, ntr = struct.unpack("!BBHBBBB", body[off:off + 8])
        if plen < 8 or off + plen > len(body):
            break
        p = {"num": num, "protocol": {1: "IKE", 2: "AH", 3: "ESP"}.get(proto, proto),
             "encr": None, "key_len": None, "prf": None, "integ": None, "dh": None, "esn": None}
        toff = off + 8 + spisz
        for _ in range(min(ntr, 32)):
            if toff + 8 > off + plen:
                break
            _m, _r2, tlen, ttype, _r3, tid = struct.unpack("!BBHBBH", body[toff:toff + 8])
            if tlen < 8:
                break
            attrs = body[toff + 8:toff + tlen]
            kl = None
            if len(attrs) >= 4 and struct.unpack("!H", attrs[:2])[0] == 0x800E:
                kl = struct.unpack("!H", attrs[2:4])[0]
            if ttype == 1:
                p["encr"], p["encr_id"], p["key_len"] = IKEV2_ENCR.get(tid, f"ID-{tid}"), tid, kl
            elif ttype == 2:
                p["prf"] = IKEV2_PRF.get(tid, f"ID-{tid}")
            elif ttype == 3:
                p["integ"] = IKEV2_INTEG.get(tid, f"ID-{tid}")
            elif ttype == 4:
                p["dh"], p["dh_id"] = DH_GROUPS.get(tid, f"ID-{tid}"), tid
            elif ttype == 5:
                p["esn"] = bool(tid)
            toff += tlen
        props.append(p)
        off += plen
        if more == 0:
            break
    return props


def _v1_sa(body: bytes) -> list[dict]:
    out: list[dict] = []
    if len(body) < 8 + 8:
        return out
    off = 8  # DOI + situation
    # proposal payload (generic header)
    _n, _r, plen = struct.unpack("!BBH", body[off:off + 4])
    pbody = body[off + 4:off + plen]
    if len(pbody) < 4:
        return out
    _pnum, _proto, spisz, ntr = struct.unpack("!BBBB", pbody[:4])
    toff = 4 + spisz
    for _ in range(min(ntr, 32)):
        if toff + 8 > len(pbody):
            break
        _nx, _r, tlen = struct.unpack("!BBH", pbody[toff:toff + 4])
        if tlen < 8:
            break
        attrs = pbody[toff + 8:toff + tlen]
        t: dict[str, Any] = {}
        a = 0
        while a + 4 <= len(attrs):
            atype, aval = struct.unpack("!HH", attrs[a:a + 4])
            if atype & 0x8000:
                val, a = aval, a + 4
            else:
                raw = attrs[a + 4:a + 4 + aval]
                val = int.from_bytes(raw, "big") if raw else 0
                a += 4 + aval
            atype &= 0x7FFF
            if atype == 1:
                t["encr"] = IKEV1_ENCR.get(val, f"ID-{val}")
            elif atype == 2:
                t["hash"] = IKEV1_HASH.get(val, f"ID-{val}")
            elif atype == 3:
                t["auth"] = IKEV1_AUTH.get(val, f"ID-{val}")
            elif atype == 4:
                t["dh"], t["dh_id"] = DH_GROUPS.get(val, f"ID-{val}"), val
            elif atype == 11:
                t["life_type"] = {1: "seconds", 2: "kilobytes"}.get(val, val)
            elif atype == 12:
                t["life_duration"] = val
            elif atype == 14:
                t["key_len"] = val
        out.append(t)
        toff += tlen
    return out


def parse_ike(data: bytes) -> dict | None:
    if not looks_like_ike(data):
        return None
    ispi, rspi, nxt, ver, exch, flags, msg_id, length = struct.unpack("!8s8sBBBBII", data[:28])
    v = 2 if ver == 0x20 else 1
    msg: dict[str, Any] = {
        "version": v, "exchange_id": exch,
        "exchange": (IKEV2_EXCHANGE if v == 2 else IKEV1_EXCHANGE).get(exch, f"type-{exch}"),
        "ispi": ispi.hex(), "rspi": rspi.hex(), "msg_id": msg_id, "length": length,
        "initiator": bool(flags & 0x08) if v == 2 else None,
        "response": bool(flags & 0x20) if v == 2 else None,
        "encrypted": bool(flags & 0x01) if v == 1 else False,
        "payloads": [], "proposals": [], "ke_group": None, "ke_len": None, "notifies": [],
        "vendor_ids": [], "identities": [], "sk_len": None, "cert_req": False, "hash_cleartext": False,
    }
    if v == 1 and msg["encrypted"]:
        msg["sk_len"] = length - 28
        return msg
    names = IKEV2_PAYLOAD if v == 2 else IKEV1_PAYLOAD
    off = 28
    end = min(length, len(data))
    for _ in range(MAX_PAYLOADS):
        if nxt == 0 or off + 4 > end:
            break
        n2, _crit, plen = struct.unpack("!BBH", data[off:off + 4])
        if plen < 4 or off + plen > end:
            msg["malformed"] = True
            break
        body = data[off + 4:off + plen]
        pname = names.get(nxt, f"type-{nxt}")
        msg["payloads"].append(pname)
        if pname == "SA":
            msg["proposals"] = _v2_sa(body) if v == 2 else _v1_sa(body)
        elif pname == "KE":
            if v == 2 and len(body) >= 4:
                g = struct.unpack("!H", body[:2])[0]
                msg["ke_group"], msg["ke_len"] = g, len(body) - 4
            else:
                msg["ke_len"] = len(body)
        elif pname == "Notify" and len(body) >= 4:
            ntype = struct.unpack("!H", body[2:4])[0] if v == 2 else struct.unpack("!H", body[6:8])[0] if len(body) >= 8 else 0
            msg["notifies"].append(IKEV2_NOTIFY.get(ntype, str(ntype)))
        elif pname == "VendorID":
            msg["vendor_ids"].append(_vendor(body))
        elif pname in ("ID", "IDi", "IDr") and len(body) >= 4:
            id_type = body[0]
            raw = body[4:]
            if id_type == 1 and len(raw) == 4:
                val = ".".join(str(x) for x in raw)
            elif id_type in (2, 3):
                val = raw.decode("utf-8", "replace")[:128]
            else:
                val = raw.hex()[:64]
            msg["identities"].append({"type": {1: "IPV4_ADDR", 2: "FQDN", 3: "USER_FQDN", 5: "IPV6_ADDR",
                                               9: "DER_ASN1_DN", 11: "KEY_ID"}.get(id_type, id_type), "value": val})
        elif pname == "HASH":
            msg["hash_cleartext"] = True
        elif pname in ("CERTREQ", "CR"):
            msg["cert_req"] = True
        elif pname in ("SK", "SKF"):
            msg["sk_len"] = len(body)
        nxt = n2
        off += plen
    return msg
