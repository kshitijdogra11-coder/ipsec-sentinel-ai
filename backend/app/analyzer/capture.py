"""Turns a raw capture into an IPsec-aware model: IKE messages, ESP/AH SAs,
cleartext 'normal' traffic and per-packet ESP observations."""
from __future__ import annotations

import hashlib
import os
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .ike_parser import looks_like_ike, parse_ike
from .pcap_reader import read_packets

WELL_KNOWN = {53: "DNS", 123: "NTP", 80: "HTTP", 443: "HTTPS", 22: "SSH", 67: "DHCP", 68: "DHCP",
              5060: "SIP", 25: "SMTP", 587: "SMTP", 993: "IMAPS", 1701: "L2TP", 1194: "OpenVPN",
              51820: "WireGuard"}


@dataclass
class EspObs:
    t: float
    src: str
    dst: str
    spi: int
    seq: int
    esp_len: int      # bytes after SPI+SeqNo (IV + ciphertext + ICV)
    ip_len: int
    natt: bool
    head: bytes       # first 48 bytes after SPI/Seq (for NULL-cipher detection)
    tail: bytes       # last 40 bytes


@dataclass
class AhObs:
    t: float
    src: str
    dst: str
    spi: int
    seq: int
    next_header: int
    icv_len: int
    ip_len: int


@dataclass
class Capture:
    path: str
    sha256: str = ""
    size_bytes: int = 0
    total_packets: int = 0
    malformed: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    ip_versions: Counter = field(default_factory=Counter)
    ike: list[dict] = field(default_factory=list)
    esp: list[EspObs] = field(default_factory=list)
    ah: list[AhObs] = field(default_factory=list)
    cleartext: Counter = field(default_factory=Counter)
    cleartext_bytes: int = 0
    natt_keepalives: int = 0
    talkers: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _esp(cap: Capture, p, data: bytes, natt: bool):
    if len(data) < 8:
        cap.malformed += 1
        return
    spi, seq = struct.unpack("!II", data[:8])
    body = data[8:]
    cap.esp.append(EspObs(p.ts, p.src, p.dst, spi, seq, len(body), p.ip_len, natt, body[:48], body[-40:]))


def parse_capture(path: str, max_packets: int = 2_000_000) -> Capture:
    cap = Capture(path=path, sha256=sha256_file(path), size_bytes=os.path.getsize(path))
    for p in read_packets(path, max_packets=max_packets):
        cap.total_packets += 1
        if p is None:
            cap.malformed += 1
            continue
        if cap.first_ts == 0.0 or p.ts < cap.first_ts:
            cap.first_ts = p.ts
        cap.last_ts = max(cap.last_ts, p.ts)
        cap.ip_versions[p.ip_ver] += 1
        cap.talkers[(p.src, p.dst)] += 1
        if p.proto == 50:
            _esp(cap, p, p.payload, False)
        elif p.proto == 51:
            d = p.payload
            if len(d) >= 12:
                nh, plen = d[0], d[1]
                spi, seq = struct.unpack("!II", d[4:12])
                cap.ah.append(AhObs(p.ts, p.src, p.dst, spi, seq, nh, (plen + 2) * 4 - 12, p.ip_len))
            else:
                cap.malformed += 1
        elif p.proto == 17 and (p.sport in (500, 4500) or p.dport in (500, 4500)):
            d = p.payload
            if p.sport == 4500 or p.dport == 4500:
                if len(d) == 1 and d[0] == 0xFF:
                    cap.natt_keepalives += 1
                    continue
                if d[:4] == b"\x00\x00\x00\x00":
                    d = d[4:]
                else:
                    _esp(cap, p, d, True)
                    continue
            if looks_like_ike(d):
                try:
                    m = parse_ike(d)
                except (struct.error, IndexError, ValueError):
                    m = None
                if m:
                    m.update(t=p.ts, src=p.src, dst=p.dst, sport=p.sport, dport=p.dport, natt=p.dport == 4500 or p.sport == 4500)
                    cap.ike.append(m)
                    continue
            cap.malformed += 1
        else:
            if p.proto in (6, 17):
                port = min(p.sport, p.dport)
                label = WELL_KNOWN.get(p.sport) or WELL_KNOWN.get(p.dport) or f"{'TCP' if p.proto == 6 else 'UDP'}/{port}"
            else:
                label = {1: "ICMP", 58: "ICMPv6", 47: "GRE", -1: "IP-fragment"}.get(p.proto, f"IP-proto-{p.proto}")
            cap.cleartext[label] += 1
            cap.cleartext_bytes += p.ip_len
    cap.ike.sort(key=lambda m: m["t"])
    cap.esp.sort(key=lambda e: e.t)
    return cap


def group_sas(cap: Capture) -> dict[tuple, list[EspObs]]:
    sas: dict[tuple, list[EspObs]] = defaultdict(list)
    for e in cap.esp:
        sas[(e.src, e.dst, e.spi)].append(e)
    return sas
