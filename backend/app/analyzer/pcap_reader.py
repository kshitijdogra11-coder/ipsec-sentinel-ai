"""Hardened, dependency-free pcap / pcapng reader and L2-L4 decoder.

Why not Scapy/dpkt for ingest?  Captures are *untrusted input* uploaded by
users. This reader is small, bounds-checked at every slice, never evaluates
data, enforces packet/size budgets, and counts (rather than raises on)
malformed frames - which keeps the attack surface of the upload path minimal.

Supported: pcap (LE/BE, µs/ns), pcapng (SHB/IDB/EPB/SPB/OPB), link types
Ethernet (1), RAW (101/228/229), Linux SLL (113), SLL2 (276), NULL/LOOP (0/108),
802.1Q/QinQ VLAN tags, IPv6 extension headers.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class CaptureFormatError(ValueError):
    pass


@dataclass(slots=True)
class Packet:
    ts: float
    ip_ver: int
    src: str
    dst: str
    proto: int           # L4 protocol after IPv6 ext headers
    ip_len: int          # total IP datagram length
    sport: int = 0
    dport: int = 0
    payload: bytes = b""  # L4 payload (for UDP) or IP payload (ESP/AH/others)
    ttl: int = 0


def sniff_format(head: bytes) -> str:
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if head[:4] == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFormatError("Not a pcap/pcapng file (bad magic number)")


def _frames_pcap(f: BinaryIO, head: bytes, max_packets: int) -> Iterator[tuple[float, int, bytes]]:
    endian, res = PCAP_MAGICS[head[:4]]
    rest = f.read(20)
    if len(rest) < 20:
        raise CaptureFormatError("Truncated pcap global header")
    _vmaj, _vmin, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", rest)
    linktype &= 0x0FFFFFFF
    hdr = struct.Struct(endian + "IIII")
    n = 0
    while n < max_packets:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = hdr.unpack(h)
        if incl > 262144:
            raise CaptureFormatError("Packet record larger than 256 KiB - corrupt capture")
        data = f.read(incl)
        if len(data) < incl:
            return
        n += 1
        yield sec + frac * res, linktype, data


def _frames_pcapng(f: BinaryIO, max_packets: int) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    ifaces: list[tuple[int, float]] = []
    n = 0
    first = True
    while n < max_packets:
        h = f.read(8)
        if len(h) < 8:
            return
        if first or h[:4] == PCAPNG_MAGIC:
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise CaptureFormatError("Bad pcapng byte-order magic")
            btype, blen = struct.unpack(endian + "II", h)
            if blen < 16 or blen > 1 << 24:
                raise CaptureFormatError("Bad pcapng block length")
            f.read(blen - 12)
            ifaces = []
            first = False
            continue
        btype, blen = struct.unpack(endian + "II", h)
        if blen < 12 or blen > 1 << 24 or blen % 4:
            raise CaptureFormatError("Bad pcapng block length")
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1 and len(body) >= 8:  # IDB
            linktype = struct.unpack(endian + "H", body[:2])[0]
            res = 1e-6
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = opts[i + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + olen + ((-olen) % 4)
            ifaces.append((linktype, res))
        elif btype == 6 and len(body) >= 20:  # EPB
            iid, th, tl, cap, _orig = struct.unpack(endian + "IIIII", body[:20])
            if iid >= len(ifaces):
                continue
            lt, res = ifaces[iid]
            n += 1
            yield ((th << 32) | tl) * res, lt, body[20:20 + cap]
        elif btype == 3 and len(body) >= 4 and ifaces:  # SPB
            n += 1
            yield 0.0, ifaces[0][0], body[4:]
        elif btype == 2 and len(body) >= 20:  # obsolete PB
            iid, _d, th, tl, cap, _o = struct.unpack(endian + "HHIIII", body[:20])
            if iid < len(ifaces):
                n += 1
                yield ((th << 32) | tl) * ifaces[iid][1], ifaces[iid][0], body[20:20 + cap]


def _l3(linktype: int, frame: bytes) -> tuple[int, bytes] | None:
    """Return (ethertype-ish, l3 bytes)."""
    if linktype == 1:
        if len(frame) < 14:
            return None
        et = struct.unpack("!H", frame[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
            et = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return et, frame[off:]
    if linktype in (101, 228, 229, 12, 14):
        if not frame:
            return None
        v = frame[0] >> 4
        return (0x0800 if v == 4 else 0x86DD), frame
    if linktype == 113 and len(frame) >= 16:
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
    if linktype == 276 and len(frame) >= 20:
        return struct.unpack("!H", frame[0:2])[0], frame[20:]
    if linktype in (0, 108) and len(frame) >= 4:
        fam = struct.unpack("<I", frame[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", frame[:4])[0]
        return (0x0800 if fam == 2 else 0x86DD), frame[4:]
    return None


V6_EXT = {0, 43, 60, 44, 135, 139, 140}


def decode(ts: float, linktype: int, frame: bytes) -> Packet | None:
    r = _l3(linktype, frame)
    if r is None:
        return None
    et, b = r
    if et == 0x0800 and len(b) >= 20 and b[0] >> 4 == 4:
        ihl = (b[0] & 0x0F) * 4
        total = struct.unpack("!H", b[2:4])[0]
        if ihl < 20 or len(b) < ihl:
            return None
        frag = struct.unpack("!H", b[6:8])[0] & 0x1FFF
        proto = b[9]
        src = str(ipaddress.IPv4Address(b[12:16]))
        dst = str(ipaddress.IPv4Address(b[16:20]))
        body = b[ihl:total] if total >= ihl else b[ihl:]
        pkt = Packet(ts, 4, src, dst, proto, total or len(b), ttl=b[8])
        if frag:
            pkt.proto = -1  # non-first fragment
            return pkt
    elif et == 0x86DD and len(b) >= 40 and b[0] >> 4 == 6:
        plen = struct.unpack("!H", b[4:6])[0]
        nh = b[6]
        src = str(ipaddress.IPv6Address(b[8:24]))
        dst = str(ipaddress.IPv6Address(b[24:40]))
        body = b[40:40 + plen] if plen else b[40:]
        hops = 0
        while nh in V6_EXT and len(body) >= 8 and hops < 8:
            if nh == 44:
                nxt, elen = body[0], 8
            else:
                nxt, elen = body[0], (body[1] + 1) * 8
            nh, body = nxt, body[elen:]
            hops += 1
        pkt = Packet(ts, 6, src, dst, nh, 40 + plen, ttl=b[7])
    else:
        return None
    pkt.payload = body
    if pkt.proto in (6, 17) and len(body) >= 8:
        pkt.sport, pkt.dport = struct.unpack("!HH", body[:4])
        if pkt.proto == 17:
            pkt.payload = body[8:]
        else:
            doff = (body[12] >> 4) * 4 if len(body) >= 13 else 20
            pkt.payload = body[doff:]
    return pkt


def read_packets(path: str, max_packets: int = 2_000_000) -> Iterator[Packet | None]:
    """Yield decoded packets (None for undecodable frames)."""
    with open(path, "rb") as f:
        head = f.read(4)
        fmt = sniff_format(head)
        if fmt == "pcapng":
            f.seek(0)
        frames = _frames_pcap(f, head, max_packets) if fmt == "pcap" else _frames_pcapng(f, max_packets)
        for ts, lt, data in frames:
            try:
                yield decode(ts, lt, data)
            except (struct.error, ValueError, IndexError):
                yield None
