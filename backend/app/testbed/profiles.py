"""Application traffic models used to populate the (inner) payload of ESP.

Each profile yields ``Event`` tuples describing the *cleartext* packet that the
VPN will encapsulate. The statistical shapes (packet sizes, inter-arrival
times, direction ratios, burst structure) follow published characterisations
of the respective applications (RTP/G.711 & Opus VoIP, DASH/HLS video
chunking, TLS web page loads, SMTP/IMAP submission, WhatsApp/XMPP chat).
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class Event:
    t: float
    direction: int  # 0 = client -> server (initiator side), 1 = server -> client
    proto: str      # "tcp" | "udp" | "icmp"
    sport: int
    dport: int
    size: int       # L4 payload bytes (application data)
    flags: str = "PA"


MSS = 1448


def _tcp_bulk(ev, t, direction, sport, dport, nbytes, rng, gap=0.0008):
    """Bulk TCP transfer with delayed ACKs from the receiver."""
    sent, k = 0, 0
    while sent < nbytes:
        seg = min(MSS, nbytes - sent)
        ev.append(Event(t, direction, "tcp", sport, dport, seg))
        sent += seg
        k += 1
        if k % 2 == 0:
            ev.append(Event(t + 0.0004 + rng.random() * 0.003, 1 - direction, "tcp", dport, sport, 0, "A"))
        t += gap * (0.6 + rng.random())
    return t


def _handshake(ev, t, sport, dport, rng, rtt):
    ev.append(Event(t, 0, "tcp", sport, dport, 0, "S"))
    ev.append(Event(t + rtt, 1, "tcp", dport, sport, 0, "SA"))
    ev.append(Event(t + rtt * 1.02, 0, "tcp", sport, dport, 0, "A"))
    # TLS 1.3 ClientHello / ServerHello+cert / Finished
    ev.append(Event(t + rtt * 1.05, 0, "tcp", sport, dport, rng.randint(510, 620)))
    t2 = t + rtt * 2.1
    t2 = _tcp_bulk(ev, t2, 1, dport, sport, rng.randint(2600, 5200), rng)
    ev.append(Event(t2 + rtt, 0, "tcp", sport, dport, rng.randint(64, 90)))
    return t2 + rtt * 1.1


def icmp(duration, rng: random.Random):
    ev, t = [], rng.random()
    size = rng.choice([56, 56, 56, 32, 120, 1000])
    interval = rng.choice([1.0, 1.0, 0.5, 0.2])
    rtt = rng.uniform(0.004, 0.06)
    while t < duration:
        ev.append(Event(t, 0, "icmp", 0, 0, size + 8, "req"))
        ev.append(Event(t + rtt * rng.uniform(0.9, 1.2), 1, "icmp", 0, 0, size + 8, "rep"))
        t += interval * rng.uniform(0.98, 1.02)
    return ev


def voip(duration, rng: random.Random):
    ev = []
    codec = rng.choice(["g711", "g729", "opus"])
    ptime = 0.02
    rtp_port_a, rtp_port_b = rng.randrange(10000, 20000, 2), rng.randrange(10000, 20000, 2)
    t = rng.random() * 2
    while t < duration:
        # SIP INVITE / 100 / 180 / 200 / ACK
        for i, (d, s) in enumerate([(0, 950), (1, 380), (1, 520), (1, 880), (0, 420)]):
            ev.append(Event(t + i * 0.03, d, "udp", 5060, 5060, s + rng.randint(-40, 40)))
        t += 0.2
        call_len = rng.uniform(2, 5)
        end = min(duration, t + call_len)
        tt = t
        while tt < end:
            for d in (0, 1):
                if codec == "g711":
                    sz = 172
                elif codec == "g729":
                    sz = 32
                else:
                    sz = rng.randint(70, 130)
                # silence suppression gaps for g729 / opus
                if codec != "g711" and rng.random() < 0.12:
                    continue
                jitter = rng.gauss(0, 0.0015)
                ev.append(Event(tt + jitter + d * 0.0003, d, "udp", rtp_port_a if d == 0 else rtp_port_b,
                                rtp_port_b if d == 0 else rtp_port_a, sz))
            if rng.random() < 0.01:  # RTCP
                ev.append(Event(tt, 0, "udp", rtp_port_a + 1, rtp_port_b + 1, rng.randint(60, 90)))
            tt += ptime
        ev.append(Event(end, 0, "udp", 5060, 5060, 450))  # BYE
        ev.append(Event(end + 0.03, 1, "udp", 5060, 5060, 380))  # 200 OK
        t = end + rng.uniform(8, 20)
    return ev


def video(duration, rng: random.Random):
    ev = []
    rtt = rng.uniform(0.02, 0.08)
    sport = rng.randint(40000, 60000)
    t = rng.random()
    t = _handshake(ev, t, sport, 443, rng, rtt)
    quic = rng.random() < 0.35
    while t < duration:
        ev.append(Event(t, 0, "udp" if quic else "tcp", sport, 443, rng.randint(350, 700)))  # segment request
        chunk = rng.randint(28, 55) * MSS
        if quic:
            sent, tt = 0, t + rtt
            while sent < chunk:
                sz = rng.choice([1252, 1350, 1350])
                ev.append(Event(tt, 1, "udp", 443, sport, sz))
                if (sent // sz) % 8 == 0:
                    ev.append(Event(tt + 0.001, 0, "udp", sport, 443, rng.randint(30, 45)))
                sent += sz
                tt += 0.0007 * (0.6 + rng.random())
        else:
            tt = _tcp_bulk(ev, t + rtt, 1, 443, sport, chunk, rng, gap=0.0006)
        t = tt + rng.uniform(2.0, 4.5)  # player buffer refill interval
    return ev


def web(duration, rng: random.Random):
    ev = []
    t = rng.random()
    rtt = rng.uniform(0.015, 0.12)
    while t < duration:
        n_conn = rng.randint(1, 3)
        page_end = t
        for c in range(n_conn):
            sport = rng.randint(40000, 60000)
            tc = t + c * rng.uniform(0.01, 0.2)
            tc = _handshake(ev, tc, sport, 443, rng, rtt)
            for _ in range(rng.randint(1, 4)):  # HTTP requests on this connection
                ev.append(Event(tc, 0, "tcp", sport, 443, rng.randint(280, 900)))
                size = int(rng.lognormvariate(9.0, 1.3))  # response object ~ e^9 ≈ 8 kB median
                tc = _tcp_bulk(ev, tc + rtt, 1, 443, sport, max(200, min(size, 90000)), rng)
                tc += rng.uniform(0.01, 0.3)
            ev.append(Event(tc, 0, "tcp", sport, 443, 0, "FA"))
            ev.append(Event(tc + rtt, 1, "tcp", 443, sport, 0, "FA"))
            page_end = max(page_end, tc)
        t = page_end + rng.expovariate(1 / 8.0)  # user think time
    return ev


def email(duration, rng: random.Random):
    ev = []
    rtt = rng.uniform(0.02, 0.1)
    t = rng.random()
    port = rng.choice([587, 465, 993])
    while t < duration:
        sport = rng.randint(40000, 60000)
        t = _handshake(ev, t, sport, port, rng, rtt)
        # SMTP / IMAP command-response dialogue (small, strictly alternating)
        for _ in range(rng.randint(5, 9)):
            ev.append(Event(t, 0, "tcp", sport, port, rng.randint(18, 90)))
            ev.append(Event(t + rtt, 1, "tcp", port, sport, rng.randint(20, 140)))
            t += rtt * 1.2 + rng.uniform(0.001, 0.01)
        if port == 993:  # fetch: download
            t = _tcp_bulk(ev, t, 1, port, sport, rng.randint(4000, 150000), rng)
        else:  # submission: upload with attachment
            t = _tcp_bulk(ev, t, 0, sport, port, rng.randint(3000, 200000), rng)
        ev.append(Event(t + rtt, 1, "tcp", port, sport, rng.randint(30, 60)))  # 250 OK
        # IMAP IDLE keepalives until next mail
        nxt = t + rng.uniform(8, 25)
        while t < nxt and t < duration:
            t += rng.uniform(4, 9)
            ev.append(Event(t, 0, "tcp", sport, port, rng.randint(10, 20)))
            ev.append(Event(t + rtt, 1, "tcp", port, sport, rng.randint(20, 40)))
        t = nxt
    return ev


def whatsapp(duration, rng: random.Random):
    ev = []
    rtt = rng.uniform(0.03, 0.15)
    sport = rng.randint(40000, 60000)
    port = rng.choice([443, 5222])
    t = rng.random()
    t = _handshake(ev, t, sport, port, rng, rtt)
    next_ka = t + rng.uniform(15, 30)
    while t < duration:
        # conversation burst
        for _ in range(rng.randint(2, 8)):
            d = rng.randint(0, 1)
            ev.append(Event(t, d, "tcp", sport if d == 0 else port, port if d == 0 else sport, rng.randint(90, 420)))
            # delivery + read receipts
            ev.append(Event(t + rtt, 1 - d, "tcp", port if d == 0 else sport, sport if d == 0 else port, rng.randint(55, 95)))
            if rng.random() < 0.5:
                ev.append(Event(t + rng.uniform(0.5, 3), 1 - d, "tcp", port if d == 0 else sport,
                                sport if d == 0 else port, rng.randint(55, 95)))
            # typing indicator
            if rng.random() < 0.6:
                ev.append(Event(t + rng.uniform(0.3, 1.0), d, "tcp", sport if d == 0 else port,
                                port if d == 0 else sport, rng.randint(40, 70)))
            if rng.random() < 0.08:  # media (image/voice note) upload
                t = _tcp_bulk(ev, t + 0.1, d, sport if d == 0 else port, port if d == 0 else sport,
                              rng.randint(20000, 120000), rng)
            t += rng.uniform(1.5, 9.0)  # human typing delay
        t += rng.uniform(5, 20)
        while next_ka < t:
            ev.append(Event(next_ka, 0, "tcp", sport, port, rng.randint(30, 45)))
            ev.append(Event(next_ka + rtt, 1, "tcp", port, sport, rng.randint(30, 45)))
            next_ka += rng.uniform(15, 30)
    return ev


PROFILES = {"icmp": icmp, "voip": voip, "video": video, "web": web, "email": email, "whatsapp": whatsapp}


def generate(kind: str, duration: float, rng: random.Random, max_events: int = 2500) -> list[Event]:
    ev = [e for e in PROFILES[kind](duration, rng) if 0 <= e.t < duration]
    ev.sort(key=lambda e: e.t)
    return ev[:max_events]
