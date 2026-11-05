"""IPsec VPN testbed traffic generator.

Produces realistic, *really encrypted* IPsec captures (.pcap) for a given VPN
configuration:

* IKEv2 (RFC 7296) or IKEv1 Main/Aggressive Mode (RFC 2409) negotiation
  with byte-exact cleartext payloads and correctly sized encrypted payloads
* ESP (RFC 4303) or AH (RFC 4302) data plane, encrypted with the real
  algorithm/key size via Scapy's SecurityAssociation (AES-CBC, AES-GCM,
  3DES, NULL + HMAC-SHA1/SHA2/MD5)
* Tunnel or Transport mode, IPv4 or IPv6, optional NAT-Traversal (UDP 4500)
* Child SA rekeying (CREATE_CHILD_SA / Quick Mode) with or without PFS
* Application traffic models: VoIP, WhatsApp, e-mail, web, ICMP, video
* Optional replay-attack injection and cleartext background traffic

Used both by the dataset builder (ML training) and interactively from the
dashboard's "Testbed" page. For captures from a *real* strongSwan lab see
``/testbed`` in the repository root.
"""
from __future__ import annotations

import ipaddress
import os
import random
import struct
from dataclasses import asdict, dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.ipsec import AH, ESP, SecurityAssociation
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from app.testbed import ike_builder as ib
from app.testbed import profiles

# ------------------------------------------------------------ configuration --

IKE_ENCR_IDS = {"AES-CBC": 12, "AES-GCM": 20, "3DES": 3, "CHACHA20-POLY1305": 28}
PRF_IDS = {"HMAC-SHA1": 2, "HMAC-SHA2-256": 5, "HMAC-SHA2-384": 6, "HMAC-SHA2-512": 7, "HMAC-MD5": 1}
INTEG_IDS = {"HMAC-SHA1-96": 2, "HMAC-SHA2-256-128": 12, "HMAC-SHA2-384-192": 13,
             "HMAC-SHA2-512-256": 14, "HMAC-MD5-96": 1, "NONE": 0}
INTEG_ICV = {"HMAC-SHA1-96": 12, "HMAC-SHA2-256-128": 16, "HMAC-SHA2-384-192": 24,
             "HMAC-SHA2-512-256": 32, "HMAC-MD5-96": 12, "NONE": 0}
SCAPY_AUTH = {"HMAC-SHA1-96": "HMAC-SHA1-96", "HMAC-SHA2-256-128": "SHA2-256-128",
              "HMAC-SHA2-512-256": "SHA2-512-256", "HMAC-MD5-96": "HMAC-MD5-96", "NONE": None}
V1_ENCR = {"AES-CBC": 7, "3DES": 5, "DES": 1}
V1_HASH = {"HMAC-MD5": 1, "HMAC-SHA1": 2, "HMAC-SHA2-256": 4, "HMAC-SHA2-512": 6}


@dataclass
class VPNConfig:
    name: str = "custom"
    ike_version: int = 2
    ikev1_mode: str = "main"             # main | aggressive
    ike_encr: str = "AES-CBC"
    ike_key_bits: int = 256
    ike_prf: str = "HMAC-SHA2-256"
    ike_integ: str = "HMAC-SHA2-256-128"
    dh_group: int = 14
    auth_method: str = "PSK"             # PSK | RSA
    ike_lifetime: int = 10800
    protocol: str = "ESP"                # ESP | AH
    mode: str = "tunnel"                 # tunnel | transport
    esp_encr: str = "AES-CBC"            # AES-CBC | AES-GCM | 3DES | NULL
    esp_key_bits: int = 256
    esp_integ: str = "HMAC-SHA2-256-128"
    pfs: bool = True
    pfs_group: int = 14
    child_lifetime: int = 3600           # seconds (lab captures use short values to observe rekeys)
    ip_version: int = 4
    nat_t: bool = False
    traffic: str = "web"
    duration: float = 120.0
    replay_attack: bool = False
    background: bool = True
    seed: int | None = None
    labels: dict = field(default_factory=dict)

    def normalized(self) -> "VPNConfig":
        if self.esp_encr == "AES-GCM":
            self.esp_integ = "NONE"
        if self.ike_encr in ("AES-GCM", "CHACHA20-POLY1305"):
            self.ike_integ = "NONE"
        if self.esp_encr == "3DES":
            self.esp_key_bits = 192
        if self.esp_encr == "NULL":
            self.esp_key_bits = 0
        if self.ike_encr == "3DES":
            self.ike_key_bits = 192
        if self.protocol == "AH":
            self.esp_encr, self.esp_key_bits = "NONE", 0
            if self.esp_integ == "NONE":
                self.esp_integ = "HMAC-SHA2-256-128"
        if self.ike_version == 2:
            self.ikev1_mode = "n/a"
        return self


PRESETS: dict[str, dict] = {
    "cnsa-suite-b": dict(ike_encr="AES-GCM", ike_key_bits=256, ike_prf="HMAC-SHA2-384", dh_group=20,
                         auth_method="RSA", esp_encr="AES-GCM", esp_key_bits=256, pfs=True, pfs_group=20,
                         child_lifetime=45, ike_lifetime=14400),
    "enterprise-default": dict(ike_encr="AES-CBC", ike_key_bits=256, dh_group=14, esp_encr="AES-CBC",
                               esp_key_bits=256, esp_integ="HMAC-SHA2-256-128", pfs=True, pfs_group=14,
                               child_lifetime=40),
    "modern-ecp": dict(ike_encr="AES-GCM", ike_key_bits=128, dh_group=31, esp_encr="AES-GCM", esp_key_bits=128,
                       pfs=True, pfs_group=31, child_lifetime=50),
    "host-to-host-transport": dict(mode="transport", esp_encr="AES-CBC", esp_key_bits=128,
                                   esp_integ="HMAC-SHA1-96", pfs=False, dh_group=14, child_lifetime=3600),
    "legacy-ikev1-main": dict(ike_version=1, ikev1_mode="main", ike_encr="3DES", ike_prf="HMAC-SHA1",
                              ike_integ="HMAC-SHA1-96", dh_group=2, esp_encr="3DES", esp_integ="HMAC-SHA1-96",
                              pfs=False, child_lifetime=45, ike_lifetime=86400),
    "insecure-aggressive-psk": dict(ike_version=1, ikev1_mode="aggressive", ike_encr="3DES", ike_prf="HMAC-MD5",
                                    ike_integ="HMAC-MD5-96", dh_group=2, esp_encr="3DES",
                                    esp_integ="HMAC-MD5-96", pfs=False, child_lifetime=86400,
                                    ike_lifetime=172800, auth_method="PSK"),
    "null-encryption": dict(esp_encr="NULL", esp_integ="HMAC-SHA1-96", pfs=False, dh_group=5),
    "ah-integrity-only": dict(protocol="AH", esp_integ="HMAC-SHA2-256-128", pfs=True),
    "ipv6-tunnel": dict(ip_version=6, nat_t=False, esp_encr="AES-GCM", esp_key_bits=256, dh_group=19,
                             pfs=True, pfs_group=19, child_lifetime=40),
    "natt-roadwarrior": dict(nat_t=True, esp_encr="AES-CBC", esp_key_bits=256, dh_group=14, pfs=False,
                             child_lifetime=60),
}


def preset(name: str, **overrides) -> VPNConfig:
    cfg = VPNConfig(name=name, **{**PRESETS[name], **overrides})
    return cfg.normalized()


def random_config(rng: random.Random) -> VPNConfig:
    """Sample a configuration from the test matrix (weighted towards realism)."""
    tier = rng.choices(["strong", "standard", "legacy", "weak"], [0.3, 0.35, 0.2, 0.15])[0]
    v = 2 if tier in ("strong", "standard") or rng.random() < 0.35 else 1
    c = VPNConfig(ike_version=v, name=f"matrix-{tier}")
    c.mode = rng.choices(["tunnel", "transport"], [0.62, 0.38])[0]
    c.ip_version = rng.choice([4, 4, 6])
    c.nat_t = c.ip_version == 4 and rng.random() < 0.25
    c.traffic = rng.choice(list(profiles.PROFILES))
    c.duration = rng.uniform(90, 160)
    c.replay_attack = rng.random() < 0.12
    c.protocol = "AH" if rng.random() < 0.05 else "ESP"
    c.auth_method = rng.choice(["PSK", "RSA"])
    if tier == "strong":
        c.ike_encr = rng.choice(["AES-GCM", "AES-CBC"]); c.ike_key_bits = 256
        c.ike_prf = rng.choice(["HMAC-SHA2-384", "HMAC-SHA2-512"]); c.ike_integ = "HMAC-SHA2-512-256"
        c.dh_group = rng.choice([19, 20, 21, 31, 15, 16])
        c.esp_encr = rng.choice(["AES-GCM", "AES-GCM", "AES-CBC"]); c.esp_key_bits = 256
        c.esp_integ = rng.choice(["HMAC-SHA2-256-128", "HMAC-SHA2-512-256"])
        c.pfs, c.pfs_group = True, c.dh_group
    elif tier == "standard":
        c.ike_encr = rng.choice(["AES-CBC", "AES-GCM"]); c.ike_key_bits = rng.choice([128, 256])
        c.ike_prf = "HMAC-SHA2-256"; c.ike_integ = "HMAC-SHA2-256-128"
        c.dh_group = rng.choice([14, 19, 31])
        c.esp_encr = rng.choice(["AES-CBC", "AES-GCM"]); c.esp_key_bits = rng.choice([128, 256])
        c.esp_integ = rng.choice(["HMAC-SHA2-256-128", "HMAC-SHA1-96"])
        c.pfs = rng.random() < 0.7; c.pfs_group = c.dh_group
    elif tier == "legacy":
        c.ike_encr = rng.choice(["AES-CBC", "3DES"]); c.ike_key_bits = 128
        c.ike_prf = "HMAC-SHA1"; c.ike_integ = "HMAC-SHA1-96"
        c.dh_group = rng.choice([2, 5, 14])
        c.esp_encr = rng.choice(["AES-CBC", "3DES"]); c.esp_key_bits = 128
        c.esp_integ = rng.choice(["HMAC-SHA1-96", "HMAC-MD5-96"])
        c.pfs = rng.random() < 0.3; c.pfs_group = c.dh_group
        c.ikev1_mode = rng.choice(["main", "main", "aggressive"])
    else:
        c.ike_encr = "3DES"; c.ike_prf = rng.choice(["HMAC-MD5", "HMAC-SHA1"])
        c.ike_integ = "HMAC-MD5-96" if c.ike_prf == "HMAC-MD5" else "HMAC-SHA1-96"
        c.dh_group = rng.choice([1, 2])
        c.esp_encr = rng.choice(["3DES", "NULL", "AES-CBC"]); c.esp_key_bits = 128
        c.esp_integ = rng.choice(["HMAC-MD5-96", "HMAC-SHA1-96"])
        c.pfs = False; c.ikev1_mode = "aggressive" if rng.random() < 0.6 else "main"
    # Child SA crypto often differs from IKE SA crypto in the wild
    if rng.random() < 0.25:
        c.esp_key_bits = rng.choice([128, 256])
    c.child_lifetime = rng.choice([30, 40, 60, 3600, 28800]) if tier != "weak" else rng.choice([45, 86400])
    c.ike_lifetime = {"strong": 14400, "standard": 28800, "legacy": 86400, "weak": 172800}[tier]
    return c.normalized()


# ------------------------------------------------------------ packet build --


class _Capture:
    def __init__(self, cfg: VPNConfig, rng: random.Random):
        self.cfg, self.rng = cfg, rng
        self.pkts: list[tuple[float, bytes]] = []
        v6 = cfg.ip_version == 6
        r = rng.randint
        if v6:
            self.gw = (f"2001:db8:{r(1, 0xffff):x}::{r(1, 0xff):x}", f"2001:db8:{r(1, 0xffff):x}::{r(1, 0xff):x}")
            self.inner = (f"fd00:{r(1, 0xff):x}::{r(2, 0xfe):x}", f"fd00:{r(0x100, 0x1ff):x}::{r(2, 0xfe):x}")
        else:
            self.gw = (f"{r(11, 200)}.{r(0, 255)}.{r(0, 255)}.{r(1, 254)}",
                       f"{r(11, 200)}.{r(0, 255)}.{r(0, 255)}.{r(1, 254)}")
            self.inner = (f"10.{r(0, 127)}.{r(0, 255)}.{r(2, 254)}", f"10.{r(128, 255)}.{r(0, 255)}.{r(2, 254)}")
            if cfg.nat_t:  # initiator behind carrier-grade NAT
                self.gw = (f"100.{r(64, 127)}.{r(0, 255)}.{r(1, 254)}", self.gw[1])
        if cfg.mode == "transport":
            self.inner = self.gw
        self.natt_sport = rng.randint(1024, 65000) if cfg.nat_t else 4500
        self.mac = ("02:00:00:%02x:%02x:%02x" % (r(0, 255), r(0, 255), r(0, 255)),
                    "02:00:00:%02x:%02x:%02x" % (r(0, 255), r(0, 255), r(0, 255)))

    # -- outer helpers
    def _ip(self, d: int, src=None, dst=None):
        s, t = (self.gw if d == 0 else self.gw[::-1])
        s, t = src or s, dst or t
        return IPv6(src=s, dst=t, hlim=64) if self.cfg.ip_version == 6 else IP(src=s, dst=t, ttl=64)

    def emit(self, t: float, d: int, pkt):
        eth = Ether(src=self.mac[d], dst=self.mac[1 - d])
        self.pkts.append((t, bytes(eth / pkt)))

    def ike(self, t: float, d: int, payload: bytes, natt: bool = False):
        if natt and self.cfg.nat_t:
            sp, dp = (self.natt_sport, 4500) if d == 0 else (4500, self.natt_sport)
            self.emit(t, d, self._ip(d) / UDP(sport=sp, dport=dp) / Raw(b"\x00\x00\x00\x00" + payload))
        else:
            self.emit(t, d, self._ip(d) / UDP(sport=500, dport=500) / Raw(payload))


def _ike_cipher_params(cfg: VPNConfig) -> tuple[int, int, int]:
    if cfg.ike_encr == "AES-GCM":
        return 8, 16, 4
    if cfg.ike_encr == "3DES":
        return 8, INTEG_ICV[cfg.ike_integ], 8
    return 16, INTEG_ICV[cfg.ike_integ], 16


def _v2_ike_props(cfg: VPNConfig, rng: random.Random, offer: bool) -> bytes:
    kl = cfg.ike_key_bits if cfg.ike_encr in ("AES-CBC", "AES-GCM") else None
    integ = INTEG_IDS[cfg.ike_integ] or None
    chosen = ib.v2_ike_transforms(IKE_ENCR_IDS[cfg.ike_encr], kl, PRF_IDS[cfg.ike_prf], integ, cfg.dh_group)
    if not offer:
        return ib.v2_proposal(1, 1, chosen)
    # Initiator typically offers several proposals, preferred first
    extra = [ib.v2_ike_transforms(12, 128, 5, 12, 14), ib.v2_ike_transforms(20, 256, 6, None, 19)]
    props = [chosen] + rng.sample(extra, rng.randint(0, 2))
    return b"".join(ib.v2_proposal(i + 1, 1, p, last=(i == len(props) - 1)) for i, p in enumerate(props))


def _ikev2_init(cap: _Capture, t: float, ispi: bytes, rspi: bytes):
    cfg, rng = cap.cfg, cap.rng
    nat = lambda: os.urandom(20)  # noqa: E731
    common = [(41, ib.v2_notify(16388, nat())), (41, ib.v2_notify(16389, nat())),
              (41, ib.v2_notify(16430)), (41, ib.v2_notify(16431, b"\x00\x02\x00\x03\x00\x04"))]
    req = ib.v2_message(ispi, b"\x00" * 8, 34, 0x08, 0, [(33, _v2_ike_props(cfg, rng, True)),
                        (34, ib.v2_ke(cfg.dh_group)), (40, os.urandom(32))] + common +
                        [(43, bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb"))])
    resp = ib.v2_message(ispi, rspi, 34, 0x20, 0, [(33, _v2_ike_props(cfg, rng, False)),
                         (34, ib.v2_ke(cfg.dh_group)), (40, os.urandom(32))] + common +
                         [(38, os.urandom(20) if cfg.auth_method == "RSA" else b"\x04" + os.urandom(20))])
    rtt = rng.uniform(0.01, 0.08)
    cap.ike(t, 0, req)
    cap.ike(t + rtt, 1, resp)
    iv, icv, blk = _ike_cipher_params(cfg)
    t2 = t + rtt * 2.2
    auth_plain = 260 + (1350 if cfg.auth_method == "RSA" else 0)
    if cfg.mode == "transport":
        auth_plain += 8  # USE_TRANSPORT_MODE notify
    cap.ike(t2, 0, ib.v2_message(ispi, rspi, 35, 0x08, 1, [(46, ib.v2_sk_blob(auth_plain, iv, icv, blk))]), natt=True)
    cap.ike(t2 + rtt, 1, ib.v2_message(ispi, rspi, 35, 0x20, 1,
            [(46, ib.v2_sk_blob(auth_plain - 20, iv, icv, blk))]), natt=True)
    return t2 + rtt * 1.5, rtt


def _ikev2_rekey(cap: _Capture, t: float, ispi: bytes, rspi: bytes, msg_id: int, rtt: float):
    cfg = cap.cfg
    iv, icv, blk = _ike_cipher_params(cfg)
    plain = 4 + 44 + 4 + 32 + 4 + 24 + 4 + 24 + 12  # SA + Nonce + TSi + TSr + REKEY_SA notify
    if cfg.pfs:
        plain += 4 + 4 + ib.DH_KE_LEN.get(cfg.pfs_group, 256)
    cap.ike(t, 0, ib.v2_message(ispi, rspi, 36, 0x08, msg_id, [(46, ib.v2_sk_blob(plain, iv, icv, blk))]), natt=True)
    cap.ike(t + rtt, 1, ib.v2_message(ispi, rspi, 36, 0x20, msg_id,
                                      [(46, ib.v2_sk_blob(plain - 12, iv, icv, blk))]), natt=True)
    # INFORMATIONAL: delete old child SA
    cap.ike(t + rtt * 1.3, 0, ib.v2_message(ispi, rspi, 37, 0x08, msg_id + 1,
                                            [(46, ib.v2_sk_blob(16, iv, icv, blk))]), natt=True)
    cap.ike(t + rtt * 2.3, 1, ib.v2_message(ispi, rspi, 37, 0x20, msg_id + 1,
                                            [(46, ib.v2_sk_blob(16, iv, icv, blk))]), natt=True)


def _v1_transforms(cfg: VPNConfig) -> list[dict]:
    a = {1: V1_ENCR.get(cfg.ike_encr, 7), 2: V1_HASH.get(cfg.ike_prf, 2), 3: 1 if cfg.auth_method == "PSK" else 3,
         4: cfg.dh_group, 11: 1, 12: cfg.ike_lifetime}
    if cfg.ike_encr == "AES-CBC":
        a[14] = cfg.ike_key_bits
    return [a]


def _ikev1_init(cap: _Capture, t: float, ispi: bytes, rspi: bytes):
    cfg, rng = cap.cfg, cap.rng
    rtt = rng.uniform(0.01, 0.08)
    blk = 8 if cfg.ike_encr == "3DES" else 16
    vids = [(13, bytes.fromhex("4a131c81070358455c5728f20e95452f")),
            (13, bytes.fromhex("afcad71368a1f1c96b8696fc77570100")),
            (13, bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb"))]
    sa_offer = ib.v1_sa(_v1_transforms(cfg) + ([{1: 5, 2: 2, 3: 1, 4: 2, 11: 1, 12: 28800}] if rng.random() < .5 else []))
    sa_chosen = ib.v1_sa(_v1_transforms(cfg))
    ke = lambda: os.urandom(ib.DH_KE_LEN.get(cfg.dh_group, 128))  # noqa: E731
    if cfg.ikev1_mode == "aggressive":
        ident = rng.choice([b"vpn-user@corp.example", b"branch-office-7", b"admin@hq.example.org"])
        m1 = ib.v1_message(ispi, b"\x00" * 8, 4, 0, 0, [(1, sa_offer), (4, ke()), (10, os.urandom(20)),
                           (5, ib.v1_id(3 if b"@" in ident else 2, ident))] + vids)
        m2 = ib.v1_message(ispi, rspi, 4, 0, 0, [(1, sa_chosen), (4, ke()), (10, os.urandom(20)),
                           (5, ib.v1_id(1, os.urandom(4))), (8, os.urandom(20 if 'SHA1' in cfg.ike_prf else 16))] + vids)
        cap.ike(t, 0, m1)
        cap.ike(t + rtt, 1, m2)
        cap.ike(t + rtt * 2, 0, ib.v1_encrypted(ispi, rspi, 4, 0, 8, 28, blk), natt=True)
        t = t + rtt * 2.2
    else:
        cap.ike(t, 0, ib.v1_message(ispi, b"\x00" * 8, 2, 0, 0, [(1, sa_offer)] + vids))
        cap.ike(t + rtt, 1, ib.v1_message(ispi, rspi, 2, 0, 0, [(1, sa_chosen)] + vids))
        cap.ike(t + rtt * 1.5, 0, ib.v1_message(ispi, rspi, 2, 0, 0, [(4, ke()), (10, os.urandom(20)),
                                                (20, os.urandom(20)), (20, os.urandom(20))]))
        cap.ike(t + rtt * 2.5, 1, ib.v1_message(ispi, rspi, 2, 0, 0, [(4, ke()), (10, os.urandom(20)),
                                                (20, os.urandom(20)), (20, os.urandom(20))]))
        idl = 60 + (1200 if cfg.auth_method == "RSA" else 0)
        cap.ike(t + rtt * 3, 0, ib.v1_encrypted(ispi, rspi, 2, 0, 5, idl, blk), natt=True)
        cap.ike(t + rtt * 4, 1, ib.v1_encrypted(ispi, rspi, 2, 0, 5, idl, blk), natt=True)
        t = t + rtt * 4.2
    _ikev1_quick(cap, t, ispi, rspi, rtt)
    return t + rtt * 2.5, rtt


def _ikev1_quick(cap: _Capture, t: float, ispi: bytes, rspi: bytes, rtt: float):
    cfg = cap.cfg
    blk = 8 if cfg.ike_encr == "3DES" else 16
    plain = 24 + 64 + 24 + 16 + 16
    if cfg.pfs:
        plain += 4 + ib.DH_KE_LEN.get(cfg.pfs_group, 128)
    mid = struct.unpack("!I", os.urandom(4))[0]
    cap.ike(t, 0, ib.v1_encrypted(ispi, rspi, 32, mid, 8, plain, blk), natt=True)
    cap.ike(t + rtt, 1, ib.v1_encrypted(ispi, rspi, 32, mid, 8, plain, blk), natt=True)
    cap.ike(t + rtt * 1.5, 0, ib.v1_encrypted(ispi, rspi, 32, mid, 8, 24, blk), natt=True)


def _make_sa(cfg: VPNConfig, cap: _Capture, d: int, spi: int) -> SecurityAssociation:
    kw = {}
    if cfg.mode == "tunnel":
        s, t = cap.gw if d == 0 else cap.gw[::-1]
        kw["tunnel_header"] = IPv6(src=s, dst=t) if cfg.ip_version == 6 else IP(src=s, dst=t)
    if cfg.nat_t and cfg.protocol == "ESP":
        sp, dp = (cap.natt_sport, 4500) if d == 0 else (4500, cap.natt_sport)
        kw["nat_t_header"] = UDP(sport=sp, dport=dp)
    auth = SCAPY_AUTH[cfg.esp_integ]
    auth_key = os.urandom(64) if auth else None
    if cfg.protocol == "AH":
        return SecurityAssociation(AH, spi=spi, auth_algo=auth, auth_key=auth_key, **kw)
    if cfg.esp_encr == "AES-GCM":
        return SecurityAssociation(ESP, spi=spi, crypt_algo="AES-GCM",
                                   crypt_key=os.urandom(cfg.esp_key_bits // 8 + 4), **kw)
    if cfg.esp_encr == "3DES":
        return SecurityAssociation(ESP, spi=spi, crypt_algo="3DES", crypt_key=os.urandom(24),
                                   auth_algo=auth, auth_key=auth_key, **kw)
    if cfg.esp_encr == "NULL":
        return SecurityAssociation(ESP, spi=spi, crypt_algo="NULL", crypt_key=None,
                                   auth_algo=auth, auth_key=auth_key, **kw)
    return SecurityAssociation(ESP, spi=spi, crypt_algo="AES-CBC", crypt_key=os.urandom(cfg.esp_key_bits // 8),
                               auth_algo=auth, auth_key=auth_key, **kw)


def _inner(cfg: VPNConfig, cap: _Capture, e: profiles.Event):
    src, dst = cap.inner if e.direction == 0 else cap.inner[::-1]
    v6 = cfg.ip_version == 6
    ip = IPv6(src=src, dst=dst, hlim=63) if v6 else IP(src=src, dst=dst, ttl=63)
    data = Raw(os.urandom(e.size)) if e.size > 0 else None
    if e.proto == "icmp":
        body = e.size - 8
        if v6:
            l4 = (ICMPv6EchoRequest if e.flags == "req" else ICMPv6EchoReply)(id=0x42, data=os.urandom(max(0, body)))
            return ip / l4
        l4 = ICMP(type=8 if e.flags == "req" else 0, id=0x42) / Raw(os.urandom(max(0, body)))
    elif e.proto == "udp":
        l4 = UDP(sport=e.sport, dport=e.dport) / data if data else UDP(sport=e.sport, dport=e.dport)
    else:
        tcp = TCP(sport=e.sport, dport=e.dport, flags=e.flags, options=[("NOP", None), ("NOP", None),
                                                                         ("Timestamp", (1, 1))])
        l4 = tcp / data if data else tcp
    return ip / l4


def _background(cap: _Capture, duration: float):
    """Cleartext 'normal communication' observed on the same link (DNS, NTP)."""
    rng = cap.rng
    t = rng.uniform(0, 5)
    v6 = cap.cfg.ip_version == 6
    resolver = "2001:4860:4860::8888" if v6 else "8.8.8.8"
    names = ["update.example.com", "mail.example.org", "cdn.example.net", "time.example.com", "api.example.io"]
    while t < duration:
        qn = rng.choice(names)
        sp = rng.randint(30000, 60000)
        qid = rng.randint(0, 65535)
        ip = IPv6(src=cap.gw[0], dst=resolver) if v6 else IP(src=cap.gw[0], dst=resolver)
        cap.emit(t, 0, ip / UDP(sport=sp, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qn)))
        ip = IPv6(src=resolver, dst=cap.gw[0]) if v6 else IP(src=resolver, dst=cap.gw[0])
        cap.emit(t + 0.02, 1, ip / UDP(sport=53, dport=sp) / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qn),
                 an=DNSRR(rrname=qn, rdata="93.184.216.%d" % rng.randint(1, 254))))
        t += rng.uniform(8, 25)


def generate_capture(cfg: VPNConfig, out_path: str) -> dict:
    """Generate one capture file. Returns ground-truth labels + stats."""
    cfg = cfg.normalized()
    rng = random.Random(cfg.seed if cfg.seed is not None else int.from_bytes(os.urandom(4), "big"))
    cap = _Capture(cfg, rng)
    ispi, rspi = os.urandom(8), os.urandom(8)
    t0 = rng.uniform(0.0, 0.5)
    if cfg.ike_version == 2:
        t_data, rtt = _ikev2_init(cap, t0, ispi, rspi)
    else:
        t_data, rtt = _ikev1_init(cap, t0, ispi, rspi)

    events = profiles.generate(cfg.traffic, cfg.duration, rng)
    new_spi = lambda: rng.randint(0xC0000000, 0xCFFFFFFF)  # noqa: E731  (strongSwan-like SPI range)
    sas = [_make_sa(cfg, cap, 0, new_spi()), _make_sa(cfg, cap, 1, new_spi())]
    rekey_times, spis = [], [(sas[0].spi, sas[1].spi)]
    next_rekey = t_data + cfg.child_lifetime * rng.uniform(0.9, 1.0)
    msg_id = 2
    sent_esp: list[tuple[float, int, bytes]] = []
    n_esp = 0
    for e in events:
        t = t_data + e.t
        if t > t_data + cfg.duration:
            break
        while t >= next_rekey:
            if cfg.ike_version == 2:
                _ikev2_rekey(cap, next_rekey, ispi, rspi, msg_id, rtt)
                msg_id += 2
            else:
                _ikev1_quick(cap, next_rekey, ispi, rspi, rtt)
            rekey_times.append(next_rekey)
            sas = [_make_sa(cfg, cap, 0, new_spi()), _make_sa(cfg, cap, 1, new_spi())]
            spis.append((sas[0].spi, sas[1].spi))
            next_rekey += cfg.child_lifetime * rng.uniform(0.9, 1.0)
        inner = _inner(cfg, cap, e)
        outer = sas[e.direction].encrypt(inner)
        pkt_bytes = bytes(Ether(src=cap.mac[e.direction], dst=cap.mac[1 - e.direction]) / outer)
        cap.pkts.append((t, pkt_bytes))
        sent_esp.append((t, e.direction, pkt_bytes))
        n_esp += 1

    n_replay = 0
    if cfg.replay_attack and len(sent_esp) > 20:
        victims = rng.sample(sent_esp[: len(sent_esp) // 2], k=min(12, len(sent_esp) // 4))
        t_attack = sent_esp[-1][0] * rng.uniform(0.6, 0.9)
        for i, (_, d, b) in enumerate(victims):
            cap.pkts.append((t_attack + i * 0.05, b))
            n_replay += 1
    if cfg.background:
        _background(cap, t_data + cfg.duration)

    cap.pkts.sort(key=lambda x: x[0])
    base = 1_790_000_000 + rng.randint(0, 5_000_000)
    with PcapWriter(out_path, linktype=1, sync=False) as w:
        for t, b in cap.pkts:
            p = Ether(b)
            p.time = base + t
            w.write(p)

    labels = asdict(cfg)
    labels.pop("labels", None)
    labels.update(
        rekeys=len(rekey_times), spi_pairs=len(spis), esp_packets=n_esp, replayed_packets=n_replay,
        total_packets=len(cap.pkts), gateway_a=cap.gw[0], gateway_b=cap.gw[1],
    )
    return labels


def validate_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False
