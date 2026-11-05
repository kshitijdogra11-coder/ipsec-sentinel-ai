"""Security assessment engine.

Evaluates each identified tunnel against NIST SP 800-77r1, RFC 8221 (ESP
algorithm requirements), RFC 8247 (IKEv2 algorithm requirements) and the NSA
CNSA suite, producing: category scores, an overall security score / grade,
a risk score, prioritised findings (with likelihood x impact for the threat
matrix, STRIDE and MITRE ATT&CK mapping), compliance checks, metadata
exposure analysis and an overall AI confidence score.
"""
from __future__ import annotations

from .constants import DH_STRENGTH

WEIGHTS = {
    "Cryptographic strength": 22, "Integrity & authentication": 13, "Key exchange": 15,
    "Forward secrecy": 10, "Key lifetime / SA management": 8, "Replay protection": 10,
    "Protocol & configuration compliance": 12, "Metadata exposure": 10,
}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


class _F:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, fid, title, severity, category, evidence, recommendation, likelihood, impact,
            stride="", attack="", refs=""):
        self.items.append(dict(id=fid, title=title, severity=severity, category=category, evidence=evidence,
                               recommendation=recommendation, likelihood=likelihood, impact=impact,
                               stride=stride, mitre_attack=attack, references=refs))


def _v(ident, key, default=None):
    a = ident.get(key) or {}
    return a.get("value", default), a.get("confidence", 0.0)


def _cipher_score(enc: str, family: str | None, key_bits) -> int:
    e = (enc or "").upper()
    if e.startswith("NONE") or e == "NULL":
        return 0
    if "DES" in e and "3DES" not in e:
        return 0
    if "3DES" in e:
        return 30
    if "GCM" in e or "CHACHA" in e:
        return 100 if key_bits in (None, 256) else 95
    if "AES" in e:
        return 90 if key_bits in (None, 256) else 85
    return 50


def _integ_score(txt: str) -> int:
    t = (txt or "").upper()
    if "AEAD" in t or "512" in t or "384" in t:
        return 100
    if "256" in t:
        return 95
    if "MD5" in t and "SHA1" not in t:
        return 20
    if "SHA1" in t or "96" in t:
        return 65
    return 60


def _dh_score(group) -> int:
    s = DH_STRENGTH.get(group or -1)
    if s is None:
        return 60
    if s >= 128:
        return 100
    if s >= 112:
        return 85
    if s >= 96:
        return 45
    if s >= 80:
        return 20
    return 0


def assess_tunnel(t: dict, capture: dict) -> dict:
    ident = t["identification"]
    ike = t["ike"]
    F = _F()
    cat: dict[str, float] = {}
    proto = t["protocol"]
    enc_attr = ident.get("encryption", {})
    enc, enc_conf = enc_attr.get("value", "unknown"), enc_attr.get("confidence", 0)
    fam, kbits = enc_attr.get("family", enc), enc_attr.get("key_bits")
    neg = ike.get("negotiated", {}) if ike.get("present") else {}

    # -------- cryptographic strength
    esp_s = _cipher_score(enc, fam, kbits) if proto != "IKE-only" else 70
    ike_enc = (neg.get("encr") or "")
    ike_s = _cipher_score(ike_enc, ike_enc, neg.get("key_len")) if ike_enc else 70
    cat["Cryptographic strength"] = min(0.6 * esp_s + 0.4 * ike_s, min(esp_s, ike_s) + 25)
    if proto == "AH":
        F.add("IPS-001", "No confidentiality: AH-only protection", "High", "Cryptographic strength",
              "Data plane uses AH (IP protocol 51); payloads are integrity-protected but transmitted in cleartext.",
              "Migrate to ESP with AES-GCM-16 (RFC 8221 MUST). Use AH only where confidentiality is not required.",
              5, 4, "Information disclosure", "T1040 Network Sniffing", "RFC 4302; RFC 8221 §5")
    elif enc == "NULL":
        F.add("IPS-002", "ESP-NULL: traffic is not encrypted", "Critical", "Cryptographic strength",
              "ESP trailer (padding, pad-length, next-header) is readable in cleartext in "
              f"{t['null_probe'].get('ratio', 0) * 100:.0f}% of packets.",
              "Configure an encryption transform: esp=aes256gcm16-ecp384 (strongSwan) or equivalent.",
              5, 5, "Information disclosure", "T1040 Network Sniffing", "RFC 4303 §3.2; RFC 8221 §5")
    elif "3DES" in (enc or "").upper():
        F.add("IPS-003", "Obsolete ESP cipher 3DES (64-bit block)", "High", "Cryptographic strength",
              f"ESP payload arithmetic matches 3DES-CBC (8-byte IV/block), AI confidence {enc_conf:.0%}.",
              "Replace with AES-GCM-16 (128/256). 3DES is vulnerable to Sweet32 birthday attacks and is "
              "deprecated by NIST (SP 800-131A r2) and RFC 8221 (SHOULD NOT).",
              3, 4, "Information disclosure", "T1040 Network Sniffing", "NIST SP 800-131A r2; RFC 8221; CVE-2016-2183")
    if "3DES" in ike_enc or ike_enc == "DES":
        F.add("IPS-004", f"Obsolete IKE SA cipher {ike_enc}", "High", "Cryptographic strength",
              f"IKE SA transform negotiated in cleartext: ENCR={ike_enc}.",
              "Use ENCR_AES_GCM_16 or ENCR_AES_CBC with 256-bit keys for the IKE SA (RFC 8247).",
              3, 4, "Information disclosure", "T1557 Adversary-in-the-Middle", "RFC 8247 §2.1")
    if fam and fam.startswith("AES-CBC") and proto == "ESP" and esp_s >= 85:
        F.add("IPS-005", "ESP uses AES-CBC + HMAC instead of AEAD", "Low", "Cryptographic strength",
              "Encrypt-then-MAC composition detected (16-byte IV, block-aligned ciphertext).",
              "Prefer AES-GCM-16 (RFC 8221 MUST) - better performance and single-pass authenticated encryption.",
              1, 2, "Tampering", "", "RFC 8221 §5")

    # -------- integrity
    integ_txt = ident.get("integrity", {}).get("value", "")
    integ_s = _integ_score(integ_txt)
    prf = (neg.get("prf") or "").upper()
    prf_s = 100 if ("SHA2" in prf or "384" in prf or "512" in prf) else 60 if "SHA1" in prf else 20 if "MD5" in prf else 80
    cat["Integrity & authentication"] = 0.55 * integ_s + 0.45 * prf_s
    if "MD5" in prf:
        F.add("IPS-010", "IKE uses HMAC-MD5 PRF/integrity", "High", "Integrity & authentication",
              f"IKE SA hash/PRF negotiated as {neg.get('prf')}.",
              "Use PRF_HMAC_SHA2_256/384 and AUTH_HMAC_SHA2_256_128 or AEAD (RFC 8247: MD5 MUST NOT).",
              3, 4, "Spoofing", "T1557 Adversary-in-the-Middle", "RFC 8247 §2.2")
    elif "SHA1" in prf:
        F.add("IPS-011", "IKE uses SHA-1 based PRF/integrity", "Medium", "Integrity & authentication",
              f"IKE SA PRF negotiated as {neg.get('prf')}.", "Migrate to SHA-2 (SHA-256 or stronger).",
              2, 3, "Spoofing", "", "RFC 8247 §2.2; NIST SP 800-131A r2")
    if integ_s <= 65 and proto in ("ESP", "AH") and enc != "NULL":
        F.add("IPS-012", "ESP integrity uses a 96-bit legacy HMAC (SHA-1/MD5)", "Medium", "Integrity & authentication",
              f"ICV length inferred as 96 bits ({integ_txt}).",
              "Use AES-GCM (AEAD) or HMAC-SHA2-256-128.", 2, 3, "Tampering", "", "RFC 8221 §6")
    auth_m, _ = _v(ident, "authentication", "")
    if isinstance(auth_m, str) and "PSK" in auth_m:
        F.add("IPS-013", "Pre-shared key authentication", "Low" if ike.get("exchange_mode") != "Aggressive Mode" else "Info",
              "Integrity & authentication", f"Peer authentication method: {auth_m}.",
              "Prefer certificate-based (ECDSA/RSA-PSS) authentication; if PSKs are used they must be high-entropy "
              "(≥ 128 bits) and unique per peer.", 2, 3, "Spoofing", "T1110 Brute Force", "NIST SP 800-77r1 §4.2")

    # -------- key exchange
    dh = (ident.get("key_exchange") or {}).get("group")
    kex_s = _dh_score(dh)
    cat["Key exchange"] = kex_s
    if dh is not None and DH_STRENGTH.get(dh, 128) < 112:
        F.add("IPS-020", f"Weak Diffie-Hellman group {dh}", "Critical" if DH_STRENGTH.get(dh, 0) <= 80 else "High",
              "Key exchange", f"KE payload uses {ident['key_exchange']['value']} "
              f"(~{DH_STRENGTH.get(dh)}-bit security).",
              "Use DH group 19/20/31 (ECP-256/384, Curve25519) or ≥ MODP-3072. Groups 1/2/5 are within reach of "
              "nation-state precomputation (Logjam).", 3, 5, "Information disclosure", "T1040 Network Sniffing",
              "RFC 8247 §2.4; Logjam (CVE-2015-4000)")
    elif dh == 14:
        F.add("IPS-021", "DH group 14 (MODP-2048) offers only 112-bit security", "Low", "Key exchange",
              "Acceptable today, below CNSA/long-term recommendations.", "Move to ECP-384 (group 20) or Curve25519.",
              1, 3, "Information disclosure", "", "NIST SP 800-57 Pt1 r5; CNSA 2.0")

    # -------- forward secrecy
    pfs, pconf = _v(ident, "pfs")
    if pfs is True:
        g = ident["pfs"].get("group") or dh
        cat["Forward secrecy"] = 100 if DH_STRENGTH.get(g or 14, 112) >= 112 else 70
    elif pfs is False:
        cat["Forward secrecy"] = 20
        F.add("IPS-030", "Perfect Forward Secrecy disabled for Child SAs", "High", "Forward secrecy",
              ident["pfs"].get("evidence", "Rekey exchanges carry no KE payload."),
              "Enable PFS (strongSwan: esp=aes256gcm16-ecp384). Without PFS, compromise of the IKE SA keys "
              "exposes all child SA traffic keys.", 2, 5, "Information disclosure", "T1040 Network Sniffing",
              "NIST SP 800-77r1 §3.3; RFC 7296 §1.3")
    else:
        cat["Forward secrecy"] = 60 if ike.get("version") != 1 else 50
        F.add("IPS-031", "PFS could not be determined", "Info", "Forward secrecy",
              ident.get("pfs", {}).get("evidence", "No rekey exchange observed."),
              "Capture across at least one Child SA rekey, or upload the gateway configuration.", 1, 1)

    # -------- lifetimes
    life, lconf = _v(ident, "child_lifetime")
    ike_life = ike.get("ike_lifetime", {}).get("value") if ike.get("present") else None
    ls = 80
    if life is not None:
        ls = 100 if life <= 3600 else 85 if life <= 28800 else 50
    if ike_life:
        if ike_life > 86400:
            ls = min(ls, 40)
            F.add("IPS-040", "Excessive IKE SA lifetime", "Medium", "Key lifetime / SA management",
                  f"IKEv1 LifeDuration attribute = {ike_life} s ({ike_life / 3600:.0f} h).",
                  "Limit IKE SA lifetime to ≤ 24 h (NIST SP 800-77r1 recommends 24 h IKE / 8 h IPsec).",
                  2, 3, "Information disclosure", "", "NIST SP 800-77r1 §4.1")
    cat["Key lifetime / SA management"] = ls
    if life is None:
        F.add("IPS-041", "Child SA lifetime not observable in capture", "Info", "Key lifetime / SA management",
              ident["child_lifetime"].get("evidence", ""), "Longer captures allow SPI rotation analysis.", 1, 1)
    elif life > 28800:
        F.add("IPS-042", "Long Child SA lifetime", "Medium", "Key lifetime / SA management",
              f"SPI rotation interval ≈ {life:.0f} s.", "Rekey Child SAs at ≤ 8 h / volume limits.", 2, 2)

    # -------- replay protection
    rp = t["replay"]
    if rp["duplicates"]:
        cat["Replay protection"] = 35
        F.add("IPS-050", "Replayed ESP/AH packets detected on the wire", "High", "Replay protection",
              f"{rp['duplicates']} packet(s) re-used an already-seen (SPI, sequence number) pair.",
              "Verify anti-replay is enabled (strongSwan replay_window ≥ 32, default 32; use ESN for high-rate "
              "tunnels) and investigate the injection source.", 4, 3, "Tampering / Spoofing",
              "T1557 Adversary-in-the-Middle", "RFC 4303 §3.4.3")
    else:
        cat["Replay protection"] = 100 if proto in ("ESP", "AH") else 70
    if rp.get("reordered", 0) > 50:
        F.add("IPS-051", "Heavy packet reordering", "Low", "Replay protection",
              f"{rp['reordered']} out-of-order sequence numbers", "Size the anti-replay window accordingly.", 2, 1)

    # -------- protocol & configuration compliance
    ps = 100
    if ike.get("version") == 1:
        ps = 55
        F.add("IPS-060", "Legacy IKEv1 in use", "Medium", "Protocol & configuration compliance",
              "ISAKMP version 1.0 headers observed.", "Migrate to IKEv2 (RFC 7296); IKEv1 is deprecated (RFC 9395).",
              2, 3, "Spoofing", "", "RFC 9395; NIST SP 800-77r1")
        if ike.get("exchange_mode") == "Aggressive Mode":
            ps = 10
            F.add("IPS-061", "IKEv1 Aggressive Mode exposes identity and PSK hash", "Critical",
                  "Protocol & configuration compliance",
                  "Aggressive Mode responder HASH_R and identities sent unencrypted: "
                  + ", ".join(i["value"] for i in ike.get("identities", [])[:3]),
                  "Disable Aggressive Mode (strongSwan aggressive=no) and migrate to IKEv2. The captured hash allows "
                  "offline dictionary attacks against the PSK (e.g. psk-crack / hashcat mode 5300).",
                  5, 5, "Spoofing / Information disclosure", "T1110.002 Password Cracking",
                  "CVE-2002-1623; NIST SP 800-77r1 §4.2")
    if not ike.get("present"):
        ps = min(ps, 70)
        F.add("IPS-062", "IKE negotiation not present in capture", "Info", "Protocol & configuration compliance",
              "Only data-plane traffic captured; negotiated parameters are inferred by AI only.",
              "Capture from tunnel establishment for full parameter visibility.", 1, 1)
    cat["Protocol & configuration compliance"] = ps

    # -------- metadata exposure
    exposures = metadata_exposure(t, capture)
    penalty = sum({"High": 30, "Medium": 12, "Low": 4, "Info": 0}[e["level"]] for e in exposures)
    cat["Metadata exposure"] = max(0, 100 - penalty)
    for e in exposures:
        if e["level"] in ("High", "Medium"):
            F.add(e["id"], e["title"], "High" if e["level"] == "High" else "Medium", "Metadata exposure",
                  e["detail"], e["mitigation"], 4 if e["level"] == "High" else 3, 3 if e["level"] == "High" else 2,
                  "Information disclosure", "T1040 Network Sniffing", e.get("ref", ""))

    # -------- aggregate
    score = sum(cat[k] * w for k, w in WEIGHTS.items()) / sum(WEIGHTS.values())
    sevs = [f["severity"] for f in F.items]
    if "Critical" in sevs:
        score = min(score, 40)
    elif sevs.count("High") >= 2:
        score = min(score, 60)
    elif "High" in sevs:
        score = min(score, 72)
    score = round(score, 1)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "F"
    risk = round(100 - score, 1)
    level = "Critical" if risk >= 60 else "High" if risk >= 40 else "Moderate" if risk >= 20 else "Low"
    findings = sorted(F.items, key=lambda f: (SEV_ORDER[f["severity"]], -f["likelihood"] * f["impact"]))
    confs = [a.get("confidence", 0) for k, a in ident.items() if isinstance(a, dict) and a.get("confidence")]
    ai_attrs = {k: a for k, a in ident.items() if isinstance(a, dict) and str(a.get("method", "")).startswith("AI")}
    return {
        "tunnel": t["id"], "score": score, "grade": grade, "risk_score": risk, "risk_level": level,
        "category_scores": {k: round(v, 1) for k, v in cat.items()}, "weights": WEIGHTS,
        "findings": findings, "severity_counts": {s: sevs.count(s) for s in SEV_ORDER},
        "compliance": compliance(t),
        "metadata_exposure": exposures,
        "threat_matrix": threat_matrix(findings),
        "ai_confidence": {
            "overall": round(sum(confs) / len(confs), 3) if confs else 0.0,
            "ai_only": round(sum(a["confidence"] for a in ai_attrs.values()) / len(ai_attrs), 3) if ai_attrs else None,
            "per_attribute": {k: a.get("confidence", 0) for k, a in ident.items() if isinstance(a, dict)},
        },
    }


def metadata_exposure(t: dict, capture: dict) -> list[dict]:
    ident, ike = t["identification"], t["ike"]
    out = []
    mode, _ = _v(ident, "mode")
    out.append({"id": "MX-01", "title": "Tunnel endpoint addresses visible", "level": "Low" if mode == "tunnel" else "Medium",
                "detail": f"Outer IPs {t['initiator']} <-> {t['responder']}"
                + ("" if mode == "tunnel" else " are the real communicating hosts (transport mode exposes endpoints)."),
                "mitigation": "Use tunnel mode between gateways to hide internal host addressing.", "ref": "RFC 4301 §4.1"})
    tt = ident.get("traffic_type", {})
    if tt.get("confidence", 0) >= 0.6:
        out.append({"id": "MX-02", "title": "Application fingerprinting through ESP", "level": "Medium",
                    "detail": f"AI infers '{tt['value']}' traffic inside the tunnel with {tt['confidence']:.0%} "
                              "confidence from packet sizes and timing alone.",
                    "mitigation": "Enable Traffic Flow Confidentiality padding / dummy packets (RFC 4303 §2.4, §2.6) "
                                  "for sensitive links.", "ref": "RFC 4303 §2.7"})
    fam = ident.get("encryption", {}).get("family") or ident.get("encryption", {}).get("value", "")
    if "GCM" in str(fam):
        out.append({"id": "MX-03", "title": "Fine-grained length leakage (AEAD 4-byte padding)", "level": "Low",
                    "detail": "AES-GCM pads only to 4 bytes, so inner packet lengths are visible to ±3 bytes.",
                    "mitigation": "Use TFC padding for high-sensitivity traffic.", "ref": "RFC 4106"})
    if ike.get("identities"):
        ids = ", ".join(f"{i['type']}={i['value']}" for i in ike["identities"][:4])
        out.append({"id": "MX-04", "title": "Peer identities transmitted in cleartext", "level": "High",
                    "detail": f"IKE identities visible to a passive observer: {ids}.",
                    "mitigation": "Use IKEv2 (identities are encrypted in IKE_AUTH).", "ref": "RFC 2409 §5.4"})
    if ike.get("vendor_ids"):
        out.append({"id": "MX-05", "title": "Implementation fingerprinting via Vendor IDs", "level": "Low",
                    "detail": "Vendor ID payloads reveal: " + ", ".join(ike["vendor_ids"]),
                    "mitigation": "Suppress non-essential Vendor ID payloads (strongSwan: send_vendor_id = no).",
                    "ref": "RFC 7296 §3.12"})
    enc = ident.get("encryption", {}).get("value", "")
    if enc == "NULL" or t["protocol"] == "AH":
        out.append({"id": "MX-06", "title": "Payload visible in cleartext", "level": "High",
                    "detail": "Inner packets (headers and data) are readable by any observer.",
                    "mitigation": "Use ESP with encryption.", "ref": "RFC 8221"})
    dns = capture.get("cleartext", {}).get("DNS", 0)
    if dns:
        out.append({"id": "MX-07", "title": "Cleartext DNS outside the tunnel (possible split-tunnel leak)",
                    "level": "Medium",
                    "detail": f"{dns} DNS packets observed unencrypted alongside the VPN.",
                    "mitigation": "Route DNS through the tunnel or use DoT/DoH; review split-tunnel policy.",
                    "ref": "NIST SP 800-77r1 §5"})
    if ident.get("nat_traversal", {}).get("value"):
        out.append({"id": "MX-08", "title": "NAT presence revealed", "level": "Info",
                    "detail": "UDP-encapsulated ESP shows an initiator behind NAT (road-warrior / CGNAT).",
                    "mitigation": "None required.", "ref": "RFC 3948"})
    return out


def compliance(t: dict) -> list[dict]:
    ident, ike = t["identification"], t["ike"]
    neg = ike.get("negotiated", {}) if ike.get("present") else {}
    enc = str(ident.get("encryption", {}).get("value", ""))
    kbits = ident.get("encryption", {}).get("key_bits")
    integ = str(ident.get("integrity", {}).get("value", ""))
    dh = (ident.get("key_exchange") or {}).get("group")
    pfs = ident.get("pfs", {}).get("value")
    prf = str(neg.get("prf") or "")
    ver = ike.get("version")
    mode = ike.get("exchange_mode")

    def st(cond):
        return "unknown" if cond is None else ("pass" if cond else "fail")

    aes = None if enc in ("unknown", "") else ("AES" in enc)
    checks = [
        ("NIST SP 800-77r1", "Use IKEv2", st(None if ver is None else ver == 2), f"IKEv{ver}" if ver else "n/a"),
        ("NIST SP 800-77r1", "No IKEv1 Aggressive Mode", st(None if ver is None else mode != "Aggressive Mode"), mode or "n/a"),
        ("NIST SP 800-77r1", "AES encryption (128/256)", st(aes), enc),
        ("NIST SP 800-77r1", "SHA-2 or AEAD integrity", st(None if not integ or integ == "unknown" else ("AEAD" in integ or "SHA2" in integ)), integ),
        ("NIST SP 800-77r1", "DH ≥ 2048-bit MODP or ECP", st(None if dh is None else DH_STRENGTH.get(dh, 0) >= 112), f"group {dh}"),
        ("NIST SP 800-77r1", "PFS enabled", st(pfs), str(pfs)),
        ("RFC 8221", "ESP: no NULL/DES/3DES encryption", st(None if enc in ("unknown", "") else not any(x in enc for x in ("NULL", "DES", "NONE"))), enc),
        ("RFC 8221", "ESP: no HMAC-MD5", st(None if not integ or integ == "unknown" else "MD5" not in integ or "SHA1" in integ), integ),
        ("RFC 8247", "IKEv2 PRF not MD5/SHA-1", st(None if not prf else not any(x in prf.upper() for x in ("MD5", "SHA1"))), prf or "n/a"),
        ("RFC 8247", "DH group not 1/2/5", st(None if dh is None else dh not in (1, 2, 5)), f"group {dh}"),
        ("CNSA / Suite B", "AES-256", st(None if enc in ("unknown", "") else ("AES" in enc and kbits == 256)), f"{enc}"),
        ("CNSA / Suite B", "ECP-384 or MODP ≥ 3072", st(None if dh is None else dh in (15, 16, 17, 18, 20, 21)), f"group {dh}"),
        ("CNSA / Suite B", "SHA-384 or stronger PRF", st(None if not prf else ("384" in prf or "512" in prf)), prf or "n/a"),
    ]
    return [{"framework": f, "control": c, "status": s, "observed": o} for f, c, s, o in checks]


def threat_matrix(findings: list[dict]) -> dict:
    grid = [[[] for _ in range(5)] for _ in range(5)]  # [impact-1][likelihood-1]
    for f in findings:
        if f["severity"] == "Info":
            continue
        grid[f["impact"] - 1][f["likelihood"] - 1].append(f["id"])
    stride: dict[str, list[str]] = {}
    for f in findings:
        for s in filter(None, (x.strip() for x in f.get("stride", "").split("/"))):
            stride.setdefault(s, []).append(f["id"])
    return {"grid": grid, "stride": stride}


def assess(result: dict) -> dict:
    tunnels = [assess_tunnel(t, result["capture"]) for t in result["tunnels"] if t["protocol"] != "IKE-only"
               or t["ike"].get("present")]
    if not tunnels:
        return {"score": None, "grade": "N/A", "risk_score": None, "risk_level": "Unknown", "tunnels": [],
                "summary": "No IPsec traffic (IKE/ESP/AH) was found in this capture."}
    worst = min(tunnels, key=lambda x: x["score"])
    summary = executive_summary(result, worst)
    return {"score": worst["score"], "grade": worst["grade"], "risk_score": worst["risk_score"],
            "risk_level": worst["risk_level"], "ai_confidence": worst["ai_confidence"]["overall"],
            "tunnels": tunnels, "summary": summary}


def executive_summary(result: dict, a: dict) -> str:
    t = next(x for x in result["tunnels"] if x["id"] == a["tunnel"])
    idn = t["identification"]
    crit = a["severity_counts"]
    enc = idn.get("encryption", {}).get("value", "unknown")
    mode = idn.get("mode", {}).get("value", "unknown")
    ikev = idn.get("ike_version", {}).get("value", "IKE not observed")
    tr = idn.get("traffic_type", {})
    parts = [
        f"The capture '{result['capture']['filename']}' contains {len(result['tunnels'])} IPsec tunnel(s). "
        f"The weakest tunnel ({t['id']}) uses {ikev} with {t['protocol']} in {mode} mode, "
        f"protected by {enc}.",
        f"Overall security score is {a['score']}/100 (grade {a['grade']}), corresponding to a "
        f"{a['risk_level'].lower()} risk (risk score {a['risk_score']}).",
        f"The assessment raised {crit['Critical']} critical, {crit['High']} high, {crit['Medium']} medium and "
        f"{crit['Low']} low severity findings.",
    ]
    if tr.get("value") not in (None, "unknown"):
        parts.append(f"Although payloads are encrypted, the AI engine identified the tunnelled traffic as "
                     f"'{tr['value']}' with {tr['confidence']:.0%} confidence, demonstrating metadata leakage.")
    top = [f for f in a["findings"] if f["severity"] in ("Critical", "High")][:3]
    if top:
        parts.append("Priority actions: " + "; ".join(f"{f['title']} → {f['recommendation'].split('.')[0]}" for f in top) + ".")
    else:
        parts.append("No critical or high-severity weaknesses were identified; configuration aligns with current guidance.")
    return " ".join(parts)
