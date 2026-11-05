"""End-to-end analysis pipeline: capture -> protocol identification -> AI
inference -> security assessment -> report-ready JSON."""
from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict

import numpy as np

from . import assessment
from .capture import AhObs, Capture, EspObs, parse_capture
from .constants import DH_GROUPS, DH_KE_LEN, IP_PROTO
from .features import crypto_features, ike_icv_prior, null_cipher_probe, traffic_windows
from .ml_engine import MLEngine

RULE_CONF = 0.99  # confidence for attributes read directly from cleartext protocol fields


def _attr(value, confidence: float, method: str, evidence: str = "") -> dict:
    return {"value": value, "confidence": round(float(confidence), 3), "method": method, "evidence": evidence}


def _ike_cipher_overhead(neg: dict) -> tuple[int, int]:
    enc = (neg or {}).get("encr") or ""
    integ = (neg or {}).get("integ") or ""
    if "GCM" in enc or "CHACHA" in enc:
        return 8, 16
    icv = {"HMAC-SHA1-96": 12, "HMAC-MD5-96": 12, "HMAC-SHA2-256-128": 16, "HMAC-SHA2-384-192": 24,
           "HMAC-SHA2-512-256": 32}.get(integ, 16)
    return (8 if "3DES" in enc else 16), icv


def _nearest_group(ke_len: float, prefer: int | None) -> int | None:
    if prefer and abs(DH_KE_LEN.get(prefer, 0) - ke_len) <= 24:
        return prefer
    best = min(DH_KE_LEN.items(), key=lambda kv: abs(kv[1] - ke_len))
    return best[0] if abs(best[1] - ke_len) <= 40 else None


def _tunnels(cap: Capture) -> dict[frozenset, dict]:
    tun: dict[frozenset, dict] = defaultdict(lambda: {"ike": [], "esp": [], "ah": []})
    for m in cap.ike:
        tun[frozenset((m["src"], m["dst"]))]["ike"].append(m)
    for e in cap.esp:
        tun[frozenset((e.src, e.dst))]["esp"].append(e)
    for a in cap.ah:
        tun[frozenset((a.src, a.dst))]["ah"].append(a)
    return tun


def _analyze_ike(msgs: list[dict], t0: float) -> dict:
    if not msgs:
        return {"present": False}
    v = msgs[0]["version"]
    init = next((m for m in msgs if (m.get("initiator") or (v == 1 and m["rspi"] == "0" * 16))), msgs[0])
    initiator = init["src"]
    out = {"present": True, "version": v, "initiator": initiator,
           "responder": init["dst"], "ike_spi_i": init["ispi"], "messages": len(msgs)}
    exch = Counter(m["exchange"] for m in msgs)
    out["exchanges"] = dict(exch)
    if v == 2:
        out["exchange_mode"] = "IKEv2"
    else:
        out["exchange_mode"] = "Aggressive Mode" if exch.get("Aggressive Mode") else "Main Mode"
    # negotiated (responder's chosen) proposal
    sa_msgs = [m for m in msgs if m["proposals"]]
    offered = sa_msgs[0]["proposals"] if sa_msgs else []
    chosen_msg = next((m for m in sa_msgs if m["src"] != initiator), None)
    chosen = (chosen_msg["proposals"][0] if chosen_msg and chosen_msg["proposals"] else
              (offered[0] if offered else {}))
    ke_msg = next((m for m in msgs if m.get("ke_group")), None)
    neg = dict(chosen)
    if v == 1:
        neg["prf"] = chosen.get("hash")
        neg["integ"] = {"MD5": "HMAC-MD5-96", "SHA1": "HMAC-SHA1-96", "SHA2-256": "HMAC-SHA2-256-128",
                        "SHA2-512": "HMAC-SHA2-512-256"}.get(chosen.get("hash"))
    dh_id = (ke_msg or {}).get("ke_group") or chosen.get("dh_id")
    neg["dh_id"] = dh_id
    neg["dh"] = DH_GROUPS.get(dh_id, chosen.get("dh"))
    out["negotiated"] = neg
    out["offered_proposals"] = offered
    out["vendor_ids"] = sorted({vid for m in msgs for vid in m["vendor_ids"]})
    out["identities"] = [dict(i, src=m["src"]) for m in msgs if not m["encrypted"] for i in m["identities"]]
    out["hash_cleartext"] = any(m["hash_cleartext"] for m in msgs if m["exchange"] == "Aggressive Mode")
    out["notifies"] = sorted({n for m in msgs for n in m["notifies"]})
    out["nat_t"] = any(m["natt"] for m in msgs)
    out["fragmentation"] = "IKEV2_FRAGMENTATION_SUPPORTED" in out["notifies"]
    # auth method
    if v == 1 and chosen.get("auth"):
        out["auth_method"] = _attr(chosen["auth"], RULE_CONF, "IKEv1 SA attribute (cleartext)")
    elif v == 2:
        auth = [m for m in msgs if m["exchange"] == "IKE_AUTH" and m["sk_len"]]
        if auth:
            mx = max(m["sk_len"] for m in auth)
            certish = mx > 900
            out["auth_method"] = _attr("Certificate (RSA/ECDSA)" if certish else "PSK / EAP", 0.82 if certish else 0.74,
                                       "IKE_AUTH encrypted-length heuristic", f"largest IKE_AUTH SK payload {mx} B")
        else:
            out["auth_method"] = _attr("unknown", 0.0, "no IKE_AUTH observed")
    # lifetime
    if v == 1 and chosen.get("life_duration"):
        out["ike_lifetime"] = _attr(chosen["life_duration"], RULE_CONF, "IKEv1 SA LifeDuration attribute")
    else:
        out["ike_lifetime"] = _attr(None, 0.0, "not negotiated on the wire in IKEv2")
    # PFS from rekey exchange sizes
    iv, icv = _ike_cipher_overhead(neg)
    if v == 2:
        rk = [m for m in msgs if m["exchange"] == "CREATE_CHILD_SA" and m["src"] == initiator and m["sk_len"]]
        if rk:
            plain = statistics.median(m["sk_len"] - iv - icv for m in rk)
            pfs = plain > 180
            grp = _nearest_group(plain - 153 - 8, dh_id) if pfs else None
            out["pfs"] = _attr(pfs, 0.93 if abs(plain - 180) > 20 else 0.7, "CREATE_CHILD_SA length analysis",
                               f"{len(rk)} rekey request(s), est. plaintext {plain:.0f} B "
                               f"({'KE payload present' if pfs else 'no KE payload'})")
            out["pfs_group"] = grp
        else:
            out["pfs"] = _attr(None, 0.0, "no CREATE_CHILD_SA observed", "capture too short to observe a rekey")
    else:
        qm = [m for m in msgs if m["exchange"] == "Quick Mode" and m["src"] == initiator and m["sk_len"]]
        first_qm = [m for m in qm if m["sk_len"] > 60]
        if first_qm:
            plain = statistics.median(m["sk_len"] for m in first_qm)
            pfs = plain > 175
            out["pfs"] = _attr(pfs, 0.9, "Quick Mode length analysis",
                               f"Quick Mode message 1 body {plain:.0f} B ({'KE present' if pfs else 'no KE'})")
            out["pfs_group"] = _nearest_group(plain - 148, dh_id) if pfs else None
        else:
            out["pfs"] = _attr(None, 0.0, "no Quick Mode observed")
    out["timeline"] = [
        {"t": round(m["t"] - t0, 4), "exchange": m["exchange"], "from": m["src"], "to": m["dst"],
         "dir": "I→R" if m["src"] == initiator else "R→I", "length": m["length"],
         "encrypted": bool(m["sk_len"]), "payloads": m["payloads"][:12], "natt": m["natt"]}
        for m in msgs[:400]
    ]
    out["rekey_times"] = [round(m["t"] - t0, 3) for m in msgs
                          if m["src"] == initiator and m["exchange"] in ("CREATE_CHILD_SA",)] + \
        [round(m["t"] - t0, 3) for m in msgs if m["src"] == initiator and m["exchange"] == "Quick Mode"
         and m["sk_len"] and m["sk_len"] > 60][1:]
    return out


def _sa_table(obs: list, t0: float) -> tuple[list[dict], dict]:
    by: dict[tuple, list] = defaultdict(list)
    for e in obs:
        by[(e.src, e.dst, e.spi)].append(e)
    rows = []
    dup_total, reorder_total = 0, 0
    for (src, dst, spi), lst in sorted(by.items(), key=lambda kv: kv[1][0].t):
        seqs = [e.seq for e in lst]
        seen, dups, reorder, gaps = set(), 0, 0, 0
        hi = 0
        for s in seqs:
            if s in seen:
                dups += 1
            elif s < hi:
                reorder += 1
            seen.add(s)
            hi = max(hi, s)
        uniq = sorted(seen)
        if uniq:
            gaps = (uniq[-1] - uniq[0] + 1) - len(uniq)
        dup_total += dups
        reorder_total += reorder
        size = sum(getattr(e, "ip_len", 0) for e in lst)
        rows.append({"spi": f"0x{spi:08x}", "src": src, "dst": dst, "first_seen": round(lst[0].t - t0, 3),
                     "last_seen": round(lst[-1].t - t0, 3), "packets": len(lst), "bytes": size,
                     "seq_first": seqs[0], "seq_last": max(seqs), "duplicates": dups, "reordered": reorder,
                     "gaps": gaps})
    return rows, {"duplicates": dup_total, "reordered": reorder_total}


def _child_lifetime(sa_rows: list[dict], duration: float) -> dict:
    per_dir: dict[tuple, list[float]] = defaultdict(list)
    for r in sa_rows:
        per_dir[(r["src"], r["dst"])].append(r["first_seen"])
    intervals = []
    for firsts in per_dir.values():
        firsts.sort()
        intervals += [b - a for a, b in zip(firsts, firsts[1:]) if b - a > 1.0]
    if intervals:
        est = statistics.median(intervals)
        return _attr(round(est, 1), 0.9 if len(intervals) > 1 else 0.75, "SPI rotation interval",
                     f"{len(intervals)} SPI rotation(s) observed; median interval {est:.1f}s")
    return _attr(None, 0.5, "no SPI rotation observed", f"lifetime ≥ {duration:.0f}s (capture duration)")


def _series(obs: list, t0: float, initiator: str | None, buckets: int = 120) -> dict:
    if not obs:
        return {"t": [], "up": [], "down": []}
    ts = np.array([e.t - t0 for e in obs])
    span = max(ts.max(), 1.0)
    step = max(1.0, span / buckets)
    idx = (ts // step).astype(int)
    n = idx.max() + 1
    up = np.zeros(n)
    dn = np.zeros(n)
    for i, e in zip(idx, obs):
        size = e.ip_len
        if e.src == initiator:
            up[i] += size
        else:
            dn[i] += size
    return {"step": step, "t": [round(i * step, 1) for i in range(n)],
            "up": (up / step).round(1).tolist(), "down": (dn / step).round(1).tolist()}


def _size_hist(obs: list) -> list[dict]:
    edges = [0, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1280, 1400, 1600]
    sizes = np.array([e.ip_len for e in obs]) if obs else np.array([])
    h, _ = np.histogram(sizes, bins=edges)
    return [{"bin": f"{edges[i]}-{edges[i + 1]}", "count": int(h[i])} for i in range(len(h))]


def _ah_as_esp(ah: list[AhObs]) -> list[EspObs]:
    return [EspObs(a.t, a.src, a.dst, a.spi, a.seq, a.ip_len, a.ip_len, False, b"", b"") for a in ah]


def analyze_tunnel(peers: frozenset, data: dict, cap: Capture, engine: MLEngine | None) -> dict:
    t0 = cap.first_ts
    ike = _analyze_ike(data["ike"], t0)
    esp, ah = data["esp"], data["ah"]
    initiator = ike.get("initiator") or (esp[0].src if esp else (ah[0].src if ah else sorted(peers)[0]))
    responder = next((p for p in peers if p != initiator), initiator)
    ipver = 6 if ":" in initiator else 4
    proto = "ESP" if esp else ("AH" if ah else "IKE-only")
    ident: dict = {"ipsec_protocol": _attr(proto, RULE_CONF if proto != "IKE-only" else 0.6, "IP protocol number",
                                           f"{len(esp)} ESP / {len(ah)} AH packets")}
    ident["ike_version"] = (_attr(f"IKEv{ike['version']}", RULE_CONF, "ISAKMP header version field")
                            if ike["present"] else _attr("not observed", 0.0, "no IKE in capture"))
    ident["ip_version"] = _attr(f"IPv{ipver}", RULE_CONF, "outer IP header")
    ident["nat_traversal"] = _attr(bool(ike.get("nat_t") or any(e.natt for e in esp[:50])), RULE_CONF,
                                   "UDP/4500 encapsulation (RFC 3948)")
    ml: dict = {}
    null_probe = null_cipher_probe(esp) if esp else {"ratio": 0}
    neg0 = ike.get("negotiated", {}) if ike["present"] else {}
    if esp and engine:
        prior = ike_icv_prior(neg0.get("integ"), neg0.get("encr")) if ike["present"] else -1.0
        x = crypto_features(esp, ipver, prior)
        ml = engine.predict_crypto(x)
    # ---- mode
    if ah:
        nh = Counter(a.next_header for a in ah).most_common(1)[0][0]
        ident["mode"] = _attr("tunnel" if nh in (4, 41) else "transport", RULE_CONF, "AH Next Header field",
                              f"next header = {IP_PROTO.get(nh, nh)}")
    elif null_probe["ratio"] > 0.9:
        nh = max(null_probe["next_headers"], key=null_probe["next_headers"].get)
        ident["mode"] = _attr("tunnel" if nh in (4, 41) else "transport", RULE_CONF,
                              "ESP trailer Next Header (NULL encryption)", f"next header = {IP_PROTO.get(nh, nh)}")
    elif ml:
        ident["mode"] = _attr(ml["mode"]["label"], ml["mode"]["confidence"], "AI: ESP length side-channel",
                              "min/percentile ciphertext lengths vs. inner-header overhead")
    else:
        ident["mode"] = _attr("unknown", 0.0, "no data-plane traffic")
    # ---- encryption
    neg = ike.get("negotiated", {}) if ike["present"] else {}
    if proto == "AH":
        ident["encryption"] = _attr("NONE (AH provides no confidentiality)", RULE_CONF, "AH protocol")
        ident["integrity"] = _attr({12: "HMAC-96 (SHA1/MD5)", 16: "HMAC-SHA2-256-128", 24: "HMAC-SHA2-384-192",
                                    32: "HMAC-SHA2-512-256"}.get(ah[0].icv_len, f"{ah[0].icv_len * 8}-bit ICV"),
                                   RULE_CONF, "AH ICV length", f"ICV = {ah[0].icv_len} bytes")
    elif null_probe["ratio"] > 0.9:
        ident["encryption"] = _attr("NULL", RULE_CONF, "ESP trailer readable in cleartext",
                                    f"{null_probe['ratio'] * 100:.0f}% packets expose padding/next-header")
        icv = null_probe["icv"]
        ident["integrity"] = _attr({12: "HMAC-96 (SHA1/MD5)", 16: "HMAC-SHA2-256-128", 32: "HMAC-SHA2-512-256"}
                                   .get(icv, "?"), 0.9, "ESP trailer offset", f"ICV = {icv} bytes")
    elif ml:
        fam = ml["cipher"]["label"]
        key_bits, kconf, kev = None, 0.0, "key length is not observable on the wire"
        if neg.get("encr") and fam.split("-")[0] in (neg.get("encr") or "") and neg.get("key_len"):
            key_bits, kconf = neg["key_len"], 0.6
            kev = "assumed equal to IKE SA key length (Child SA proposal is encrypted inside IKE_AUTH)"
        elif fam == "3DES":
            key_bits, kconf = 168, 0.95
        label = f"{fam}-{key_bits}" if key_bits and fam.startswith("AES") else fam
        ident["encryption"] = _attr(label, ml["cipher"]["confidence"] * (1 if not key_bits or kconf > .9 else 0.9),
                                    "AI: IV/block-size length arithmetic", kev)
        ident["encryption"]["family"] = fam
        ident["encryption"]["key_bits"] = key_bits
        ident["encryption"]["distribution"] = ml["cipher"]["distribution"]
        icv = ml["icv"]["label"]
        ident["integrity"] = _attr({"AEAD-128": "AEAD (GCM 128-bit ICV)", "96": "HMAC-SHA1-96 / MD5-96",
                                    "128": "HMAC-SHA2-256-128", "256": "HMAC-SHA2-512-256"}.get(icv, icv),
                                   ml["icv"]["confidence"], "AI: ICV length inference")
        ident["integrity"]["icv_class"] = icv
        ident["integrity"]["distribution"] = ml["icv"]["distribution"]
        if ml.get("mode"):
            ident["mode"]["distribution"] = ml["mode"]["distribution"]
    else:
        ident["encryption"] = _attr("unknown", 0.0, "no ESP traffic")
        ident["integrity"] = _attr("unknown", 0.0, "no ESP traffic")
    # ---- IKE derived
    if ike["present"]:
        dh = neg.get("dh_id")
        ident["key_exchange"] = _attr(f"DH group {dh} ({DH_GROUPS.get(dh, '?')})" if dh else "unknown",
                                      RULE_CONF if dh else 0.0, "KE payload / SA transform (cleartext)")
        ident["key_exchange"]["group"] = dh
        kl = f"-{neg['key_len']}" if neg.get("key_len") else ""
        ident["ike_encryption"] = _attr(f"{neg.get('encr', '?')}{kl}", RULE_CONF, "IKE SA transform (cleartext)")
        ident["ike_integrity"] = _attr(f"PRF {neg.get('prf') or '-'} / INTEG {neg.get('integ') or 'AEAD'}", RULE_CONF,
                                       "IKE SA transform (cleartext)")
        ident["exchange_mode"] = _attr(ike["exchange_mode"], RULE_CONF, "ISAKMP exchange type")
        ident["authentication"] = ike["auth_method"]
        ident["pfs"] = ike["pfs"]
        if ike.get("pfs_group"):
            ident["pfs"]["group"] = ike["pfs_group"]
    # ---- SAs
    sa_rows, replay = _sa_table(esp or _ah_as_esp(ah), t0)
    duration = cap.duration
    ident["child_lifetime"] = _child_lifetime(sa_rows, duration)
    ident["security_associations"] = _attr(f"{len(sa_rows)} SA(s), {max(1, len(sa_rows) // 2)} pair(s)", RULE_CONF,
                                           "SPI enumeration")
    # ---- traffic
    data_obs = esp or _ah_as_esp(ah)
    windows = traffic_windows(data_obs, initiator)
    traffic_pred, per = ({"label": "unknown", "confidence": 0.0, "distribution": {}}, [])
    if engine and windows:
        traffic_pred, per = engine.predict_traffic([w[2] for w in windows])
    ident["traffic_type"] = _attr(traffic_pred["label"], traffic_pred["confidence"],
                                  "AI: encrypted traffic fingerprinting", f"{len(windows)} × 30 s windows")
    ident["traffic_type"]["distribution"] = traffic_pred["distribution"]
    timeline = [{"t0": round(w[0] - t0, 1), "t1": round(w[1] - t0, 1), "label": p["label"],
                 "confidence": p["confidence"]} for w, p in zip(windows, per)]
    total_bytes = sum(e.ip_len for e in data_obs)
    return {
        "id": f"{initiator} <-> {responder}",
        "initiator": initiator, "responder": responder, "protocol": proto,
        "identification": ident, "ike": ike, "sas": sa_rows,
        "replay": {**replay, "verdict": "replayed packets detected" if replay["duplicates"] else "no replay observed"},
        "traffic": {"prediction": traffic_pred, "timeline": timeline},
        "stats": {"packets": len(data_obs), "bytes": total_bytes,
                  "avg_packet": round(total_bytes / len(data_obs), 1) if data_obs else 0,
                  "throughput_bps": round(total_bytes * 8 / max(duration, 1e-3), 1),
                  "series": _series(data_obs, t0, initiator), "size_histogram": _size_hist(data_obs)},
        "null_probe": null_probe,
    }


def analyze_file(path: str, filename: str | None = None, max_packets: int = 2_000_000) -> dict:
    started = time.time()
    cap = parse_capture(path, max_packets=max_packets)
    try:
        engine = MLEngine.get()
        model_info = {"version": engine.version, "sha256": engine.sha256, "status": "verified"}
    except Exception as exc:  # noqa: BLE001
        engine, model_info = None, {"status": f"unavailable: {exc}"}
    tunnels = []
    for peers, data in sorted(_tunnels(cap).items(), key=lambda kv: -(len(kv[1]["esp"]) + len(kv[1]["ah"]) + len(kv[1]["ike"]))):
        tunnels.append(analyze_tunnel(peers, data, cap, engine))
    breakdown = {"IKE": len(cap.ike), "ESP": len(cap.esp), "AH": len(cap.ah), "NAT-T keepalive": cap.natt_keepalives}
    breakdown.update({f"Cleartext: {k}": v for k, v in cap.cleartext.most_common(8)})
    result = {
        "capture": {
            "filename": filename or path.rsplit("/", 1)[-1], "sha256": cap.sha256, "size_bytes": cap.size_bytes,
            "packets": cap.total_packets, "malformed": cap.malformed, "duration_s": round(cap.duration, 2),
            "start": cap.first_ts, "end": cap.last_ts,
            "ip_versions": {f"IPv{k}": v for k, v in cap.ip_versions.items()},
            "cleartext": dict(cap.cleartext), "cleartext_bytes": cap.cleartext_bytes,
        },
        "protocol_breakdown": breakdown,
        "tunnels": tunnels,
        "model": model_info,
    }
    result["assessment"] = assessment.assess(result)
    result["processing_ms"] = int((time.time() - started) * 1000)
    return result
