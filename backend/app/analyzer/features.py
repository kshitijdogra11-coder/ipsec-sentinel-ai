"""Feature engineering for the AI classification engine.

Two families of features are extracted from *encrypted* ESP traffic only
(no decryption, no keys):

1. **Cryptographic side-channel features** (per tunnel) - ESP payload length
   arithmetic reveals IV size, block size and ICV length: e.g. AES-CBC gives
   ``(len - 16 - ICV) % 16 == 0`` while AES-GCM pads to 4 bytes with an 8-byte
   IV. Minimum observed lengths reveal the extra inner IP header of tunnel
   mode. NULL encryption leaves a parseable trailer.
2. **Traffic-shape features** (per 30 s window) - packet size distribution,
   inter-arrival timing, direction asymmetry and burst structure, which
   fingerprint the application inside the tunnel (VoIP, video, web...).
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

CIPHER_HYPOTHESES = [  # (iv, icv, block)
    (16, 12, 16), (16, 16, 16), (16, 32, 16), (8, 16, 4), (8, 12, 8), (8, 16, 8), (0, 12, 4), (0, 16, 4),
]
VALID_NH = {4, 41, 6, 17, 1, 58, 50, 47}


def _null_trailer_ok(tail: bytes, icv: int) -> tuple[bool, int]:
    if len(tail) < icv + 2:
        return False, -1
    nh = tail[-icv - 1]
    padlen = tail[-icv - 2]
    if nh not in VALID_NH or padlen > 15 or len(tail) < icv + 2 + padlen:
        return False, -1
    pad = tail[len(tail) - icv - 2 - padlen:len(tail) - icv - 2]
    return (bytes(range(1, padlen + 1)) == pad), nh


def null_cipher_probe(obs) -> dict:
    """Detect ESP-NULL: trailer (pad 1..n, pad-len, next-header) readable in clear."""
    best = {"ratio": 0.0, "icv": None, "next_headers": {}}
    if not obs:
        return best
    sample = obs[:: max(1, len(obs) // 400)]
    for icv in (12, 16, 32):
        nhs = Counter()
        ok = 0
        for e in sample:
            good, nh = _null_trailer_ok(e.tail, icv)
            if good:
                ok += 1
                nhs[nh] += 1
        r = ok / len(sample)
        if r > best["ratio"]:
            best = {"ratio": r, "icv": icv, "next_headers": dict(nhs)}
    return best


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


CRYPTO_FEATURES = (
    [f"mod16_{i}" for i in range(16)] + [f"mod8_{i}" for i in range(8)]
    + [f"hyp_{iv}_{icv}_{b}" for iv, icv, b in CIPHER_HYPOTHESES]
    + ["null_trailer", "head_ip_like", "head_entropy", "uniq_mod16", "uniq_len_ratio",
       "min_len", "p1_len", "p5_len", "p10_len", "p50_len", "max_len",
       "lt64", "lt80", "lt96", "lt112", "lt128", "lt160", "ip6", "natt", "min_mod_class", "ike_icv"]
)


IKE_ICV = {"HMAC-SHA1-96": 12, "HMAC-MD5-96": 12, "HMAC-SHA2-256-128": 16, "HMAC-SHA2-384-192": 24,
           "HMAC-SHA2-512-256": 32}


def ike_icv_prior(ike_integ: str | None, ike_encr: str | None) -> float:
    """Configuration-consistency prior: ICV length of the (cleartext) IKE SA integrity transform.
    0 = AEAD IKE SA, -1 = no IKE observed."""
    if ike_encr is None and ike_integ is None:
        return -1.0
    if ike_encr and ("GCM" in ike_encr or "CHACHA" in ike_encr):
        return 0.0
    return float(IKE_ICV.get(ike_integ or "", -1))


def crypto_features(obs, ip_version: int = 4, ike_icv: float = -1.0) -> np.ndarray:
    L = np.array([e.esp_len for e in obs], dtype=float)
    n = len(L)
    if n == 0:
        return np.zeros(len(CRYPTO_FEATURES))
    Li = L.astype(int)
    m16 = np.bincount(Li % 16, minlength=16) / n
    m8 = np.bincount(Li % 8, minlength=8) / n
    hyps = []
    for iv, icv, blk in CIPHER_HYPOTHESES:
        body = Li - iv - icv
        hyps.append(float(np.mean((body >= blk) & (body % blk == 0))))
    nt = null_cipher_probe(obs)["ratio"]
    sample = obs[:: max(1, n // 300)]
    head_ip = np.mean([(e.head[:1] == b"\x45") or (len(e.head) > 0 and e.head[0] >> 4 == 6) for e in sample])
    ent = np.mean([_entropy(e.head[:48]) for e in sample])
    p = np.percentile(L, [1, 5, 10, 50])
    mn = L.min()
    small = [float(np.mean(L < x)) for x in (64, 80, 96, 112, 128, 160)]
    natt = float(np.mean([e.natt for e in sample]))
    return np.array(
        list(m16) + list(m8) + hyps
        + [nt, head_ip, ent / 8.0, len(set(Li % 16)) / 16, len(set(Li)) / n,
           mn, p[0], p[1], p[2], p[3], L.max()] + small
        + [1.0 if ip_version == 6 else 0.0, natt, float(int(mn) % 16), ike_icv],
        dtype=float,
    )


TRAFFIC_FEATURES = [
    "n", "pps", "bps", "up_pkt_frac", "up_byte_frac",
    "sz_mean", "sz_std", "sz_min", "sz_p10", "sz_p25", "sz_p50", "sz_p75", "sz_p90", "sz_max",
    "sz_lt128", "sz_128_256", "sz_256_512", "sz_512_1024", "sz_gt1024", "sz_mode_frac", "sz_uniq",
    "up_sz_mean", "dn_sz_mean", "up_sz_p90", "dn_sz_p90", "up_sz_std", "dn_sz_std",
    "iat_mean", "iat_std", "iat_med", "iat_cv", "iat_lt1ms", "iat_1_5ms", "iat_5_15ms", "iat_15_25ms",
    "iat_25_100ms", "iat_100ms_1s", "iat_gt1s", "up_iat_med", "dn_iat_med", "up_iat_20ms", "dn_iat_20ms",
    "bursts_per_min", "burst_pkts_mean", "burst_dur_mean", "burst_bytes_max", "burst_bytes_mean",
    "max_large_run", "active_frac",
]


def traffic_window_features(ts: np.ndarray, dirs: np.ndarray, sizes: np.ndarray, span: float) -> np.ndarray:
    n = len(ts)
    span = max(span, 1e-3)
    up = dirs == 0
    s = sizes.astype(float)
    tot = s.sum() or 1.0
    iat = np.diff(ts) if n > 1 else np.array([0.0])
    iat = np.clip(iat, 0, None)

    def pct(a, q):
        return float(np.percentile(a, q)) if len(a) else 0.0

    def dir_iat(mask):
        t = ts[mask]
        return np.diff(t) if len(t) > 1 else np.array([0.0])

    up_iat, dn_iat = dir_iat(up), dir_iat(~up)
    # bursts: gap > 0.5 s separates bursts
    gaps = np.where(iat > 0.5)[0]
    starts = np.concatenate([[0], gaps + 1])
    ends = np.concatenate([gaps, [n - 1]])
    b_pk = ends - starts + 1
    b_dur = ts[ends] - ts[starts]
    b_bytes = np.array([s[a:b + 1].sum() for a, b in zip(starts, ends)])
    # longest run of large packets
    run = best = 0
    for v in s > 1000:
        run = run + 1 if v else 0
        best = max(best, run)
    mode_frac = Counter(sizes.tolist()).most_common(1)[0][1] / n
    active = np.sum(np.minimum(iat, 1.0)) / span
    f = [
        n, n / span, tot / span, float(up.mean()), float(s[up].sum() / tot),
        s.mean(), s.std(), s.min(), pct(s, 10), pct(s, 25), pct(s, 50), pct(s, 75), pct(s, 90), s.max(),
        float(np.mean(s < 128)), float(np.mean((s >= 128) & (s < 256))), float(np.mean((s >= 256) & (s < 512))),
        float(np.mean((s >= 512) & (s < 1024))), float(np.mean(s >= 1024)), mode_frac, len(set(sizes.tolist())) / n,
        s[up].mean() if up.any() else 0, s[~up].mean() if (~up).any() else 0,
        pct(s[up], 90), pct(s[~up], 90), s[up].std() if up.any() else 0, s[~up].std() if (~up).any() else 0,
        iat.mean(), iat.std(), float(np.median(iat)), iat.std() / (iat.mean() + 1e-9),
        float(np.mean(iat < 0.001)), float(np.mean((iat >= 0.001) & (iat < 0.005))),
        float(np.mean((iat >= 0.005) & (iat < 0.015))), float(np.mean((iat >= 0.015) & (iat < 0.025))),
        float(np.mean((iat >= 0.025) & (iat < 0.1))), float(np.mean((iat >= 0.1) & (iat < 1))), float(np.mean(iat >= 1)),
        float(np.median(up_iat)), float(np.median(dn_iat)),
        float(np.mean((up_iat > 0.017) & (up_iat < 0.023))), float(np.mean((dn_iat > 0.017) & (dn_iat < 0.023))),
        len(starts) / span * 60, b_pk.mean(), b_dur.mean(), b_bytes.max(), b_bytes.mean(),
        best, float(min(1.0, active)),
    ]
    return np.nan_to_num(np.array(f, dtype=float))


def traffic_windows(obs, initiator: str | None, window: float = 30.0, min_pkts: int = 12):
    """Split a tunnel's ESP observations into windows -> (t_start, t_end, features)."""
    if not obs:
        return []
    if initiator is None:
        initiator = obs[0].src
    ts = np.array([e.t for e in obs])
    dirs = np.array([0 if e.src == initiator else 1 for e in obs])
    sizes = np.array([e.esp_len for e in obs])
    out = []
    t0, tend = ts[0], ts[-1]
    w = t0
    while w <= tend:
        m = (ts >= w) & (ts < w + window)
        if m.sum() >= min_pkts:
            span = min(window, max(ts[m][-1] - w, 1.0))
            out.append((float(w), float(min(w + window, tend)), traffic_window_features(ts[m] - w, dirs[m], sizes[m], span)))
        w += window
    if not out and len(ts) >= 4:
        out.append((float(t0), float(tend), traffic_window_features(ts - t0, dirs, sizes, max(tend - t0, 1.0))))
    return out
