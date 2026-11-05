"""Build the labelled training/testing dataset.

Generates N IPsec captures from the configuration matrix, extracts features
exactly as the live analyzer does, and writes:

  dataset/labels.csv            ground truth per capture (full VPN config)
  dataset/crypto_features.csv   per-capture crypto side-channel features + labels
  dataset/traffic_features.csv  per-30s-window traffic features + app label
  dataset/pcaps/*.pcap          (only with --keep-pcaps)

Usage:  python -m ml.build_dataset --n 600 --workers 8 --out ../dataset
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import sys
import tempfile
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analyzer.capture import parse_capture  # noqa: E402
from app.analyzer.features import CRYPTO_FEATURES, TRAFFIC_FEATURES, crypto_features, ike_icv_prior, traffic_windows  # noqa: E402
from app.testbed.generator import random_config, generate_capture  # noqa: E402


def icv_label(cfg: dict) -> str:
    if cfg["esp_encr"] == "AES-GCM":
        return "AEAD-128"
    return {"HMAC-SHA1-96": "96", "HMAC-MD5-96": "96", "HMAC-SHA2-256-128": "128",
            "HMAC-SHA2-512-256": "256"}.get(cfg["esp_integ"], "none")


def one(args):
    idx, seed, out_dir, keep = args
    rng = random.Random(seed)
    cfg = random_config(rng)
    cfg.seed = seed
    pdir = os.path.join(out_dir, "pcaps") if keep else tempfile.mkdtemp()
    os.makedirs(pdir, exist_ok=True)
    path = os.path.join(pdir, f"cap_{idx:05d}_{cfg.traffic}_{cfg.mode}.pcap")
    labels = generate_capture(cfg, path)
    labels["capture_id"] = idx
    labels["file"] = os.path.basename(path)
    cap = parse_capture(path)
    initiator = cap.ike[0]["src"] if cap.ike else None
    crypto_row, traffic_rows = None, []
    if cap.esp:
        crypto_row = list(crypto_features(cap.esp, cfg.ip_version, ike_icv_prior(cfg.ike_integ, cfg.ike_encr))) + [
            idx, cfg.esp_encr, icv_label(labels), cfg.mode]
        for (w0, w1, f) in traffic_windows(cap.esp, initiator):
            traffic_rows.append(list(f) + [idx, cfg.traffic])
    if not keep:
        os.remove(path)
        os.rmdir(pdir)
    return labels, crypto_row, traffic_rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "dataset"))
    ap.add_argument("--seed", type=int, default=20260930)
    ap.add_argument("--keep-pcaps", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    master = random.Random(a.seed)
    jobs = [(i, master.randint(0, 2**31), a.out, a.keep_pcaps) for i in range(a.n)]
    labels_all, crypto, traffic = [], [], []
    with Pool(a.workers) as pool:
        for k, (lab, c, t) in enumerate(pool.imap_unordered(one, jobs, chunksize=2)):
            labels_all.append(lab)
            if c:
                crypto.append(c)
            traffic.extend(t)
            if (k + 1) % 25 == 0:
                print(f"  {k + 1}/{a.n} captures", flush=True)
    labels_all.sort(key=lambda r: r["capture_id"])
    with open(os.path.join(a.out, "labels.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(labels_all[0].keys()))
        w.writeheader()
        w.writerows(labels_all)
    with open(os.path.join(a.out, "crypto_features.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CRYPTO_FEATURES + ["capture_id", "y_cipher", "y_icv", "y_mode"])
        w.writerows(sorted(crypto, key=lambda r: r[-4]))
    with open(os.path.join(a.out, "traffic_features.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(TRAFFIC_FEATURES + ["capture_id", "y_traffic"])
        w.writerows(sorted(traffic, key=lambda r: r[-2]))
    print(f"Done: {len(labels_all)} captures, {len(crypto)} crypto rows, {len(traffic)} traffic windows -> {a.out}")


if __name__ == "__main__":
    main()
