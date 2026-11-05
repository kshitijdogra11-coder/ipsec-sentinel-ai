from __future__ import annotations

import csv
import os
from collections import Counter

from fastapi import APIRouter, Depends

from ..analyzer.ml_engine import MLEngine
from ..core.config import BASE_DIR
from ..core.database import User
from ..core.security import get_current_user

router = APIRouter(tags=["system"])
DATASET_DIR = os.environ.get("DATASET_DIR", os.path.join(BASE_DIR, "..", "dataset"))


@router.get("/health")
def health():
    try:
        e = MLEngine.get()
        model = {"status": "verified", "version": e.version}
    except Exception as exc:  # noqa: BLE001
        model = {"status": "unavailable", "error": str(exc)[:200]}
    return {"status": "ok", "model": model}


@router.get("/model")
def model_info(_: User = Depends(get_current_user)):
    try:
        e = MLEngine.get()
        return {"status": "verified", "sha256": e.sha256, **e.metrics}
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "error": str(exc)[:200]}


@router.get("/dataset")
def dataset_summary(_: User = Depends(get_current_user)):
    path = os.path.join(DATASET_DIR, "labels.csv")
    if not os.path.exists(path):
        return {"available": False}
    rows = list(csv.DictReader(open(path)))
    keys = ["traffic", "mode", "esp_encr", "esp_integ", "ike_version", "ikev1_mode", "dh_group", "pfs", "ip_version",
            "nat_t", "protocol", "replay_attack", "esp_key_bits"]
    samples = sorted(os.listdir(os.path.join(DATASET_DIR, "samples"))) if os.path.isdir(os.path.join(DATASET_DIR, "samples")) else []
    return {"available": True, "captures": len(rows),
            "total_packets": sum(int(r["total_packets"]) for r in rows),
            "esp_packets": sum(int(r["esp_packets"]) for r in rows),
            "distributions": {k: dict(Counter(r[k] for r in rows)) for k in keys},
            "sample_files": [s for s in samples if s.endswith((".pcap", ".pcapng"))]}
