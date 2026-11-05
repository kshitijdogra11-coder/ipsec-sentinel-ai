"""AI classification engine - loads integrity-verified models and serves predictions."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading

import numpy as np

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "models"))


class ModelIntegrityError(RuntimeError):
    pass


class MLEngine:
    _lock = threading.Lock()
    _instance: "MLEngine | None" = None

    def __init__(self, model_dir: str = MODEL_DIR):
        import joblib  # local import: heavy

        path = os.path.join(model_dir, "ipsec_models.joblib")
        manifest = os.path.join(model_dir, "MANIFEST.sha256")
        if not os.path.exists(path) or not os.path.exists(manifest):
            raise ModelIntegrityError("Model bundle or manifest missing - run `python -m ml.train`.")
        expected = open(manifest).read().split()[0].strip()
        with open(path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        # Constant-time compare; refuse to unpickle anything that was tampered with.
        if not hmac.compare_digest(expected, actual):
            raise ModelIntegrityError("Model bundle SHA-256 mismatch - refusing to load (possible tampering).")
        self.bundle = joblib.load(path)
        self.models = self.bundle["models"]
        self.sha256 = actual
        self.version = self.bundle.get("version", "unknown")
        mpath = os.path.join(model_dir, "metrics.json")
        self.metrics = json.load(open(mpath)) if os.path.exists(mpath) else {}

    @classmethod
    def get(cls) -> "MLEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = MLEngine()
            return cls._instance

    @classmethod
    def reset(cls):
        with cls._lock:
            cls._instance = None

    def _predict(self, key: str, X: np.ndarray) -> list[dict]:
        m = self.models[key]
        proba = m.predict_proba(np.atleast_2d(X))
        out = []
        for row in proba:
            order = np.argsort(row)[::-1]
            out.append({
                "label": str(m.classes_[order[0]]),
                "confidence": round(float(row[order[0]]), 4),
                "distribution": {str(m.classes_[i]): round(float(row[i]), 4) for i in order},
            })
        return out

    def predict_crypto(self, x: np.ndarray) -> dict:
        return {k: self._predict(k, x)[0] for k in ("cipher", "icv", "mode")}

    def predict_traffic(self, windows: list[np.ndarray]) -> tuple[dict, list[dict]]:
        if not windows:
            return {"label": "unknown", "confidence": 0.0, "distribution": {}}, []
        per = self._predict("traffic", np.vstack(windows))
        classes = list(per[0]["distribution"].keys())
        agg = {c: float(np.mean([p["distribution"].get(c, 0) for p in per])) for c in classes}
        best = max(agg, key=agg.get)
        return ({"label": best, "confidence": round(agg[best], 4),
                 "distribution": {k: round(v, 4) for k, v in sorted(agg.items(), key=lambda kv: -kv[1])}}, per)
