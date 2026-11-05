"""Train the AI classification engine.

Models (scikit-learn RandomForest, class-balanced):
  cipher  - ESP encryption family   (AES-CBC | AES-GCM | 3DES | NULL)
  icv     - ESP integrity ICV class  (96 | 128 | 256 | AEAD-128)
  mode    - IPsec mode               (tunnel | transport)
  traffic - application inside ESP   (voip | whatsapp | email | web | icmp | video)

Evaluation uses a *grouped* hold-out split (by capture) so that windows of the
same capture never leak between train and test. Final models are re-fitted on
all data. Artefacts are written with a SHA-256 manifest that the backend
verifies before deserialising (joblib uses pickle - never load unverified).

Usage: python -m ml.train --data ../dataset --out models
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.analyzer.features import CRYPTO_FEATURES, TRAFFIC_FEATURES  # noqa: E402


def fit_eval(X, y, groups, name, feature_names, seed=7):
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    tr, te = next(gss.split(X, y, groups))
    clf = RandomForestClassifier(n_estimators=300, min_samples_leaf=1, class_weight="balanced",
                                 n_jobs=-1, random_state=seed)
    clf.fit(X[tr], y[tr])
    pred = clf.predict(X[te])
    labels = sorted(set(y))
    imp = sorted(zip(feature_names, clf.feature_importances_), key=lambda x: -x[1])[:12]
    metrics = {
        "model": name, "train_samples": int(len(tr)), "test_samples": int(len(te)),
        "accuracy": round(float(accuracy_score(y[te], pred)), 4),
        "macro_f1": round(float(f1_score(y[te], pred, average="macro")), 4),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y[te], pred, labels=labels).tolist(),
        "report": classification_report(y[te], pred, labels=labels, output_dict=True, zero_division=0),
        "top_features": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp],
    }
    print(f"[{name:8s}] acc={metrics['accuracy']:.3f}  macroF1={metrics['macro_f1']:.3f}  "
          f"(train={len(tr)}, test={len(te)})")
    final = RandomForestClassifier(n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=seed)
    final.fit(X, y)
    return final, metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "..", "..", "dataset"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "models"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    c = pd.read_csv(os.path.join(a.data, "crypto_features.csv"), keep_default_na=False)
    t = pd.read_csv(os.path.join(a.data, "traffic_features.csv"), keep_default_na=False)
    Xc, gc = c[CRYPTO_FEATURES].to_numpy(float), c["capture_id"].to_numpy()
    Xt, gt = t[TRAFFIC_FEATURES].to_numpy(float), t["capture_id"].to_numpy()

    models, metrics = {}, {}
    for key, col in (("cipher", "y_cipher"), ("icv", "y_icv"), ("mode", "y_mode")):
        models[key], metrics[key] = fit_eval(Xc, c[col].astype(str).to_numpy(), gc, key, CRYPTO_FEATURES)
    models["traffic"], metrics["traffic"] = fit_eval(Xt, t["y_traffic"].astype(str).to_numpy(), gt, "traffic",
                                                     TRAFFIC_FEATURES)
    bundle = {"models": models, "crypto_features": CRYPTO_FEATURES, "traffic_features": TRAFFIC_FEATURES,
              "version": time.strftime("%Y.%m.%d-%H%M"), "algorithm": "RandomForest(n=300, balanced)"}
    path = os.path.join(a.out, "ipsec_models.joblib")
    joblib.dump(bundle, path, compress=3)
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(os.path.join(a.out, "MANIFEST.sha256"), "w") as f:
        f.write(f"{digest}  ipsec_models.joblib\n")
    meta = {"version": bundle["version"], "algorithm": bundle["algorithm"], "sha256": digest,
            "dataset": {"captures": int(c["capture_id"].nunique()), "traffic_windows": int(len(t))},
            "metrics": metrics}
    with open(os.path.join(a.out, "metrics.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved {path}\n  sha256={digest}")


if __name__ == "__main__":
    main()
