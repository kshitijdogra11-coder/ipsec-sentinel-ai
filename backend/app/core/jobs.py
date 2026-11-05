"""Evidence ingestion and background analysis execution."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

from ..analyzer.pcap_reader import CaptureFormatError, sniff_format
from ..analyzer.pipeline import analyze_file
from .audit import audit
from .config import settings
from .database import Analysis, SessionLocal, utcnow
from .security import decrypt_file, encrypt_file, secure_delete

log = logging.getLogger("sentinel.jobs")
executor = ThreadPoolExecutor(max_workers=settings.analysis_workers, thread_name_prefix="analysis")


def tmp_path(suffix: str = ".bin") -> str:
    return os.path.join(settings.data_dir, "tmp", uuid.uuid4().hex + suffix)


def ingest_file(plain_path: str, analysis_id: str) -> tuple[str, str, int, bool]:
    """Validate + hash + (optionally) encrypt evidence. Returns (storage_path, sha256, size, encrypted)."""
    with open(plain_path, "rb") as f:
        head = f.read(4)
    try:
        sniff_format(head)
    except CaptureFormatError:
        raise
    h = hashlib.sha256()
    size = 0
    with open(plain_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    dst = os.path.join(settings.data_dir, "evidence", analysis_id + (".enc" if settings.encrypt_evidence else ".pcap"))
    if settings.encrypt_evidence:
        encrypt_file(plain_path, dst, analysis_id.encode())
        secure_delete(plain_path)
    else:
        os.replace(plain_path, dst)
        os.chmod(dst, 0o600)
    return dst, h.hexdigest(), size, settings.encrypt_evidence


def materialize(a: Analysis) -> str:
    """Return a plaintext temp copy of the evidence (caller must secure_delete it)."""
    out = tmp_path(".pcap")
    if a.encrypted:
        decrypt_file(a.storage_path, out, a.id.encode())
    else:
        with open(a.storage_path, "rb") as fi, open(out, "wb") as fo:
            fo.write(fi.read())
    return out


def _summarize(a: Analysis, result: dict):
    asmt = result["assessment"]
    a.score = asmt.get("score")
    a.grade = asmt.get("grade", "")
    a.risk_level = asmt.get("risk_level", "")
    a.ai_confidence = asmt.get("ai_confidence")
    if result["tunnels"]:
        t = result["tunnels"][0]
        idn = t["identification"]
        a.protocol = t["protocol"]
        a.ike_version = str(idn.get("ike_version", {}).get("value", ""))[:16]
        a.mode = str(idn.get("mode", {}).get("value", ""))[:16]
        a.encryption = str(idn.get("encryption", {}).get("value", ""))[:64]
        a.traffic = str(idn.get("traffic_type", {}).get("value", ""))[:32]
    crit = high = 0
    for t in asmt.get("tunnels", []):
        crit += t["severity_counts"]["Critical"]
        high += t["severity_counts"]["High"]
    a.findings_critical, a.findings_high = crit, high


def run_analysis(analysis_id: str):
    db = SessionLocal()
    plain = None
    try:
        a = db.get(Analysis, analysis_id)
        if not a:
            return
        a.status = "running"
        db.commit()
        plain = materialize(a)
        if hashlib.sha256(open(plain, "rb").read()).hexdigest() != a.sha256:
            raise ValueError("Evidence integrity check failed (SHA-256 mismatch)")
        result = analyze_file(plain, a.filename, max_packets=settings.max_packets)
        blob = json.dumps(result, default=str, separators=(",", ":"))
        a.result_json = blob
        a.result_sha256 = hashlib.sha256(blob.encode()).hexdigest()
        _summarize(a, result)
        a.status = "done"
        a.finished_at = utcnow()
        db.commit()
        audit(db, "analysis.completed", username=a.owner_name, target=a.id,
              detail={"score": a.score, "grade": a.grade, "ms": result.get("processing_ms")})
    except Exception as exc:  # noqa: BLE001
        log.exception("analysis %s failed", analysis_id)
        db.rollback()
        a = db.get(Analysis, analysis_id)
        if a:
            a.status = "failed"
            a.error = f"{type(exc).__name__}: {str(exc)[:300]}"
            a.finished_at = utcnow()
            db.commit()
            audit(db, "analysis.failed", username=a.owner_name, target=a.id, outcome="failure", detail=a.error)
    finally:
        if plain:
            secure_delete(plain)
        db.close()


def submit(analysis_id: str):
    executor.submit(run_analysis, analysis_id)
