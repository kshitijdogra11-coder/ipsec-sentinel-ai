from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..analyzer.pcap_reader import CaptureFormatError
from ..core import jobs
from ..core.audit import audit
from ..core.config import settings
from ..core.database import Analysis, User, get_db
from ..core.security import get_current_user, require_role, secure_delete, sign, verify_signature
from ..reports.pdf_report import build_report
from ..testbed import generator

router = APIRouter(tags=["analyses"])
analyst = require_role("analyst")
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")


def _safe_name(name: str) -> str:
    base = os.path.basename(name or "capture.pcap")
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:120]
    return base or "capture.pcap"


def _get(db: Session, aid: str) -> Analysis:
    if not UUID_RE.match(aid):
        raise HTTPException(status_code=404, detail="Not found")
    a = db.get(Analysis, aid)
    if not a:
        raise HTTPException(status_code=404, detail="Not found")
    return a


def _row(a: Analysis) -> dict:
    return {"id": a.id, "filename": a.filename, "sha256": a.sha256, "size_bytes": a.size_bytes, "source": a.source,
            "status": a.status, "error": a.error, "owner": a.owner_name, "created_at": a.created_at.isoformat(),
            "finished_at": a.finished_at.isoformat() if a.finished_at else None, "score": a.score, "grade": a.grade,
            "risk_level": a.risk_level, "ike_version": a.ike_version, "protocol": a.protocol, "mode": a.mode,
            "encryption": a.encryption, "traffic": a.traffic, "ai_confidence": a.ai_confidence,
            "findings_critical": a.findings_critical, "findings_high": a.findings_high,
            "encrypted_at_rest": a.encrypted}


@router.post("/analyses", status_code=202)
async def upload(request: Request, file: UploadFile = File(...), user: User = Depends(analyst),
                 db: Session = Depends(get_db)):
    limit = settings.max_upload_mb * 1024 * 1024
    tmp = jobs.tmp_path(".upload")
    size = 0
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB limit")
                out.write(chunk)
        if size < 24:
            raise HTTPException(status_code=400, detail="File too small to be a capture")
        aid = str(uuid.uuid4())
        try:
            path, sha, size, enc = jobs.ingest_file(tmp, aid)
        except CaptureFormatError as e:
            audit(db, "analysis.upload", request=request, target=_safe_name(file.filename), outcome="failure", detail=str(e))
            raise HTTPException(status_code=415, detail="Unsupported file: only pcap / pcapng captures are accepted") from None
    finally:
        if os.path.exists(tmp):
            secure_delete(tmp)
    a = Analysis(id=aid, owner_id=user.id, owner_name=user.username, filename=_safe_name(file.filename), sha256=sha,
                 size_bytes=size, storage_path=path, encrypted=enc, source="upload")
    db.add(a)
    db.commit()
    audit(db, "analysis.upload", request=request, target=aid, detail={"file": a.filename, "sha256": sha, "size": size})
    jobs.submit(aid)
    return _row(a)


class TestbedIn(BaseModel):
    preset: Literal[tuple(generator.PRESETS.keys())] = "enterprise-default"  # type: ignore[valid-type]
    traffic: Literal["voip", "whatsapp", "email", "web", "icmp", "video"] = "web"
    ip_version: Literal[4, 6] | None = None
    mode: Literal["tunnel", "transport"] | None = None
    nat_t: bool | None = None
    pfs: bool | None = None
    replay_attack: bool = False
    duration: float = Field(default=120, ge=20, le=600)


@router.get("/testbed/presets")
def presets(_: User = Depends(get_current_user)):
    out = []
    for name, p in generator.PRESETS.items():
        c = generator.preset(name)
        out.append({"name": name, "ike_version": c.ike_version, "ikev1_mode": c.ikev1_mode,
                    "ike": f"{c.ike_encr}-{c.ike_key_bits}/{c.ike_prf}/DH{c.dh_group}", "protocol": c.protocol,
                    "mode": c.mode, "esp": f"{c.esp_encr}{'-' + str(c.esp_key_bits) if c.esp_key_bits else ''}"
                    f"/{c.esp_integ}", "pfs": c.pfs, "ip_version": c.ip_version, "nat_t": c.nat_t,
                    "child_lifetime": c.child_lifetime, "auth": c.auth_method})
    return out


@router.post("/testbed/generate", status_code=202)
def testbed_generate(body: TestbedIn, request: Request, user: User = Depends(analyst), db: Session = Depends(get_db)):
    overrides = {k: v for k, v in body.model_dump().items() if v is not None and k not in ("preset",)}
    cfg = generator.preset(body.preset, **overrides)
    tmp = jobs.tmp_path(".pcap")
    try:
        truth = generator.generate_capture(cfg, tmp)
        aid = str(uuid.uuid4())
        path, sha, size, enc = jobs.ingest_file(tmp, aid)
    finally:
        if os.path.exists(tmp):
            secure_delete(tmp)
    name = f"testbed_{body.preset}_{cfg.traffic}_{cfg.mode}_ipv{cfg.ip_version}.pcap"
    a = Analysis(id=aid, owner_id=user.id, owner_name=user.username, filename=name, sha256=sha, size_bytes=size,
                 storage_path=path, encrypted=enc, source="testbed", ground_truth_json=json.dumps(truth, default=str))
    db.add(a)
    db.commit()
    audit(db, "testbed.generate", request=request, target=aid, detail={"preset": body.preset, "traffic": cfg.traffic})
    jobs.submit(aid)
    return _row(a)


@router.get("/analyses")
def list_analyses(limit: int = 100, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(max(1, min(limit, 500)))
    return [_row(a) for a in q]


@router.get("/analyses/{aid}")
def get_analysis(aid: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = _get(db, aid)
    out = _row(a)
    out["result"] = json.loads(a.result_json) if a.result_json else None
    out["ground_truth"] = json.loads(a.ground_truth_json) if a.ground_truth_json else None
    out["result_sha256"] = a.result_sha256
    return out


@router.delete("/analyses/{aid}")
def delete_analysis(aid: str, request: Request, user: User = Depends(analyst), db: Session = Depends(get_db)):
    a = _get(db, aid)
    if user.role != "admin" and a.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only the owner or an administrator may delete this analysis")
    secure_delete(a.storage_path)
    db.delete(a)
    db.commit()
    audit(db, "analysis.delete", request=request, target=aid)
    return {"ok": True}


def _sig_payload(a: Analysis, kind: str) -> bytes:
    return f"{a.id}|{kind}|{a.result_sha256}".encode()


@router.get("/analyses/{aid}/report/{kind}")
def report(aid: str, kind: Literal["executive", "technical", "json"], request: Request,
           user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = _get(db, aid)
    if a.status != "done":
        raise HTTPException(status_code=409, detail="Analysis not finished")
    result = json.loads(a.result_json)
    sig = sign(_sig_payload(a, kind))
    audit(db, "report.download", request=request, target=aid, detail={"kind": kind})
    if kind == "json":
        body = json.dumps({"analysis_id": a.id, "result_sha256": a.result_sha256, "signature": sig, "result": result},
                          indent=2, default=str).encode()
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="ipsec-assessment-{a.id[:8]}.json"'})
    pdf = build_report(kind.title(), result, {"id": a.id, "owner": a.owner_name}, sig, a.result_sha256)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="ipsec-{kind}-report-{a.id[:8]}.pdf"'})


@router.get("/reports/verify")
def verify_report(analysis_id: str, kind: Literal["executive", "technical", "json"], signature: str,
                  _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    a = _get(db, analysis_id)
    ok = bool(re.fullmatch(r"[0-9a-f]{64}", signature)) and verify_signature(_sig_payload(a, kind), signature)
    return {"valid": ok, "analysis_id": a.id, "result_sha256": a.result_sha256}


@router.get("/analyses/{aid}/evidence")
def download_evidence(aid: str, request: Request, user: User = Depends(analyst), db: Session = Depends(get_db)):
    a = _get(db, aid)
    plain = jobs.materialize(a)
    try:
        data = open(plain, "rb").read()
    finally:
        secure_delete(plain)
    if hashlib.sha256(data).hexdigest() != a.sha256:
        raise HTTPException(status_code=500, detail="Evidence integrity check failed")
    audit(db, "evidence.download", request=request, target=aid)
    return Response(data, media_type="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": f'attachment; filename="{a.filename}"'})


@router.get("/stats")
def stats(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Analysis).all()
    done = [a for a in rows if a.status == "done"]
    scores = [a.score for a in done if a.score is not None]
    acc = Counter()
    for a in done:
        if not a.ground_truth_json:
            continue
        gt = json.loads(a.ground_truth_json)
        acc["n"] += 1
        acc["mode"] += int(gt.get("mode") == a.mode)
        acc["traffic"] += int(gt.get("traffic") == a.traffic)
        fam = gt.get("esp_encr", "")
        acc["encryption"] += int(bool(fam) and (fam in (a.encryption or "") or (fam == "NONE" and "NONE" in (a.encryption or ""))))
    return {
        "total": len(rows), "done": len(done), "running": sum(a.status in ("queued", "running") for a in rows),
        "failed": sum(a.status == "failed" for a in rows),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
        "grades": dict(Counter(a.grade for a in done if a.grade)),
        "risk_levels": dict(Counter(a.risk_level for a in done if a.risk_level)),
        "traffic": dict(Counter(a.traffic for a in done if a.traffic)),
        "ike_versions": dict(Counter(a.ike_version for a in done if a.ike_version)),
        "modes": dict(Counter(a.mode for a in done if a.mode)),
        "encryption": dict(Counter(a.encryption for a in done if a.encryption)),
        "critical_findings": sum(a.findings_critical for a in done),
        "high_findings": sum(a.findings_high for a in done),
        "testbed_accuracy": {k: round(acc[k] / acc["n"], 3) for k in ("mode", "traffic", "encryption")} | {"n": acc["n"]}
        if acc["n"] else None,
        "recent": [_row(a) for a in sorted(rows, key=lambda x: x.created_at, reverse=True)[:8]],
        "score_trend": [{"t": a.created_at.isoformat(), "score": a.score, "file": a.filename}
                        for a in sorted(done, key=lambda x: x.created_at)[-30:] if a.score is not None],
    }
