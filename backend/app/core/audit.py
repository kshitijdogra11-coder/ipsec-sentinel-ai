"""Tamper-evident audit trail (SHA-256 hash chain over every entry)."""
from __future__ import annotations

import hashlib
import json
import threading

from fastapi import Request
from sqlalchemy.orm import Session

from .database import AuditLog, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, ts: str, username: str, ip: str, action: str, target: str, outcome: str, detail: str) -> str:
    canon = json.dumps([prev, ts, username, ip, action, target, outcome, detail], separators=(",", ":"),
                       ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()


def client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "-"
    return request.client.host


def audit(db: Session, action: str, *, request: Request | None = None, username: str | None = None,
          target: str = "", outcome: str = "success", detail: str | dict = ""):
    if isinstance(detail, dict):
        detail = json.dumps(detail, sort_keys=True)
    if username is None and request is not None and getattr(request.state, "user", None):
        username = request.state.user.username
    username = (username or "-")[:64]
    with _lock:
        last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev = last.hash if last else GENESIS
        ts = utcnow().replace(microsecond=0)
        ip = client_ip(request)
        h = _digest(prev, ts.replace(tzinfo=None).isoformat(), username, ip, action, target[:255], outcome, detail[:4000])
        db.add(AuditLog(ts=ts, username=username, ip=ip, action=action, target=target[:255], outcome=outcome,
                        detail=detail[:4000], prev_hash=prev, hash=h))
        db.commit()


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    n = 0
    for e in db.query(AuditLog).order_by(AuditLog.id.asc()).yield_per(500):
        # timestamps are hashed as naive UTC ISO strings (SQLite drops tzinfo)
        expect = _digest(prev, e.ts.replace(tzinfo=None).isoformat(), e.username, e.ip, e.action, e.target, e.outcome, e.detail)
        if e.prev_hash != prev or e.hash != expect:
            return {"valid": False, "entries_checked": n, "broken_at": e.id}
        prev = e.hash
        n += 1
    return {"valid": True, "entries_checked": n, "head": prev}
