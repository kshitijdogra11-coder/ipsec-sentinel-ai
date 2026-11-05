from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import audit, verify_chain
from ..core.database import AuditLog, User, get_db
from ..core.security import hash_password, password_policy_errors, require_role

router = APIRouter(tags=["administration"])
admin = require_role("admin")


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    full_name: str = Field(default="", max_length=128)
    password: str = Field(min_length=12, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class UserPatch(BaseModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=128)


def _out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role, "is_active": u.is_active,
            "locked": bool(u.locked_until), "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None}


@router.get("/users")
def list_users(_: User = Depends(admin), db: Session = Depends(get_db)):
    return [_out(u) for u in db.query(User).order_by(User.id)]


@router.post("/users", status_code=201)
def create_user(body: UserIn, request: Request, _: User = Depends(admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    errs = password_policy_errors(body.password, body.username)
    if errs:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(errs))
    u = User(username=body.username, full_name=body.full_name, role=body.role,
             password_hash=hash_password(body.password), must_change_password=True)
    db.add(u)
    db.commit()
    audit(db, "user.create", request=request, target=body.username, detail={"role": body.role})
    return _out(u)


@router.patch("/users/{uid}")
def patch_user(uid: int, body: UserPatch, request: Request, me: User = Depends(admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    if u.id == me.id and (body.role not in (None, "admin") or body.is_active is False):
        raise HTTPException(status_code=400, detail="You cannot demote or disable yourself")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(u, k, v)
    if "role" in changes or changes.get("is_active") is False:
        u.token_version += 1
    db.commit()
    audit(db, "user.update", request=request, target=u.username, detail=changes)
    return _out(u)


@router.post("/users/{uid}/unlock")
def unlock(uid: int, request: Request, _: User = Depends(admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    u.locked_until, u.failed_attempts = None, 0
    db.commit()
    audit(db, "user.unlock", request=request, target=u.username)
    return _out(u)


@router.delete("/users/{uid}")
def delete_user(uid: int, request: Request, me: User = Depends(admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(status_code=404, detail="Not found")
    if u.id == me.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    name = u.username
    db.delete(u)
    db.commit()
    audit(db, "user.delete", request=request, target=name)
    return {"ok": True}


@router.get("/audit")
def audit_log(limit: int = 200, offset: int = 0, _: User = Depends(admin), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 1000))
    q = db.query(AuditLog).order_by(AuditLog.id.desc()).offset(max(0, offset)).limit(limit)
    return {"total": db.query(AuditLog).count(), "items": [
        {"id": e.id, "ts": e.ts.isoformat(), "username": e.username, "ip": e.ip, "action": e.action,
         "target": e.target, "outcome": e.outcome, "detail": e.detail, "hash": e.hash} for e in q]}


@router.get("/audit/verify")
def audit_verify(request: Request, _: User = Depends(admin), db: Session = Depends(get_db)):
    res = verify_chain(db)
    audit(db, "audit.verify", request=request, outcome="success" if res["valid"] else "failure", detail=res)
    return res
