from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.audit import audit
from ..core.config import settings
from ..core.database import User, get_db, utcnow
from ..core.security import (COOKIE_NAME, create_access_token, get_current_user, hash_password, needs_rehash,
                             password_policy_errors, revoke, verify_password)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=128)


class ChangePwIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


def user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role,
            "must_change_password": u.must_change_password,
            "last_login": u.last_login.isoformat() if u.last_login else None}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    now = utcnow()
    generic = HTTPException(status_code=401, detail="Invalid username or password")
    if user and user.locked_until and user.locked_until.replace(tzinfo=now.tzinfo) > now:
        verify_password(body.password, None)  # equalise timing
        audit(db, "auth.login", request=request, username=body.username, outcome="failure", detail="account locked")
        raise HTTPException(status_code=423, detail="Account temporarily locked. Try again later.")
    ok = verify_password(body.password, user.password_hash if user else None)
    if not user or not ok or not user.is_active:
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= settings.lockout_threshold:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_attempts = 0
            db.commit()
        audit(db, "auth.login", request=request, username=body.username, outcome="failure", detail="bad credentials")
        raise generic
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()
    token, exp = create_access_token(user)
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=settings.secure_cookies, samesite="strict",
                        max_age=settings.access_token_minutes * 60, path="/api")
    audit(db, "auth.login", request=request, username=user.username)
    return {"access_token": token, "token_type": "bearer", "expires_at": exp.isoformat(), "user": user_out(user)}


@router.post("/logout")
def logout(request: Request, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    revoke(db, request.state.claims)
    response.delete_cookie(COOKIE_NAME, path="/api")
    audit(db, "auth.logout", request=request)
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)


@router.post("/change-password")
def change_password(body: ChangePwIn, request: Request, response: Response, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        audit(db, "auth.change_password", request=request, outcome="failure")
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    errs = password_policy_errors(body.new_password, user.username)
    if errs:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(errs))
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # invalidates every existing session
    user.must_change_password = False
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/api")
    audit(db, "auth.change_password", request=request)
    return {"ok": True, "detail": "Password changed. Please sign in again."}
