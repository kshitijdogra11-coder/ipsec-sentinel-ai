"""Authentication, authorization and cryptographic helpers.

* Argon2id password hashing (RFC 9106 parameters) with transparent rehash
* Strong password policy
* Short-lived HS512 JWTs (iss/aud/exp/nbf/iat/jti) with server-side revocation
  and per-user token_version (password change / disable = global logout)
* HttpOnly + SameSite=Strict cookie transport **and** a mandatory custom
  request header on state-changing calls (CSRF defence in depth)
* AES-256-GCM encryption-at-rest for uploaded evidence (HKDF-derived key)
* HMAC-SHA256 signatures for generated reports
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import settings
from .database import RevokedToken, User, get_db, utcnow

ROLES = ("admin", "analyst", "viewer")
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "IPsecSentinel"
COOKIE_NAME = "sentinel_session"

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


# ------------------------------------------------------------- passwords --
def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str | None) -> bool:
    try:
        return _ph.verify(hashed or _DUMMY_HASH, pw) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


def password_policy_errors(pw: str, username: str = "") -> list[str]:
    errs = []
    if len(pw) < 12:
        errs.append("at least 12 characters")
    if len(pw) > 128:
        errs.append("at most 128 characters")
    if not re.search(r"[a-z]", pw):
        errs.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        errs.append("an uppercase letter")
    if not re.search(r"\d", pw):
        errs.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errs.append("a symbol")
    if username and username.lower() in pw.lower():
        errs.append("must not contain the username")
    return errs


# ------------------------------------------------------------------ JWT --
def create_access_token(user: User) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.access_token_minutes)
    payload = {"sub": str(user.id), "usr": user.username, "role": user.role, "tv": user.token_version,
               "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "iat": now, "nbf": now, "exp": exp,
               "jti": uuid.uuid4().hex}
    return jwt.encode(payload, settings.secret_key, algorithm="HS512"), exp


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS512"], audience=settings.jwt_audience,
                      issuer=settings.jwt_issuer, options={"require": ["exp", "iat", "nbf", "jti", "sub"]})


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE_NAME)


_unauth = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"})


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = _extract_token(request)
    if not token:
        raise _unauth
    try:
        claims = decode_token(token)
    except jwt.PyJWTError:
        raise _unauth from None
    if db.get(RevokedToken, claims["jti"]):
        raise _unauth
    user = db.get(User, int(claims["sub"]))
    if not user or not user.is_active or user.token_version != claims.get("tv"):
        raise _unauth
    # CSRF: cookie-authenticated, state-changing requests must carry the custom header
    if request.method not in ("GET", "HEAD", "OPTIONS") and not request.headers.get("authorization"):
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise HTTPException(status_code=403, detail="CSRF check failed")
    request.state.user = user
    request.state.claims = claims
    return user


def require_role(min_role: str):
    def dep(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return user
    return dep


def revoke(db: Session, claims: dict):
    exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    db.merge(RevokedToken(jti=claims["jti"], expires_at=exp))
    db.query(RevokedToken).filter(RevokedToken.expires_at < utcnow()).delete()
    db.commit()


# ------------------------------------------------- evidence encryption --
def _derive(info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"ipsec-sentinel-v1", info=info).derive(
        settings.secret_key.encode())


_EVIDENCE_KEY = None


def evidence_key() -> bytes:
    global _EVIDENCE_KEY
    if _EVIDENCE_KEY is None:
        _EVIDENCE_KEY = _derive(b"evidence-at-rest")
    return _EVIDENCE_KEY


CHUNK = 1 << 20
MAGIC = b"ISEV1"


def encrypt_file(src: str, dst: str, aad: bytes):
    """Chunked AES-256-GCM: MAGIC | [nonce(12) | len(4) | ct+tag]*  (per-chunk AAD binds index + id)."""
    aes = AESGCM(evidence_key())
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(src, "rb") as fi, os.fdopen(fd, "wb") as fo:
        fo.write(MAGIC)
        idx = 0
        while True:
            chunk = fi.read(CHUNK)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, chunk, aad + idx.to_bytes(8, "big") + (b"L" if len(chunk) < CHUNK else b"C"))
            fo.write(nonce + len(ct).to_bytes(4, "big") + ct)
            idx += 1
            if len(chunk) < CHUNK:
                break


def decrypt_file(src: str, dst: str, aad: bytes):
    aes = AESGCM(evidence_key())
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(src, "rb") as fi, os.fdopen(fd, "wb") as fo:
        if fi.read(len(MAGIC)) != MAGIC:
            raise ValueError("Evidence container corrupt")
        idx, final = 0, False
        while not final:
            hdr = fi.read(16)
            if len(hdr) < 16:
                raise ValueError("Evidence container truncated")
            nonce, n = hdr[:12], int.from_bytes(hdr[12:], "big")
            if n < 16 or n > CHUNK + 16:
                raise ValueError("Evidence container corrupt")
            ct = fi.read(n)
            final = (n - 16) < CHUNK
            fo.write(aes.decrypt(nonce, ct, aad + idx.to_bytes(8, "big") + (b"L" if final else b"C")))
            idx += 1
        if fi.read(1):
            raise ValueError("Trailing data after final evidence chunk")


def secure_delete(path: str):
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(min(size, 64 << 20)))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except FileNotFoundError:
        pass


# ------------------------------------------------------------ signing --
def sign(data: bytes) -> str:
    return hmac.new(_derive(b"report-signing"), data, hashlib.sha256).hexdigest()


def verify_signature(data: bytes, sig: str) -> bool:
    return hmac.compare_digest(sign(data), sig)
