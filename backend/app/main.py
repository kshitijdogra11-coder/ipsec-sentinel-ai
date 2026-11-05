"""IPsec Sentinel AI - FastAPI application entry point."""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import analyses, auth, system, users
from .core.audit import audit
from .core.config import settings
from .core.database import SessionLocal, User, init_db
from .core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from .core.security import hash_password, password_policy_errors

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel")

app = FastAPI(
    title="IPsec Sentinel AI",
    description="AI-powered IPsec VPN protocol analyzer and security assessment framework (SIH26160).",
    version="1.0.0",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"],
                   allow_headers=["Authorization", "Content-Type", "X-Requested-With"])

for r in (auth.router, users.router, analyses.router, system.router):
    app.include_router(r, prefix="/api/v1")


@app.exception_handler(StarletteHTTPException)
async def http_exc(_: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exc(_: Request, exc: RequestValidationError):
    errs = [{"field": ".".join(str(x) for x in e["loc"][1:]), "msg": e["msg"]} for e in exc.errors()]
    return JSONResponse({"detail": "Invalid request", "errors": errs}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error rid=%s", getattr(request.state, "request_id", "-"))
    return JSONResponse({"detail": "Internal server error",
                         "request_id": getattr(request.state, "request_id", None)}, status_code=500)


def bootstrap_admin():
    db = SessionLocal()
    try:
        if db.query(User).count():
            return
        username = os.environ.get("ADMIN_USERNAME", "admin")
        pw = os.environ.get("ADMIN_PASSWORD")
        generated = pw is None
        if generated:
            pw = secrets.token_urlsafe(12) + "#9a"
        errs = password_policy_errors(pw, username)
        if errs:
            raise RuntimeError("ADMIN_PASSWORD does not meet policy: " + ", ".join(errs))
        db.add(User(username=username, full_name="Administrator", role="admin", password_hash=hash_password(pw),
                    must_change_password=generated))
        db.commit()
        audit(db, "system.bootstrap_admin", username="system", target=username)
        if generated:
            path = os.path.join(settings.data_dir, "INITIAL_ADMIN_PASSWORD.txt")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(f"{username}:{pw}\n")
            log.warning("Created admin user '%s'. One-time password written to %s", username, path)
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()
    bootstrap_admin()
    try:
        from .analyzer.ml_engine import MLEngine
        MLEngine.get()
        log.info("AI model bundle loaded and integrity-verified")
    except Exception as exc:  # noqa: BLE001
        log.error("AI model unavailable: %s", exc)


# ------------------------------------------------------------ SPA hosting --
dist = os.path.abspath(settings.frontend_dist)
if os.path.isdir(dist):
    if os.path.isdir(os.path.join(dist, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        candidate = os.path.abspath(os.path.join(dist, path))
        if path and candidate.startswith(dist + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(dist, "index.html"))
