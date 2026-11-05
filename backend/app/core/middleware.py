"""HTTP hardening middleware: security headers, rate limiting, request IDs."""
from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import settings

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
       "frame-ancestors 'none'")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = uuid.uuid4().hex[:16]
        request.state.request_id = rid
        response = await call_next(request)
        h = response.headers
        h["X-Request-ID"] = rid
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            h["Content-Security-Policy"] = CSP + ("; upgrade-insecure-requests" if settings.secure_cookies else "")
        if settings.secure_cookies or request.url.scheme == "https":
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        if "server" in h:
            del h["server"]
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limiter per client IP and route class (in-process)."""

    RULES = [  # (path prefix, method or None, limit, window seconds)
        ("/api/v1/auth/login", "POST", settings.login_rate_per_min, 60),
        ("/api/v1/analyses", "POST", 30, 60),
        ("/api/v1/testbed/generate", "POST", 20, 60),
        ("/api/", None, 600, 60),
    ]

    def __init__(self, app):
        super().__init__(app)
        self.hits: dict[tuple, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "-"
        path = request.url.path
        for prefix, method, limit, window in self.RULES:
            if path.startswith(prefix) and (method is None or request.method == method):
                key = (ip, prefix, method)
                now = time.monotonic()
                with self.lock:
                    q = self.hits[key]
                    while q and q[0] <= now - window:
                        q.popleft()
                    if len(q) >= limit:
                        retry = int(window - (now - q[0])) + 1
                        return JSONResponse({"detail": "Too many requests"}, status_code=429,
                                            headers={"Retry-After": str(retry)})
                    q.append(now)
                break
        return await call_next(request)
