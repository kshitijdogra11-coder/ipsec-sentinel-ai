# Security Architecture of IPsec Sentinel AI

This platform stores sensitive network evidence and produces security verdicts, so it is hardened as a security product in its own right.

| Threat | Control | Implementation |
|---|---|---|
| Credential theft / cracking | Argon2id (t=3, m=64 MiB, p=4), transparent rehash, 12+ character complexity policy, username not allowed in password | `core/security.py` |
| Brute force | Account lockout (5 failures, 15 min). Login rate limit of 10/min per IP. Timing is equalised for unknown users with a dummy hash. | `api/auth.py`, `core/middleware.py` |
| User enumeration | Generic error for unknown user and wrong password alike | `api/auth.py` |
| Session hijack | HS512 JWT with 30-minute expiry, `iss/aud/nbf/jti` required. Server-side revocation on logout. `token_version` invalidates every session on password or role change or when an account is disabled. | `core/security.py` |
| XSS token theft | Token kept in an **HttpOnly** cookie scoped to `/api`. The SPA never stores it. Strict CSP: `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`. | `api/auth.py`, `core/middleware.py` |
| CSRF | `SameSite=Strict` cookie **and** a mandatory `X-Requested-With: IPsecSentinel` header on state-changing cookie-authenticated requests (this header forces a CORS preflight) | `core/security.py` |
| Privilege escalation | RBAC with admin, analyst and viewer roles, checked on every route. Object-level check for deletes. Admins cannot demote or delete themselves. | `api/*.py` |
| Malicious uploads | Streaming size cap (200 MB). Type validated by **magic bytes** (pcap/pcapng only), not by extension. Random server-side filenames. Display names sanitised (no path traversal). Stored outside the web root with mode 0600. | `api/analyses.py`, `core/jobs.py` |
| Parser exploitation | Own minimal pcap/IKE parser: bounds-checked slicing, loop and payload caps, record-size limits, per-packet exception isolation, 2M packet budget | `analyzer/pcap_reader.py`, `analyzer/ike_parser.py` |
| Evidence disclosure | **AES-256-GCM encryption at rest** in 1 MiB authenticated chunks. AAD binds the analysis ID, chunk index and final-chunk flag, which defeats truncation, reordering and swapping. Key derived with HKDF-SHA256 from `SECRET_KEY`. Plaintext temporary files are overwritten and fsynced before deletion. | `core/security.py` |
| Evidence tampering / chain of custody | SHA-256 recorded at ingest and **re-verified before every analysis and download** | `core/jobs.py` |
| Report forgery | Reports are bound to the SHA-256 of the result and carry an **HMAC-SHA256 signature** (separately derived key). Verify with `GET /api/v1/reports/verify`. | `api/analyses.py` |
| Log tampering / repudiation | **Hash-chained audit log**: each entry is SHA-256(prev_hash ‖ canonical fields). Verification available in the UI and through the API. Logins, uploads, report downloads and admin actions are all recorded. | `core/audit.py` |
| Model poisoning / pickle RCE | The model bundle is loaded **only after its SHA-256 matches** `MANIFEST.sha256` (constant-time compare) | `analyzer/ml_engine.py` |
| Information leakage | Generic 500 responses carrying a request ID. Swagger disabled in production. `--no-server-header`. `Cache-Control: no-store` on the API. | `main.py` |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP, Permissions-Policy, HSTS when served over TLS | `core/middleware.py` |
| SQL injection | SQLAlchemy ORM only (parameterised queries). Strict Pydantic input schemas with regex, enum and range validation. | everywhere |
| Secret management | `SECRET_KEY` from the environment, or a generated 512-bit key persisted with mode 0600. No default admin password: it is set through `ADMIN_PASSWORD` or generated once and written to a 0600 file. | `core/config.py`, `main.py` |
| Container | Non-root UID, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, healthcheck | `Dockerfile`, `docker-compose.yml` |

## Production checklist
- Put the app behind TLS (nginx or Traefik), set `SECURE_COOKIES=true` and `APP_ENV=production`.
- Set a strong `SECRET_KEY` (at least 32 characters) from a secrets manager and back it up. **Without it, stored evidence cannot be decrypted.**
- Set `CORS_ORIGINS` to the real UI origin only.
- For horizontal scaling, replace SQLite with PostgreSQL (`DATABASE_URL`) and the in-process rate limiter with Redis.
- Run `pytest backend/tests`. It covers the authentication, CSRF, RBAC, lockout, upload validation, encryption round-trip and audit-chain tests.
