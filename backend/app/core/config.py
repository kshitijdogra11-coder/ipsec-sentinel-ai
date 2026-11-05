"""Runtime configuration (12-factor: everything overridable via environment)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


def _load_secret(data_dir: str) -> str:
    """SECRET_KEY from env, else a persisted random 512-bit key (file mode 0600)."""
    env = os.environ.get("SECRET_KEY")
    if env:
        if len(env) < 32:
            raise RuntimeError("SECRET_KEY must be at least 32 characters")
        return env
    path = os.path.join(data_dir, ".secret_key")
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_urlsafe(64)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


@dataclass
class Settings:
    env: str = os.environ.get("APP_ENV", "development")
    data_dir: str = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
    max_upload_mb: int = int(os.environ.get("MAX_UPLOAD_MB", "200"))
    max_packets: int = int(os.environ.get("MAX_PACKETS", "2000000"))
    access_token_minutes: int = int(os.environ.get("ACCESS_TOKEN_MINUTES", "30"))
    jwt_issuer: str = "ipsec-sentinel"
    jwt_audience: str = "ipsec-sentinel-ui"
    lockout_threshold: int = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
    lockout_minutes: int = int(os.environ.get("LOCKOUT_MINUTES", "15"))
    cors_origins: list[str] = field(default_factory=lambda: [o for o in os.environ.get(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o])
    secure_cookies: bool = _env_bool("SECURE_COOKIES", False)
    encrypt_evidence: bool = _env_bool("ENCRYPT_EVIDENCE", True)
    analysis_workers: int = int(os.environ.get("ANALYSIS_WORKERS", "2"))
    login_rate_per_min: int = int(os.environ.get("LOGIN_RATE_PER_MIN", "10"))
    frontend_dist: str = os.environ.get("FRONTEND_DIST", os.path.join(BASE_DIR, "..", "frontend", "dist"))
    secret_key: str = ""

    def __post_init__(self):
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        for sub in ("evidence", "reports", "tmp"):
            os.makedirs(os.path.join(self.data_dir, sub), mode=0o700, exist_ok=True)
        self.secret_key = _load_secret(self.data_dir)
        self.db_url = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(self.data_dir, 'sentinel.db')}")

    @property
    def is_production(self) -> bool:
        return self.env == "production"


settings = Settings()
