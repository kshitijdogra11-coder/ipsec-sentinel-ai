"""API security controls: authN, RBAC, CSRF, lockout, upload validation, audit chain."""
import glob
import os
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app

H = {"X-Requested-With": "IPsecSentinel"}
ADMIN = ("admin", os.environ["ADMIN_PASSWORD"])
SAMPLE = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "..", "dataset", "samples", "*.pcap")))


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(c, u, p):
    return c.post("/api/v1/auth/login", json={"username": u, "password": p})


def test_requires_auth(client):
    client.cookies.clear()
    assert client.get("/api/v1/analyses").status_code == 401


def test_security_headers(client):
    r = client.get("/api/v1/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_login_and_csrf(client):
    assert login(client, *ADMIN).status_code == 200
    assert client.post("/api/v1/testbed/generate", json={}).status_code == 403  # no CSRF header
    assert client.get("/api/v1/auth/me").json()["role"] == "admin"


def test_tampered_token_rejected(client):
    tok = login(client, *ADMIN).json()["access_token"]
    bad = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


def test_password_policy_and_rbac(client):
    login(client, *ADMIN)
    assert client.post("/api/v1/users", json={"username": "weak", "password": "password", "role": "analyst"}, headers=H).status_code == 422
    assert client.post("/api/v1/users", json={"username": "viewer1", "password": "Viewer#Pass2026x", "role": "viewer"}, headers=H).status_code == 201
    login(client, "viewer1", "Viewer#Pass2026x")
    assert client.get("/api/v1/users").status_code == 403
    assert client.post("/api/v1/testbed/generate", json={"preset": "modern-ecp"}, headers=H).status_code == 403


def test_lockout(client):
    login(client, *ADMIN)
    client.post("/api/v1/users", json={"username": "lock1", "password": "Lock#Pass2026xx", "role": "viewer"}, headers=H)
    codes = [login(client, "lock1", "wrong-password").status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 423
    assert login(client, "lock1", "Lock#Pass2026xx").status_code == 423


def test_upload_validation(client):
    login(client, *ADMIN)
    r = client.post("/api/v1/analyses", files={"file": ("evil.pcap", b"<script>alert(1)</script>" * 4)}, headers=H)
    assert r.status_code == 415


@pytest.mark.skipif(not SAMPLE, reason="sample captures missing")
def test_upload_analyze_report(client):
    login(client, *ADMIN)
    data = open(SAMPLE[0], "rb").read()
    a = client.post("/api/v1/analyses", files={"file": ("../../x/../cap.pcap", data)}, headers=H).json()
    assert a["filename"] == "cap.pcap"
    for _ in range(60):
        d = client.get(f"/api/v1/analyses/{a['id']}").json()
        if d["status"] in ("done", "failed"):
            break
        time.sleep(0.5)
    assert d["status"] == "done", d["error"]
    assert d["score"] is not None
    pdf = client.get(f"/api/v1/analyses/{a['id']}/report/executive")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    ev = client.get(f"/api/v1/analyses/{a['id']}/evidence")
    assert ev.content == data  # AES-GCM at-rest round trip


def test_audit_chain(client):
    login(client, *ADMIN)
    assert client.get("/api/v1/audit/verify").json()["valid"] is True
