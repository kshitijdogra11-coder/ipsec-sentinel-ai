# REST API (v1)
All endpoints are under `/api/v1`. Interactive OpenAPI docs are at `/docs` (disabled when `APP_ENV=production`).
Authenticate with the session cookie set by `/auth/login` plus the header `X-Requested-With: IPsecSentinel`, or with `Authorization: Bearer <token>`.

| Method | Path | Role | Description |
|---|---|---|---|
| POST | /auth/login | – | `{username,password}` → sets cookie, returns token + user |
| POST | /auth/logout | any | revoke token |
| GET | /auth/me | any | current user |
| POST | /auth/change-password | any | rotates password and invalidates all sessions |
| POST | /analyses | analyst | multipart `file` (pcap/pcapng) → 202 queued analysis |
| GET | /analyses | viewer | list |
| GET | /analyses/{id} | viewer | status + full result + ground truth (testbed) |
| DELETE | /analyses/{id} | owner/admin | delete + secure-erase evidence |
| GET | /analyses/{id}/report/{executive\|technical\|json} | viewer | signed report download |
| GET | /analyses/{id}/evidence | analyst | decrypted, integrity-verified original capture |
| GET | /reports/verify?analysis_id&kind&signature | viewer | verify report HMAC |
| GET | /testbed/presets | viewer | VPN configuration presets |
| POST | /testbed/generate | analyst | `{preset, traffic, ip_version?, mode?, nat_t?, pfs?, replay_attack, duration}` |
| GET | /stats | viewer | dashboard aggregates, testbed AI accuracy |
| GET | /model | viewer | model version, SHA-256, metrics |
| GET | /dataset | viewer | dataset distribution summary |
| GET/POST/PATCH/DELETE | /users[/{id}] | admin | user management; POST /users/{id}/unlock |
| GET | /audit, /audit/verify | admin | audit log, hash-chain verification |
| GET | /health | – | liveness + model status |

## Result schema (abridged)
```json
{
  "capture": {"filename": "...", "sha256": "...", "packets": 1961, "duration_s": 115.5, "cleartext": {"DNS": 16}},
  "protocol_breakdown": {"IKE": 16, "ESP": 1929, "AH": 0},
  "tunnels": [{
    "id": "a <-> b", "protocol": "ESP",
    "identification": {"mode": {"value": "tunnel", "confidence": 0.66, "method": "AI: ESP length side-channel", "distribution": {...}}, "...": "..."},
    "ike": {"version": 2, "negotiated": {"encr": "AES-CBC", "key_len": 256, "dh_id": 14}, "timeline": [...]},
    "sas": [{"spi": "0xc1234567", "packets": 400, "duplicates": 0}],
    "replay": {"duplicates": 12, "verdict": "replayed packets detected"},
    "traffic": {"prediction": {"label": "web", "confidence": 0.94}, "timeline": [...]},
    "stats": {"series": {...}, "size_histogram": [...]}
  }],
  "assessment": {"score": 72, "grade": "C", "risk_score": 28, "risk_level": "Moderate", "ai_confidence": 0.92,
                 "summary": "...", "tunnels": [{"findings": [...], "compliance": [...], "threat_matrix": {...}, "metadata_exposure": [...]}]}
}
```
