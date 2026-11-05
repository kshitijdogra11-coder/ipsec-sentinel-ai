#!/usr/bin/env bash
# One-command local start (Linux/macOS). Requires Python 3.10+ and Node 18+.
set -euo pipefail
cd "$(dirname "$0")"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-Sentinel@Demo2026}"
if [ ! -d backend/.venv ]; then python3 -m venv backend/.venv; fi
source backend/.venv/bin/activate
pip install -q -r backend/requirements.txt
if [ ! -f frontend/dist/index.html ]; then (cd frontend && npm install --no-audit --no-fund && npm run build); fi
if [ ! -f backend/models/ipsec_models.joblib ]; then (cd backend && python -m ml.train --data ../dataset --out models); fi
echo ""
echo "  IPsec Sentinel AI  →  http://127.0.0.1:8000"
echo "  login: admin / $ADMIN_PASSWORD   (change it under Account)"
echo ""
cd backend && exec uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-server-header
