@echo off
REM One-command local start (Windows). Requires Python 3.10+ and Node 18+.
cd /d %~dp0
if "%ADMIN_PASSWORD%"=="" set ADMIN_PASSWORD=Sentinel@Demo2026
if not exist backend\.venv python -m venv backend\.venv
call backend\.venv\Scripts\activate.bat
pip install -q -r backend\requirements.txt
if not exist frontend\dist\index.html (cd frontend && call npm install --no-audit --no-fund && call npm run build && cd ..)
echo.
echo   IPsec Sentinel AI  -  http://127.0.0.1:8000
echo   login: admin / %ADMIN_PASSWORD%
echo.
cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-server-header
