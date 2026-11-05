import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="sentinel-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "Test#Sentinel-Passw0rd")
os.environ.setdefault("FRONTEND_DIST", "/nonexistent")
os.environ.setdefault("LOGIN_RATE_PER_MIN", "1000")
