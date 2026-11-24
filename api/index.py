"""Vercel Serverless Entrypoint for Riskbyte."""
from __future__ import annotations
import os, sys, time

# Add root directory to sys.path so 'riskbyte' can be imported
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Ensure dev mode is enabled for demo/testing unless explicitly overridden
os.environ["RISKBYTE_DEV_MODE"] = os.environ.get("RISKBYTE_DEV_MODE", "1")

# On Vercel, filesystem is read-only except /tmp
if "VERCEL" in os.environ or not os.environ.get("RISKBYTE_DATA_DIR"):
    os.environ["RISKBYTE_DATA_DIR"] = "/tmp/riskbyte_data"
    os.environ["RISKBYTE_SYSLOG_PORT"] = "0"
    os.environ["RISKBYTE_RULES_DIR"] = os.path.join(ROOT, "rules")
    os.environ["RISKBYTE_INTEL_FILE"] = os.path.join(ROOT, "intel", "indicators.txt")

from riskbyte import config
from riskbyte.service import Service
from riskbyte.api import get_handler_class

_svc = None

def get_impl():
    global _svc
    if _svc is None:
        cfg = config.load()
        _svc = Service(cfg)
        # Pre-seed demo security telemetry on startup if database is empty
        try:
            if _svc.stats()["events"] == 0:
                now = time.time()
                events = [
                    {"ts": now - 60 + i, "host": "ci-build-01.contour.internal", "process": "sshd", "action": "login", "outcome": "failure",
                     "user": "root", "src_ip": "203.0.113.88", "message": "Failed password for root", "client": "Contour Software"} for i in range(6)
                ]
                events.append({
                    "ts": now, "host": "dev-laptop-07.contour.internal", "user": "m.silva", "process": "powershell.exe",
                    "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA", "action": "process_start", "client": "Contour Software"
                })
                events.append({
                    "ts": now, "host": "vpn.meezanbank.com", "user": "svc-backup", "process": "ssh", "action": "login", "outcome": "success",
                    "src_ip": "198.51.100.44", "message": "Accepted publickey from anomalous country", "client": "Meezan Bank"
                })
                _svc.ingest(events, "seed")
                _svc.process_pending()
        except Exception:
            pass
    return get_handler_class(_svc)


# Top-level class definition for Vercel Python AST detector
class handler(get_impl()):
    pass


# Top-level app and application variables for WSGI/ASGI detectors
app = handler
application = handler
