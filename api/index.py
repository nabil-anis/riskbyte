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

from riskbyte import config
from riskbyte.service import Service
from riskbyte.api import get_handler_class

_svc = None

def get_service():
    global _svc
    if _svc is None:
        cfg = config.load()
        _svc = Service(cfg)
        # Pre-seed demo security events on startup if database is empty
        try:
            if _svc.stats()["events"] == 0:
                now = time.time()
                events = [
                    {"ts": now - 60 + i, "host": "web-01", "process": "sshd", "action": "login", "outcome": "failure",
                     "user": "root", "src_ip": "1.2.3.4", "message": "Failed password for root"} for i in range(6)
                ]
                events.append({
                    "ts": now, "host": "fin-lt-042", "user": "m.silva", "process": "powershell.exe",
                    "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA", "action": "process_start"
                })
                events.append({
                    "ts": now, "host": "app-02", "user": "svc-backup", "process": "ssh", "action": "login", "outcome": "success",
                    "src_ip": "198.51.100.7", "message": "Accepted publickey"
                })
                _svc.ingest(events, "seed")
                _svc.process_pending()
        except Exception:
            pass
    return _svc

# Export Vercel handler class
handler = get_handler_class(get_service())
