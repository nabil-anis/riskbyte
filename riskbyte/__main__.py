"""CLI: python -m riskbyte serve | demo"""
from __future__ import annotations
import json, logging, sys, time, urllib.request

from . import config
from .api import make_server
from .service import Service


def serve():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        cfg = config.load()
    except config.ConfigError as exc:
        sys.exit(f"configuration error: {exc}")
    svc = Service(cfg)
    svc.start()
    srv = make_server(svc, cfg.bind, cfg.port)
    logging.getLogger("riskbyte").info("Riskbyte listening on %s:%s (license: %s)", cfg.bind, cfg.port, svc.license_status()["state"])
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
        srv.server_close()


def demo(base="http://127.0.0.1:8080", token="dev-ingest"):
    """Send sample attack telemetry to a running instance."""
    now = time.time()
    events = [{"ts": now - 60 + i, "host": "web-01", "process": "sshd", "action": "login", "outcome": "failure",
               "user": "root", "src_ip": "1.2.3.4", "message": "Failed password for root"} for i in range(6)]
    events.append({"ts": now, "host": "fin-lt-042", "user": "m.silva", "process": "powershell.exe",
                   "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA", "action": "process_start"})
    events.append({"ts": now, "host": "app-02", "user": "svc-backup", "process": "ssh", "action": "login", "outcome": "success",
                   "src_ip": "198.51.100.7", "message": "Accepted publickey"})
    req = urllib.request.Request(base + "/api/ingest", data=json.dumps(events).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    print(urllib.request.urlopen(req).read().decode())


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    {"serve": serve, "demo": demo}.get(cmd, lambda: sys.exit("usage: python -m riskbyte [serve|demo]"))()
