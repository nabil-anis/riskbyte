"""Response actions. Only reachable through the approval gate. Default mode is dry-run."""
from __future__ import annotations
import hashlib, hmac, ipaddress, json, re, time, urllib.request

ACTIONS = {"block_ip": "ip", "isolate_host": "host", "disable_user": "user", "reset_password": "user"}
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,128}$")


def validate(kind: str, target) -> str | None:
    """Return an error string, or None if the action/target pair is acceptable."""
    if kind not in ACTIONS:
        return f"unknown action {kind!r}"
    if not target:
        return "no target"
    t = ACTIONS[kind]
    if t == "ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return "invalid IP"
    elif t == "host" and not HOST_RE.match(target):
        return "invalid host"
    elif t == "user" and not USER_RE.match(target):
        return "invalid user"
    return None


class Responder:
    def __init__(self, cfg):
        self.mode = cfg.response_mode
        self.url = cfg.response_webhook
        self.secret = cfg.response_secret.encode()
        self.protected = [ipaddress.ip_network(p, strict=False) for p in cfg.protected_ips]

    def protected_reason(self, kind: str, target: str) -> str | None:
        if kind != "block_ip":
            return None
        ip = ipaddress.ip_address(target)
        if not ip.is_global:
            return "refusing to block a private, loopback, link-local or otherwise non-public address"
        if any(ip in n for n in self.protected):
            return "address is on the protected list"
        return None

    def execute(self, kind: str, target: str, alert_id: int):
        """Return (ok, message)."""
        err = validate(kind, target)
        if err is None:
            err = self.protected_reason(kind, target)
        if err:
            return False, err
        if self.mode == "dry_run":
            return True, f"dry-run: would {kind} {target}"
        body = json.dumps({"kind": kind, "target": target, "alert_id": alert_id, "ts": int(time.time())}).encode()
        sig = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Riskbyte-Signature": sig})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return 200 <= r.status < 300, f"webhook responded {r.status}"
        except Exception as exc:
            return False, f"webhook failed: {exc}"
