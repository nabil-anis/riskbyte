"""Normalize raw telemetry (JSON or syslog text) into one event schema. All input is treated as untrusted."""
from __future__ import annotations
import ipaddress, json, os, re, time
from datetime import datetime

MAXLEN = {"message": 2000, "cmdline": 2000}
SYSLOG = re.compile(r'^<\d+>(?:\d\s)?(?:\w{3}\s+\d+\s[\d:]{8}|\S+T\S+)\s(\S+)\s([\w\-./]+)(?:\[\d+\])?:\s?(.*)$', re.S)
SSH_FAIL = re.compile(r'Failed \w+ for (?:invalid user )?(\S+) from (\S+)')
SSH_OK = re.compile(r'Accepted \w+ for (\S+) from (\S+)')
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
CTRL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
ALIASES = {
    "host": ("host", "hostname", "computer", "computername"),
    "user": ("user", "username", "user_name", "targetusername"),
    "src_ip": ("src_ip", "source_ip", "sourceip", "src", "ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "destinationip", "dst"),
    "process": ("process", "process_name", "image"),
    "cmdline": ("cmdline", "command_line", "commandline"),
    "action": ("action", "event", "eventtype"),
    "outcome": ("outcome", "result", "status"),
    "message": ("message", "msg"),
}


def _clean(v, limit=256):
    if v is None:
        return None
    s = CTRL.sub("", str(v)).strip()
    return s[:limit] or None


def _ip(v):
    try:
        return str(ipaddress.ip_address(str(v).strip())) if v else None
    except ValueError:
        return None


def _ts(v) -> float:
    if isinstance(v, (int, float)) and 0 < v < 4102444800:
        return float(v)
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def _from_dict(d: dict, source: str) -> dict:
    low = {str(k).lower(): v for k, v in d.items()}
    ev = {"ts": _ts(low.get("ts", low.get("timestamp"))), "source": source}
    for field, names in ALIASES.items():
        for n in names:
            if n in low and low[n] not in (None, ""):
                ev[field] = low[n]
                break
    if ev.get("process"):
        ev["process"] = os.path.basename(str(ev["process"]).replace("\\", "/"))
    return ev


def _from_syslog(line: str, source: str):
    m = SYSLOG.match(line.strip())
    if not m:
        return {"ts": time.time(), "source": source, "message": line}
    host, proc, msg = m.groups()
    ev = {"ts": time.time(), "source": source, "host": host, "process": proc, "message": msg}
    for k, v in KV.findall(msg):
        k = k.lower()
        for field, names in ALIASES.items():
            if k in names and field not in ("message",):
                ev.setdefault(field, v.strip('"'))
    if (f := SSH_FAIL.search(msg)):
        ev.update(user=f.group(1), src_ip=f.group(2), action="login", outcome="failure")
    elif (s := SSH_OK.search(msg)):
        ev.update(user=s.group(1), src_ip=s.group(2), action="login", outcome="success")
    return ev


def normalize(raw, source: str = "api"):
    """Return a normalized event dict, or None if the input is unusable."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return None
            ev = _from_dict(json.loads(raw), source) if raw.startswith("{") else _from_syslog(raw, source)
        elif isinstance(raw, dict):
            ev = _from_dict(raw, source)
        else:
            return None
    except (ValueError, TypeError):
        return None
    out = {"ts": ev["ts"], "source": _clean(source, 32)}
    for f in ("host", "user", "process", "action", "outcome"):
        out[f] = _clean(ev.get(f))
    for f in ("src_ip", "dst_ip"):
        out[f] = _ip(ev.get(f))
    for f, lim in MAXLEN.items():
        out[f] = _clean(ev.get(f), lim)
    if out["host"]:
        out["host"] = out["host"].lower()
    if not any(out[k] for k in ("host", "user", "src_ip", "dst_ip", "process", "message", "cmdline")):
        return None
    return out
