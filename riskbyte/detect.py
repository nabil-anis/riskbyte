"""Rule engine: Sigma-style field matching plus simple threshold (count in window) aggregation."""
from __future__ import annotations
import glob, logging, os, re
from collections import defaultdict, deque
from dataclasses import dataclass, field

import yaml

log = logging.getLogger("riskbyte.detect")
SEVERITIES = ("low", "medium", "high", "critical")
FIELDS = ("host", "user", "src_ip", "dst_ip", "process", "cmdline", "action", "outcome", "message", "source")


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    match: dict = field(default_factory=dict)
    any_of: list = field(default_factory=list)
    threshold: dict | None = None
    action: dict | None = None
    description: str = ""
    tags: list = field(default_factory=list)


_re_cache: dict = {}


def _test(value, op: str, expected) -> bool:
    if value is None:
        return op == "ne"
    v = str(value).lower()
    if op == "in":
        return v in [str(x).lower() for x in expected]
    if op == "re":
        rx = _re_cache.setdefault(str(expected), re.compile(str(expected), re.I))
        return bool(rx.search(v))
    exp = str(expected).lower()
    if op == "eq":
        return v == exp
    if op == "ne":
        return v != exp
    if op == "contains":
        return exp in v
    if op == "startswith":
        return v.startswith(exp)
    if op == "endswith":
        return v.endswith(exp)
    return False


def _cond_ok(ev: dict, cond: dict) -> bool:
    for key, expected in cond.items():
        fld, _, op = key.partition("|")
        if not _test(ev.get(fld), op or "eq", expected):
            return False
    return True


def rule_matches(rule: Rule, ev: dict) -> bool:
    if rule.match and not _cond_ok(ev, rule.match):
        return False
    if rule.any_of and not any(_cond_ok(ev, c) for c in rule.any_of):
        return False
    return bool(rule.match or rule.any_of)


def _validate(d: dict) -> Rule:
    for k in ("id", "title", "severity"):
        if not d.get(k):
            raise ValueError(f"missing '{k}'")
    if d["severity"] not in SEVERITIES:
        raise ValueError(f"bad severity {d['severity']!r}")
    conds = [d.get("match") or {}] + list(d.get("any_of") or [])
    for c in conds:
        for key in c:
            fld, _, op = key.partition("|")
            if fld not in FIELDS or op not in ("", "eq", "ne", "contains", "startswith", "endswith", "re", "in"):
                raise ValueError(f"bad condition {key!r}")
            if op == "re":
                re.compile(str(c[key]))
    th = d.get("threshold")
    if th and (th.get("group_by") not in FIELDS or int(th.get("count", 0)) < 2 or int(th.get("window", 0)) < 1):
        raise ValueError("bad threshold")
    act = d.get("action")
    if act and (act.get("kind") not in ("block_ip", "isolate_host", "disable_user", "reset_password")
                or act.get("target_field") not in FIELDS):
        raise ValueError("bad action")
    return Rule(d["id"], d["title"], d["severity"], d.get("match") or {}, d.get("any_of") or [],
                th, act, d.get("description", ""), d.get("tags") or [])


def load_rules(directory: str) -> list:
    rules = []
    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        try:
            with open(path, encoding="utf-8") as fh:
                for doc in yaml.safe_load_all(fh):
                    if doc:
                        rules.append(_validate(doc))
        except Exception as exc:  # one bad file must not stop detection
            log.error("skipping rule file %s: %s", path, exc)
    return rules


class Engine:
    def __init__(self, rules: list):
        self.rules = rules
        self.windows: dict = defaultdict(deque)
        self.cooldown: dict = {}

    def evaluate(self, ev: dict) -> list:
        """Return a list of hits: {'rule': Rule, 'event_ids': [...], 'event': ev}."""
        hits = []
        for r in self.rules:
            if not rule_matches(r, ev):
                continue
            if not r.threshold:
                hits.append({"rule": r, "event_ids": [ev["id"]], "event": ev})
                continue
            group = ev.get(r.threshold["group_by"])
            if not group:
                continue
            key = (r.id, group)
            win = self.windows[key]
            win.append((ev["ts"], ev["id"]))
            while win and win[0][0] < ev["ts"] - r.threshold["window"]:
                win.popleft()
            if len(win) >= int(r.threshold["count"]) and ev["ts"] >= self.cooldown.get(key, 0):
                hits.append({"rule": r, "event_ids": [i for _, i in win], "event": ev})
                self.cooldown[key] = ev["ts"] + r.threshold["window"]
                win.clear()
        return hits
