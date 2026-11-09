"""SQLite event store with a hash-chained audit trail."""
from __future__ import annotations
import hashlib, json, sqlite3, threading, time

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, source TEXT, host TEXT, user TEXT,
  src_ip TEXT, dst_ip TEXT, process TEXT, cmdline TEXT, action TEXT, outcome TEXT, message TEXT,
  processed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_proc ON events(processed);
CREATE INDEX IF NOT EXISTS ix_events_host ON events(host, ts);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, entity TEXT, title TEXT, severity TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, rule_id TEXT, title TEXT, severity TEXT, status TEXT,
  host TEXT, user TEXT, src_ip TEXT, event_ids TEXT, triage TEXT, proposed_action TEXT, case_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, kind TEXT, alert_id INTEGER,
  detail TEXT, prev_hash TEXT, hash TEXT);
"""
EVENT_COLS = ("ts", "source", "host", "user", "src_ip", "dst_ip", "process", "cmdline", "action", "outcome", "message")


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    def execute(self, sql: str, params=()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    def query(self, sql: str, params=()) -> list:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def add_event(self, ev: dict) -> int:
        cols = ",".join(EVENT_COLS)
        return self.execute(f"INSERT INTO events({cols}) VALUES({','.join('?' * len(EVENT_COLS))})",
                            tuple(ev.get(c) for c in EVENT_COLS))

    def audit(self, actor: str, kind: str, alert_id, detail) -> None:
        detail = detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True)
        with self.lock:
            last = self.conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else "0" * 64
            ts = time.time()
            h = hashlib.sha256(f"{prev}|{ts!r}|{actor}|{kind}|{alert_id}|{detail}".encode()).hexdigest()
            self.conn.execute("INSERT INTO audit(ts,actor,kind,alert_id,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                              (ts, actor, kind, alert_id, detail, prev, h))
            self.conn.commit()

    def verify_audit(self) -> bool:
        prev = "0" * 64
        for r in self.query("SELECT * FROM audit ORDER BY id"):
            h = hashlib.sha256(f"{prev}|{r['ts']!r}|{r['actor']}|{r['kind']}|{r['alert_id']}|{r['detail']}".encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != h:
                return False
            prev = h
        return True

    def purge_events(self, days: int) -> int:
        with self.lock:
            cur = self.conn.execute("DELETE FROM events WHERE ts < ? AND processed=1", (time.time() - days * 86400,))
            self.conn.commit()
            return cur.rowcount
