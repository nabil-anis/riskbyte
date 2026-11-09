"""Core service: ingest -> detect -> alert/case -> triage -> approval gate -> response."""
from __future__ import annotations
import json, logging, os, socketserver, threading, time

from . import ingest
from .agent import Intel, Triage, make_llm
from .db import Store
from .detect import Engine, load_rules
from .licensing import LicenseManager
from .response import Responder, validate

log = logging.getLogger("riskbyte.service")
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ServiceError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


class Service:
    def __init__(self, cfg, llm=None):
        os.makedirs(cfg.data_dir, exist_ok=True)
        self.cfg = cfg
        self.store = Store(cfg.db_path)
        self.engine = Engine(load_rules(cfg.rules_dir))
        if llm is None:
            llm = make_llm(cfg)
        self.triage = Triage(self.store, Intel(cfg.intel_file), llm, cfg.auto_close_low,
                             f"{cfg.llm_provider}:{cfg.llm_model}", cfg.llm_redact)
        self.responder = Responder(cfg)
        self.license = LicenseManager(cfg.license_path, cfg.license_pubkey, cfg.dev_mode)
        self._stop = threading.Event()
        self._threads: list = []
        self._syslog = None

    # ---- ingestion -------------------------------------------------
    def ingest(self, items, source="api") -> int:
        n = 0
        for raw in items:
            ev = ingest.normalize(raw, source)
            if ev:
                self.store.add_event(ev)
                n += 1
        return n

    # ---- detection + triage ---------------------------------------
    def license_status(self) -> dict:
        hosts = self.store.one("SELECT COUNT(DISTINCT host) n FROM events WHERE ts>=?", (time.time() - 86400,))["n"]
        return self.license.status(hosts)

    def process_pending(self, limit=500) -> int:
        rows = self.store.query("SELECT * FROM events WHERE processed=0 ORDER BY id LIMIT ?", (limit,))
        for ev in rows:
            for hit in self.engine.evaluate(ev):
                self._create_alert(hit)
            self.store.execute("UPDATE events SET processed=1 WHERE id=?", (ev["id"],))
        if self.license_status()["can_triage"]:
            for a in self.store.query("SELECT id FROM alerts WHERE status='new' ORDER BY id LIMIT 20"):
                self._triage(a["id"])
        return len(rows)

    def _create_alert(self, hit):
        r, ev = hit["rule"], hit["event"]
        action = None
        if r.action:
            target = ev.get(r.action["target_field"])
            if target:
                action = {"kind": r.action["kind"], "target": target}
        entity = ev.get("host") or ev.get("user") or ev.get("src_ip") or r.id
        case = self.store.one("SELECT * FROM cases WHERE entity=? AND status='open' AND ts>=?", (entity, time.time() - 86400))
        if case:
            case_id = case["id"]
            if SEV_RANK[r.severity] > SEV_RANK[case["severity"]]:
                self.store.execute("UPDATE cases SET severity=? WHERE id=?", (r.severity, case_id))
        else:
            case_id = self.store.execute("INSERT INTO cases(ts,entity,title,severity,status) VALUES(?,?,?,?,'open')",
                                         (time.time(), entity, f"Investigation: {entity}", r.severity))
        aid = self.store.execute(
            "INSERT INTO alerts(ts,rule_id,title,severity,status,host,user,src_ip,event_ids,proposed_action,case_id) "
            "VALUES(?,?,?,?,'new',?,?,?,?,?,?)",
            (ev["ts"], r.id, r.title, r.severity, ev.get("host"), ev.get("user"), ev.get("src_ip"),
             json.dumps(hit["event_ids"]), json.dumps(action) if action else None, case_id))
        self.store.audit("system", "alert_created", aid, {"rule": r.id, "severity": r.severity, "case": case_id})
        return aid

    def _load_alert(self, aid: int) -> dict:
        a = self.store.one("SELECT * FROM alerts WHERE id=?", (aid,))
        if not a:
            raise ServiceError("alert not found", 404)
        for k in ("event_ids", "triage", "proposed_action"):
            a[k] = json.loads(a[k]) if a[k] else None
        return a

    def _events(self, ids):
        if not ids:
            return []
        q = ",".join("?" * len(ids))
        return self.store.query(f"SELECT * FROM events WHERE id IN ({q}) ORDER BY id", tuple(ids))

    def _triage(self, aid: int):
        a = self._load_alert(aid)
        result = self.triage.investigate(a, self._events(a["event_ids"]))
        status = "triaged"
        if self.triage.should_auto_close(a, result):
            status = "auto_closed"
        self.store.execute("UPDATE alerts SET triage=?, status=?, proposed_action=? WHERE id=?",
                           (json.dumps(result), status, json.dumps(result["proposed_action"]) if result["proposed_action"] else None, aid))
        self.store.audit("agent", "triaged", aid, {"verdict": result["verdict"], "engine": result["engine"], "status": status})
        if status == "auto_closed":
            self._maybe_close_case(a["case_id"])

    # ---- approval gate --------------------------------------------
    def approve(self, aid: int, actor: str) -> dict:
        if not self.license_status()["can_approve"]:
            raise ServiceError("license does not permit response actions", 402)
        a = self._load_alert(aid)
        if a["status"] != "triaged":
            raise ServiceError(f"alert is '{a['status']}', only triaged alerts can be approved", 409)
        act = a["proposed_action"]
        if not act:
            raise ServiceError("alert has no proposed action", 400)
        ok, msg = self.responder.execute(act["kind"], act["target"], aid)
        status = "executed" if ok else "failed"
        self.store.execute("UPDATE alerts SET status=? WHERE id=?", (status, aid))
        self.store.audit(actor, "action_approved", aid, {"action": act, "ok": ok, "result": msg})
        self._maybe_close_case(a["case_id"])
        return {"status": status, "result": msg}

    def dismiss(self, aid: int, actor: str) -> dict:
        a = self._load_alert(aid)
        if a["status"] not in ("new", "triaged", "failed"):
            raise ServiceError(f"alert is '{a['status']}' and cannot be dismissed", 409)
        self.store.execute("UPDATE alerts SET status='dismissed' WHERE id=?", (aid,))
        self.store.audit(actor, "alert_dismissed", aid, {})
        self._maybe_close_case(a["case_id"])
        return {"status": "dismissed"}

    def _maybe_close_case(self, case_id):
        left = self.store.one("SELECT COUNT(*) n FROM alerts WHERE case_id=? AND status IN ('new','triaged','failed')", (case_id,))["n"]
        if left == 0:
            self.store.execute("UPDATE cases SET status='closed' WHERE id=?", (case_id,))

    # ---- reads -----------------------------------------------------
    def alerts(self, status=None, limit=100) -> list:
        sql, p = "SELECT * FROM alerts", ()
        if status:
            sql, p = sql + " WHERE status=?", (status,)
        rows = self.store.query(sql + " ORDER BY id DESC LIMIT ?", p + (min(limit, 500),))
        for a in rows:
            for k in ("event_ids", "triage", "proposed_action"):
                a[k] = json.loads(a[k]) if a[k] else None
        return rows

    def alert_detail(self, aid: int) -> dict:
        a = self._load_alert(aid)
        a["events"] = self._events(a["event_ids"])
        return a

    def stats(self) -> dict:
        q = self.store.one
        return {"events": q("SELECT COUNT(*) n FROM events")["n"],
                "open_alerts": q("SELECT COUNT(*) n FROM alerts WHERE status IN ('new','triaged')")["n"],
                "open_cases": q("SELECT COUNT(*) n FROM cases WHERE status='open'")["n"],
                "audit_intact": self.store.verify_audit(), "version": "0.1.0",
                "llm": self.cfg.llm_provider, "llm_redaction": self.cfg.llm_redact}

    # ---- background workers ---------------------------------------
    def start(self):
        t = threading.Thread(target=self._loop, name="worker", daemon=True)
        t.start()
        self._threads.append(t)
        try:
            svc = self

            class H(socketserver.BaseRequestHandler):
                def handle(self):
                    data = self.request[0][:8192]
                    svc.ingest([data], source="syslog")

            self._syslog = socketserver.ThreadingUDPServer((self.cfg.bind, self.cfg.syslog_port), H)
            threading.Thread(target=self._syslog.serve_forever, name="syslog", daemon=True).start()
            log.info("syslog UDP listener on %s:%s", self.cfg.bind, self.cfg.syslog_port)
        except OSError as exc:
            log.warning("syslog listener not started: %s", exc)

    def _loop(self):
        last_purge = 0
        while not self._stop.is_set():
            try:
                if self.process_pending() == 0:
                    self._stop.wait(1.0)
                if time.time() - last_purge > 3600:
                    self.store.purge_events(self.cfg.retention_days)
                    last_purge = time.time()
            except Exception:
                log.exception("worker error")
                self._stop.wait(5.0)

    def stop(self):
        self._stop.set()
        if self._syslog:
            self._syslog.shutdown()
            self._syslog.server_close()
