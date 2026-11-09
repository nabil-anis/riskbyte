"""HTTP API and static console. Stdlib only. Role-based bearer tokens."""
from __future__ import annotations
import hmac, json, logging, mimetypes, os, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import ServiceError

log = logging.getLogger("riskbyte.api")
UI = os.path.join(os.path.dirname(__file__), "ui")
MAX_BODY = 1_000_000
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
ID = r"(\d+)"


def get_handler_class(svc):
    cfg = svc.cfg
    tokens = [("admin", cfg.admin_token), ("analyst", cfg.analyst_token), ("ingest", cfg.ingest_token)]

    def role_of(header: str):
        if not header.startswith("Bearer "):
            return None
        given = header[7:].strip().encode()
        found = None
        for role, tok in tokens:  # compare against all tokens so timing does not reveal which matched
            if tok and hmac.compare_digest(given, tok.encode()):
                found = found or role
        return found

    class H(BaseHTTPRequestHandler):
        server_version = "Riskbyte"
        sys_version = ""

        def log_message(self, fmt, *a):
            log.info("%s %s", self.address_string(), fmt % a)

        def _send(self, code, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, default=str).encode())

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ServiceError("body too large", 413)
            return self.rfile.read(n) if n else b""

        def _actor(self, role):
            u = re.sub(r"[^A-Za-z0-9._@-]", "", self.headers.get("X-Riskbyte-User", ""))[:64]
            return f"{role}:{u}" if u else role

        def _static(self, name):
            if name in ("", "index.html"):
                name = "index.html"
            if name not in ("index.html", "app.js", "app.css"):
                return self._json(404, {"error": "not found"})
            mimes = {
                "index.html": "text/html; charset=utf-8",
                "app.css": "text/css; charset=utf-8",
                "app.js": "application/javascript; charset=utf-8",
            }
            with open(os.path.join(UI, name), "rb") as f:
                self._send(200, f.read(), mimes.get(name, "text/plain"))

        def _route(self, method):
            raw_path = self.headers.get("x-forwarded-uri") or self.headers.get("x-matched-path") or self.path
            path = raw_path.split("?")[0]
            query = dict(p.split("=", 1) for p in (raw_path.split("?", 1) + [""])[1].split("&") if "=" in p)
            if method == "GET":
                if path == "/healthz":
                    return self._json(200, {"ok": True})
                if path in ("", "/", "/api/index.py", "/api/index"):
                    return self._static("")
                if path.startswith("/static/"):
                    return self._static(path[8:])
            role = role_of(self.headers.get("Authorization", ""))
            if not role:
                return self._json(401, {"error": "unauthorized"})
            analyst = role in ("analyst", "admin") or (cfg.dev_mode and role == "ingest" and self.headers.get("X-Riskbyte-Console") == "1")
            if method == "POST" and path == "/api/ingest":
                data = json.loads(self._body() or b"null")
                items = data.get("events") if isinstance(data, dict) and "events" in data else data
                items = items if isinstance(items, list) else [items]
                if len(items) > 1000:
                    raise ServiceError("max 1000 events per request", 413)
                accepted = svc.ingest(items, "api")
                try:
                    svc.process_pending()
                except Exception:
                    pass
                return self._json(202, {"accepted": accepted})
            if not analyst:
                return self._json(403, {"error": "forbidden"})
            if method == "GET":
                if path == "/api/alerts":
                    return self._json(200, svc.alerts(query.get("status")))
                if (m := re.fullmatch(f"/api/alerts/{ID}", path)):
                    return self._json(200, svc.alert_detail(int(m.group(1))))
                if path == "/api/cases":
                    return self._json(200, svc.store.query("SELECT * FROM cases ORDER BY id DESC LIMIT 100"))
                if path == "/api/audit":
                    return self._json(200, svc.store.query("SELECT id,ts,actor,kind,alert_id,detail FROM audit ORDER BY id DESC LIMIT 200"))
                if path == "/api/license":
                    return self._json(200, svc.license_status())
                if path == "/api/stats":
                    return self._json(200, svc.stats())
            if method == "POST":
                if (m := re.fullmatch(f"/api/alerts/{ID}/approve", path)):
                    return self._json(200, svc.approve(int(m.group(1)), self._actor(role)))
                if (m := re.fullmatch(f"/api/alerts/{ID}/dismiss", path)):
                    return self._json(200, svc.dismiss(int(m.group(1)), self._actor(role)))
            return self._json(404, {"error": "not found"})

        def _handle(self, method):
            try:
                self._route(method)
            except ServiceError as e:
                self._json(e.status, {"error": str(e)})
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "bad request"})
            except Exception:
                log.exception("unhandled error")
                self._json(500, {"error": "internal error"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return H


def make_server(svc, bind: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((bind, port), get_handler_class(svc))
