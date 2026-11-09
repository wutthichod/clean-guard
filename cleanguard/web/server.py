"""HTTP layer of the web app. Standard library only.

This server can move files, so requests from other websites must not reach it:
- binds to 127.0.0.1 only; there is no option to expose it
- the Host header must be this server, which stops DNS rebinding
- /api needs a per-start token that only this page knows (it is not in the URL, and a site on
  another origin cannot read the page), and POST also needs JSON and a matching Origin
- responses carry a strict CSP, and the page loads nothing from outside this server
"""
from __future__ import annotations

import hmac
import json
import re
import secrets
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .chat import Chat
from .service import Service, ServiceError

STATIC = Path(__file__).parent / "static"
ASSETS = {"/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/static/style.css": ("style.css", "text/css; charset=utf-8")}
MAX_BODY = 1024 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class App:
    def __init__(self, service: Service):
        self.service, self.chat = service, Chat(service)
        self.token = secrets.token_urlsafe(32)
        self.routes = [
            ("GET", r"/api/status", lambda m, q, b: service.status()),
            ("GET", r"/api/browse", lambda m, q, b: service.browse(q.get("path"))),
            ("GET", r"/api/runs", lambda m, q, b: {"runs": service.list_runs()}),
            ("POST", r"/api/scan", lambda m, q, b: service.start_scan(b.get("folder", ""), bool(b.get("dry_run")))),
            ("GET", r"/api/runs/([^/]+)", lambda m, q, b: service.run_detail(m[1])),
            ("POST", r"/api/runs/([^/]+)/resume", lambda m, q, b: service.resume(m[1])),
            ("POST", r"/api/runs/([^/]+)/move", lambda m, q, b: service.move(
                m[1], b.get("file_ids"), b.get("confirm", ""), b.get("sensitive_confirm", ""))),
            ("GET", r"/api/runs/([^/]+)/files/([^/]+)/preview", lambda m, q, b: service.preview(m[1], m[2])),
            ("POST", r"/api/runs/([^/]+)/files/([^/]+)/reveal", lambda m, q, b: service.reveal(m[1], m[2])),
            ("GET", r"/api/quarantine", lambda m, q, b: service.list_quarantine()),
            ("POST", r"/api/quarantine/([^/]+)/restore", lambda m, q, b: service.restore(m[1])),
            ("POST", r"/api/chat", lambda m, q, b: self.chat.ask(b.get("message", ""), b.get("run_id"))),
            ("POST", r"/api/chat/reset", lambda m, q, b: self._reset_chat(b.get("run_id"))),
        ]

    def _reset_chat(self, run_id):
        self.chat.reset(run_id)
        return {"ok": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "CleanGuard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app

    def log_message(self, *args):         # paths and queries can hold folder names: log nothing
        pass

    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _fail(self, status: int, message: str, kind: str = "error") -> None:
        self._json(status, {"error": message, "kind": kind})

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self._allowed_hosts()

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or origin in {f"http://{h}" for h in self._allowed_hosts()}

    def _token_ok(self) -> bool:
        return hmac.compare_digest(self.headers.get("X-CleanGuard-Token", ""), self.app.token)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            raise ServiceError(413, "Request too large.")
        raw = self.rfile.read(n) if n else b"{}"
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ServiceError(415, "Send JSON.")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ServiceError(400, "Send valid JSON.") from None
        if not isinstance(body, dict):
            raise ServiceError(400, "Send a JSON object.")
        return body

    def _serve_page(self, path: str) -> None:
        if path == "/":
            page = (STATIC / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", self.app.token)
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
        elif path in ASSETS:
            name, ctype = ASSETS[path]
            self._send(200, (STATIC / name).read_bytes(), ctype)
        else:
            self._fail(404, "Not found.")

    def _api(self, method: str, parsed) -> None:
        if not self._token_ok():
            return self._fail(403, "Reload the page: this session is not valid.")
        if method == "POST" and not self._origin_ok():
            return self._fail(403, "This request came from another site.")
        path = unquote(parsed.path)
        for m, pattern, fn in self.app.routes:
            match = re.fullmatch(pattern, path) if m == method else None
            if not match:
                continue
            try:
                body = self._read_json() if method == "POST" else {}
                query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                return self._json(200, fn(match, query, body))
            except ServiceError as e:
                return self._fail(e.status, e.message, e.kind)
            except Exception as e:  # noqa: BLE001 - never show a stack trace or a path
                return self._fail(500, f"Something went wrong ({type(e).__name__}). Nothing was moved.")
        self._fail(404, "Not found.")

    def _dispatch(self, method: str) -> None:
        if not self._host_ok():
            return self._fail(403, "Wrong host.")
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self._api(method, parsed)
        if method == "GET":
            return self._serve_page(parsed.path)
        self._fail(405, "Not allowed.")

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app: App, port: int = 0):
        self.app = app
        super().__init__(("127.0.0.1", port), Handler)     # loopback only, by design


def serve(cfg, port: int = 8765, open_browser: bool = True) -> int:
    app = App(Service(cfg))
    try:
        srv = Server(app, port)
    except OSError:
        print(f"Port {port} is in use. Try: python -m cleanguard ui --port {port + 1}")
        return 2
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"CleanGuard is running at {url}")
    print(app.service.status()["offline_line"])
    print("Press Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.server_close()
    return 0
