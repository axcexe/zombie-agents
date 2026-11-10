"""Tiny JSON-over-HTTP server and client on the standard library. Each service binds an ephemeral port."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Service:
    def __init__(self, name: str):
        self.name = name
        self.routes: dict[tuple[str, str], callable] = {}
        self._httpd: ThreadingHTTPServer | None = None

    def route(self, method: str, path: str):
        def deco(fn):
            self.routes[(method, path)] = fn
            return fn
        return deco

    def start(self) -> str:
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):  # silence per-request logging
                pass

            def _handle(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    body = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    body = {}
                fn = routes.get((method, self.path.split("?")[0]))
                if fn is None:
                    status, payload = 404, {"error": "not_found"}
                else:
                    try:
                        status, payload = fn(body, self.headers)
                    except Exception as e:  # noqa: BLE001
                        status, payload = 500, {"error": "server_error", "detail": f"{type(e).__name__}: {e}"}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        threading.Thread(target=self._httpd.serve_forever, daemon=True, name=self.name).start()
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def call(method: str, url: str, body: dict | None = None, bearer: str | None = None,
         timeout: float = 5) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except json.JSONDecodeError:
            return e.code, {}
