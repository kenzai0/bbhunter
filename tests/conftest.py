"""Testler icin yerel (127.0.0.1) sahte HTTP sunucusu. Internete hic istek atilmaz."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# path -> (status, headers, body). Testler bu tabloyu doldurur.
ROUTES: dict[str, tuple[int, dict, bytes]] = {}
SEEN: list[tuple[str, str, dict]] = []   # (method, path, headers)


class _Handler(BaseHTTPRequestHandler):
    def _serve(self):
        SEEN.append((self.command, self.path, dict(self.headers)))
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        status, headers, body = ROUTES.get(self.path, (404, {}, b"not found"))
        if callable(body):
            body = body(self)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = _serve

    def log_message(self, *a):  # sessiz
        pass


@pytest.fixture()
def server():
    ROUTES.clear()
    SEEN.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", ROUTES, SEEN
    srv.shutdown()
