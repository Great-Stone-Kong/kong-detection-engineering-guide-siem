#!/usr/bin/env python3
"""Mock loan inquiry upstream for SIEM detection demos."""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ~100KB padding so KG-API-005 hits sum(response.size) quickly
_BULK_PAD = "X" * 100_000


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, body: dict | list) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]

        if path == "/health":
            self._send(200, {"ok": True})
            return

        # strip_path leaves "/" for exact /siem-demo/heartbeat match
        if path in ("/", "/heartbeat", "/siem-demo/heartbeat"):
            self._send(200, {"ok": True, "role": "heartbeat"})
            return

        if path in ("/info", "/open/info", "/siem-demo/loan/open/info"):
            self._send(200, {"open": True, "note": "intentional control gap for KG-API-006"})
            return

        # strip_path: /siem-demo/loan/customers/{id}/bulk → /{id}/bulk
        m_bulk = re.match(r"^/(?:customers/)?([^/]+)/bulk/?$", path)
        if m_bulk:
            cid = m_bulk.group(1)
            self._send(
                200,
                {
                    "customer_id": cid,
                    "records": [{"i": i} for i in range(5)],
                    "pad": _BULK_PAD,
                },
            )
            return

        m = re.match(r"^/(?:customers/)?([^/]+)/?$", path)
        if m and m.group(1) not in ("health", "heartbeat", "info", "open"):
            cid = m.group(1)
            self._send(
                200,
                {
                    "customer_id": cid,
                    "name": f"demo-{cid}",
                    "pii": {"account": f"ACC-{cid}"},
                },
            )
            return

        self._send(200, {"echo": "get", "path": path})

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            payload = json.loads(raw.decode() or "null")
        except json.JSONDecodeError:
            payload = raw.decode(errors="replace")
        self._send(200, {"echo": "post", "path": self.path, "body": payload})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
