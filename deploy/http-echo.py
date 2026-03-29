#!/usr/bin/env python3
"""
ZTLP HTTP Echo Server — threaded, production-ready.

Endpoints:
  GET  /ping         → {"status":"ok","timestamp":"..."}
  GET  /health       → {"status":"healthy"}
  GET  /echo?size=N  → N bytes of response body
  GET  /download/N   → N MB download
  POST /echo         → echo back the request body with headers

Configurable via PORT env var (default: 8180).
"""

import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone


class EchoHandler(BaseHTTPRequestHandler):
    """Handle echo server requests."""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/ping":
            self._json_response(200, {
                "status": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        elif path == "/health":
            self._json_response(200, {"status": "healthy"})

        elif path == "/echo":
            size = int(params.get("size", ["0"])[0])
            body = b"X" * size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/download/"):
            try:
                mb = int(path.split("/download/")[1])
            except (ValueError, IndexError):
                self._json_response(400, {"error": "invalid size"})
                return
            total = mb * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total))
            self.end_headers()
            chunk_size = 65536
            sent = 0
            chunk = b"D" * chunk_size
            while sent < total:
                to_send = min(chunk_size, total - sent)
                self.wfile.write(chunk[:to_send])
                sent += to_send

        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/echo":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""
            headers = {k: v for k, v in self.headers.items()}
            response = {
                "method": "POST",
                "path": self.path,
                "headers": headers,
                "body_length": len(body),
                "body": body.decode("utf-8", errors="replace")
            }
            self._json_response(200, response)
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Log to stdout (captured by systemd journal)."""
        sys.stdout.write("%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args
        ))
        sys.stdout.flush()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread each."""
    daemon_threads = True


def main():
    port = int(os.environ.get("PORT", "8180"))
    server = ThreadedHTTPServer(("0.0.0.0", port), EchoHandler)
    print(f"ZTLP HTTP Echo Server listening on 0.0.0.0:{port}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
