#!/usr/bin/env python3
"""
ZTLP HTTP Echo Server — lightweight benchmark target.

Endpoints:
  GET  /ping              → {"ok":true,"ts":<unix_ms>}
  GET  /echo?size=<bytes> → random payload of given size
  POST /echo              → echoes the request body back
  GET  /download/<mb>     → streams <mb> megabytes of data
  POST /upload            → consumes body, returns {"bytes":<n>,"ms":<t>}
  GET  /health            → 200 OK
  GET  /stats             → server-side request count + bytes served

Runs on port 8080 by default (HTTP_PORT env).
Zero dependencies beyond Python 3.8+ stdlib.
"""

import http.server
import json
import os
import random
import time
import threading

PORT = int(os.environ.get("HTTP_PORT", "8080"))

# Server stats
stats = {"requests": 0, "bytes_sent": 0, "bytes_received": 0, "start_time": time.time()}
stats_lock = threading.Lock()


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler for benchmark endpoints."""

    def log_message(self, format, *args):
        # Suppress default logging for benchmarks
        pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Server-Time", str(int(time.time() * 1000)))
        self.end_headers()
        self.wfile.write(body)
        with stats_lock:
            stats["bytes_sent"] += len(body)

    def _send_data(self, data, content_type="application/octet-stream"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Server-Time", str(int(time.time() * 1000)))
        self.end_headers()
        self.wfile.write(data)
        with stats_lock:
            stats["bytes_sent"] += len(data)

    def do_GET(self):
        with stats_lock:
            stats["requests"] += 1

        if self.path == "/ping":
            self._send_json({"ok": True, "ts": int(time.time() * 1000)})

        elif self.path == "/health":
            self._send_json({"status": "healthy"})

        elif self.path.startswith("/echo"):
            # Parse size from query string
            size = 0
            if "?" in self.path:
                params = dict(p.split("=", 1) for p in self.path.split("?", 1)[1].split("&") if "=" in p)
                size = min(int(params.get("size", "0")), 100 * 1024 * 1024)  # Cap at 100MB
            if size > 0:
                self._send_data(os.urandom(size))
            else:
                self._send_json({"echo": True, "method": "GET", "path": self.path})

        elif self.path.startswith("/download/"):
            try:
                mb = int(self.path.split("/download/")[1])
                mb = min(mb, 100)  # Cap at 100MB
            except (ValueError, IndexError):
                self._send_json({"error": "use /download/<mb>"}, status=400)
                return

            total = mb * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total))
            self.send_header("X-Transfer-Size-MB", str(mb))
            self.end_headers()

            # Stream in 64KB chunks
            chunk_size = 65536
            chunk = os.urandom(chunk_size)  # Reuse same random chunk
            sent = 0
            while sent < total:
                to_send = min(chunk_size, total - sent)
                self.wfile.write(chunk[:to_send])
                sent += to_send
            with stats_lock:
                stats["bytes_sent"] += total

        elif self.path == "/stats":
            with stats_lock:
                uptime = time.time() - stats["start_time"]
                self._send_json({
                    "requests": stats["requests"],
                    "bytes_sent": stats["bytes_sent"],
                    "bytes_received": stats["bytes_received"],
                    "uptime_s": round(uptime, 1),
                })

        else:
            self._send_json({"error": "not found", "endpoints": [
                "/ping", "/echo?size=N", "/download/<mb>", "/upload", "/health", "/stats"
            ]}, status=404)

    def do_POST(self):
        with stats_lock:
            stats["requests"] += 1

        content_length = int(self.headers.get("Content-Length", 0))

        if self.path == "/echo":
            start = time.time()
            body = self.rfile.read(content_length) if content_length > 0 else b""
            with stats_lock:
                stats["bytes_received"] += len(body)
            # Echo body back
            self._send_data(body, self.headers.get("Content-Type", "application/octet-stream"))

        elif self.path == "/upload":
            start = time.time()
            received = 0
            while received < content_length:
                chunk = self.rfile.read(min(65536, content_length - received))
                if not chunk:
                    break
                received += len(chunk)
            elapsed_ms = (time.time() - start) * 1000
            with stats_lock:
                stats["bytes_received"] += received
            self._send_json({
                "bytes": received,
                "ms": round(elapsed_ms, 2),
                "throughput_mbps": round(received * 8 / (elapsed_ms / 1000) / 1_000_000, 2) if elapsed_ms > 0 else 0,
            })

        else:
            self._send_json({"error": "POST to /echo or /upload"}, status=404)


def main():
    server = http.server.ThreadedHTTPServer(("0.0.0.0", PORT), EchoHandler)
    print(f"═══════════════════════════════════════════════════════")
    print(f"  ZTLP HTTP Echo Server")
    print(f"  Listening on port {PORT}")
    print(f"  Endpoints: /ping /echo /download/<mb> /upload /health /stats")
    print(f"═══════════════════════════════════════════════════════")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
