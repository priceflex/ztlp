#!/usr/bin/env python3
"""Simple HTTP log receiver for ZTLP iOS diagnostics.

Listens on port 9199 and accepts POST /logs with text body.
Stores logs in ~/ztlp-logs/ with timestamps.
GET /logs returns the latest log file.
GET /logs/list returns all log files.
"""

import os
import sys
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_DIR = os.path.expanduser("~/ztlp-logs")
os.makedirs(LOG_DIR, exist_ok=True)

# [CWE-770 hfo-njyl] This receiver is unauthenticated and bound to
# 0.0.0.0, yet previously trusted the client-controlled Content-Length
# header unconditionally: `self.rfile.read(length)` with no upper bound
# let any reachable client allocate an arbitrarily large in-memory
# buffer per request and then persist that same arbitrarily large body
# to disk, with no rate limit either -- repeated large uploads could
# exhaust process memory and/or fill the filesystem hosting LOG_DIR,
# a DoS against this diagnostic service and potentially other
# applications sharing that disk.
#
# Fix: enforce a hard maximum request body size (10 MiB -- generous for
# a diagnostic text log upload, small enough that even a sustained
# flood of max-size requests can't meaningfully exhaust a modern
# server's memory or disk before an operator notices). Reject oversized
# or missing/malformed Content-Length with 413 Payload Too Large before
# ever calling rfile.read(), and read in bounded chunks rather than one
# giant read() call.
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB
READ_CHUNK_BYTES = 64 * 1024

class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/logs":
            try:
                length = int(self.headers.get("Content-Length", -1))
            except ValueError:
                length = -1

            if length < 0:
                self.send_response(411)  # Length Required
                self.end_headers()
                self.wfile.write(b"Content-Length required")
                return

            if length > MAX_BODY_BYTES:
                self.send_response(413)  # Payload Too Large
                self.end_headers()
                self.wfile.write(
                    f"Body exceeds maximum of {MAX_BODY_BYTES} bytes".encode()
                )
                return

            # Read in bounded chunks up to the (already-capped) declared
            # length -- avoids a single unbounded rfile.read() call and
            # matches the declared Content-Length exactly (no reading
            # past it even if the client keeps streaming).
            remaining = length
            chunks = []
            while remaining > 0:
                chunk = self.rfile.read(min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")

            # Save with timestamp
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            device_raw = self.headers.get("X-Device", "unknown")
            # Sanitize the device identifier before embedding it in a
            # filename: strip anything but alphanumerics/dash/underscore/dot
            # so an attacker-controlled X-Device header (e.g.
            # "../../etc/cron.d/evil") cannot traverse out of LOG_DIR on
            # write, matching the same containment guarantee as the GET
            # handler below.
            device = "".join(c for c in device_raw if c.isalnum() or c in "-_.")[:64]
            if not device:
                device = "unknown"
            filename = f"{ts}_{device}.log"
            filepath = os.path.join(LOG_DIR, filename)

            with open(filepath, "w") as f:
                f.write(body)

            print(f"[{ts}] Received {len(body)} bytes from {device} → {filename}")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "file": filename}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_GET(self):
        if self.path == "/logs/list":
            files = sorted(os.listdir(LOG_DIR), reverse=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(files).encode())
        
        elif self.path == "/logs/latest":
            files = sorted(os.listdir(LOG_DIR), reverse=True)
            if files:
                filepath = os.path.join(LOG_DIR, files[0])
                with open(filepath) as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Filename", files[0])
                self.end_headers()
                self.wfile.write(content.encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No logs yet")
        
        elif self.path.startswith("/logs/"):
            filename = self.path[6:]  # strip /logs/
            # Prevent path traversal: reject "..", absolute paths, empty names
            if ".." in filename or filename.startswith("/") or not filename:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Bad request")
                return
            filepath = os.path.join(LOG_DIR, filename)
            # Double-check resolved path stays inside LOG_DIR. Use
            # os.sep-anchored prefix (not bare startswith) to avoid the
            # classic sibling-directory bypass where e.g.
            # "/tmp/logs-evil" also startswith "/tmp/logs".
            log_dir_real = os.path.realpath(LOG_DIR)
            file_real = os.path.realpath(filepath)
            if file_real != log_dir_real and not file_real.startswith(log_dir_real + os.sep):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
            if os.path.exists(filepath):
                with open(filepath) as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(content.encode())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ZTLP Log Receiver\nPOST /logs - submit\nGET /logs/latest - latest\nGET /logs/list - all files\nGET /logs/<filename> - specific file\n")
    
    def log_message(self, format, *args):
        pass  # Suppress default access logs

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9199
    server = HTTPServer(("0.0.0.0", port), LogHandler)
    print(f"ZTLP Log Receiver listening on port {port}")
    print(f"Storing logs in {LOG_DIR}")
    server.serve_forever()
