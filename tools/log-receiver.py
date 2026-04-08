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

class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/logs":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            
            # Save with timestamp
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            device = self.headers.get("X-Device", "unknown")
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
            filepath = os.path.join(LOG_DIR, filename)
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
            self.wfile.write(b"ZTLP Log Receiver\nPOST /logs - submit\nGET /logs/latest - latest\nGET /logs/list - all files\n")
    
    def log_message(self, format, *args):
        pass  # Suppress default access logs

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9199
    server = HTTPServer(("0.0.0.0", port), LogHandler)
    print(f"ZTLP Log Receiver listening on port {port}")
    print(f"Storing logs in {LOG_DIR}")
    server.serve_forever()
