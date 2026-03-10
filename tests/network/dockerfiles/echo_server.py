#!/usr/bin/env python3
"""
Simple TCP echo server for ZTLP gateway testing.

Accepts TCP connections on port 8080 and echoes back everything received.
Handles multiple concurrent connections via threading.
"""

import socketserver
import sys
import signal

class EchoHandler(socketserver.StreamRequestHandler):
    """Echo back each line received."""

    def handle(self):
        addr = self.client_address
        print(f"[echo] Connection from {addr[0]}:{addr[1]}", flush=True)
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                self.request.sendall(data)
                print(f"[echo] Echoed {len(data)} bytes to {addr[0]}:{addr[1]}", flush=True)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            print(f"[echo] Disconnected {addr[0]}:{addr[1]}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = "0.0.0.0"
    port = 8080

    server = ThreadedTCPServer((host, port), EchoHandler)
    print(f"[echo] TCP echo server listening on {host}:{port}", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: (server.shutdown(), sys.exit(0)))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
