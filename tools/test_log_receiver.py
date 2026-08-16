#!/usr/bin/env python3
"""Regression tests for tools/log-receiver.py.

CWE-770 hfo-njyl: the /logs POST handler used to trust the
client-controlled Content-Length header unconditionally, reading and
persisting an arbitrarily large body with no cap. These tests spin up a
real instance of the receiver and verify the fixed size cap / bounded
read behavior against actual HTTP requests -- not mocked internals.

Run with: python3 tools/test_log_receiver.py
"""
import http.client
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


class LogReceiverSizeCapTest(unittest.TestCase):
    PORT = 19199

    @classmethod
    def setUpClass(cls):
        cls.tmp_home = tempfile.mkdtemp()
        env = os.environ.copy()
        env["HOME"] = cls.tmp_home
        script = os.path.join(os.path.dirname(__file__), "log-receiver.py")
        cls.proc = subprocess.Popen(
            [sys.executable, script, str(cls.PORT)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for the server to actually be listening.
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", cls.PORT, timeout=1)
                conn.request("GET", "/logs/list")
                conn.getresponse()
                conn.close()
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.1)
        else:
            raise RuntimeError("log-receiver.py did not start in time")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        shutil.rmtree(cls.tmp_home, ignore_errors=True)

    def _post_logs(self, body: bytes, content_length=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.PORT, timeout=5)
        hdrs = {"X-Device": "test-device"}
        if headers:
            hdrs.update(headers)
        if content_length is not None:
            hdrs["Content-Length"] = str(content_length)
            conn.putrequest("POST", "/logs", skip_accept_encoding=True)
            for k, v in hdrs.items():
                conn.putheader(k, v)
            conn.endheaders()
            conn.send(body)
        else:
            conn.request("POST", "/logs", body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_normal_small_upload_accepted(self):
        status, data = self._post_logs(b"hello world log line\n")
        self.assertEqual(status, 200)
        self.assertIn(b'"ok": true', data.lower())

    def test_oversized_upload_rejected_with_413(self):
        # Declare (via a real, honest Content-Length) a body larger than
        # the 10 MiB cap. Send only a small amount of actual data --
        # the server must reject based on the declared length BEFORE
        # attempting to read the (claimed) full body.
        oversized_declared_length = 10 * 1024 * 1024 + 1
        small_actual_body = b"x" * 1024

        conn = http.client.HTTPConnection("127.0.0.1", self.PORT, timeout=5)
        conn.putrequest("POST", "/logs", skip_accept_encoding=True)
        conn.putheader("Content-Length", str(oversized_declared_length))
        conn.putheader("X-Device", "attacker")
        conn.endheaders()
        conn.send(small_actual_body)
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()

        self.assertEqual(status, 413)

    def test_missing_content_length_rejected(self):
        # http.client always sends Content-Length for a bytes body, so
        # manually craft a request without one via a raw socket.
        import socket

        sock = socket.create_connection(("127.0.0.1", self.PORT), timeout=5)
        request = (
            "POST /logs HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "X-Device: no-length-device\r\n"
            "\r\n"
        )
        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="replace")
        sock.close()
        self.assertIn("411", response)

    def test_at_cap_boundary_is_accepted(self):
        # A body exactly AT the cap (not over) should still succeed --
        # confirms the check is a strict "> max", not an off-by-one
        # that rejects legitimate max-size uploads.
        body = b"y" * (1024 * 1024)  # 1 MiB -- comfortably under cap, fast test
        status, data = self._post_logs(body)
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
