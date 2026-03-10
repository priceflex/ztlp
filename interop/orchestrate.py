#!/usr/bin/env python3
"""
ZTLP Interop Test Orchestrator

Manages the Elixir relay and Rust test binary, piping commands between them.
"""

import subprocess
import sys
import os
import time
import signal

script_dir = sys.argv[1]
project_dir = sys.argv[2]
proto_dir = sys.argv[3]

relay_proc = None
rust_proc = None

def cleanup():
    for p in [rust_proc, relay_proc]:
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()

signal.signal(signal.SIGTERM, lambda *_: (cleanup(), sys.exit(1)))

try:
    # Start Elixir relay
    print("━━━ Starting Elixir relay ━━━")
    relay_proc = subprocess.Popen(
        ["elixir", os.path.join(script_dir, "relay_server.exs")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=project_dir,
        bufsize=0,
    )

    # Wait for READY <port>
    relay_port = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = relay_proc.stdout.readline().decode().strip()
        if line.startswith("READY "):
            relay_port = line.split()[1]
            break
        if relay_proc.poll() is not None:
            print(f"  ✗ Relay died. Last line: {line}")
            sys.exit(1)

    if not relay_port:
        print("  ✗ Timed out waiting for relay")
        cleanup()
        sys.exit(1)

    print(f"  Relay listening on port {relay_port}")
    print(f"  ✓ Relay running (PID {relay_proc.pid})")
    print()

    # Start Rust interop test
    print("━━━ Starting Rust interop test ━━━")
    cargo_bin = os.path.join(proto_dir, "target", "debug", "ztlp-interop-test")
    rust_proc = subprocess.Popen(
        [cargo_bin, "--relay-port", relay_port],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=proto_dir,
        bufsize=0,
    )

    # Wait for PORTS <a> <b> <sid>
    port_a = port_b = session_id = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = rust_proc.stdout.readline().decode().strip()
        if line.startswith("PORTS "):
            parts = line.split()
            port_a, port_b, session_id = parts[1], parts[2], parts[3]
            break
        if line:
            print(f"  [rust] {line}")
        if rust_proc.poll() is not None:
            print(f"  ✗ Rust binary died")
            sys.exit(1)

    if not session_id:
        print("  ✗ Timed out waiting for Rust PORTS")
        cleanup()
        sys.exit(1)

    print(f"  Node A: 127.0.0.1:{port_a}")
    print(f"  Node B: 127.0.0.1:{port_b}")
    print(f"  Session: {session_id}")
    print()

    # Register session with Elixir relay
    print("━━━ Registering session ━━━")
    cmd = f"REGISTER {session_id} {port_a} {port_b}\n"
    relay_proc.stdin.write(cmd.encode())
    relay_proc.stdin.flush()

    # Wait for OK
    deadline = time.time() + 5
    registered = False
    while time.time() < deadline:
        line = relay_proc.stdout.readline().decode().strip()
        if line.startswith("OK "):
            print(f"  ✓ Session registered with relay")
            registered = True
            break
        if line:
            print(f"  [relay] {line}")

    if not registered:
        print("  ⚠ Didn't see OK from relay, proceeding anyway")
    print()

    # Tell Rust to proceed
    print("━━━ Running tests ━━━")
    rust_proc.stdin.write(b"SESSION_REGISTERED\n")
    rust_proc.stdin.flush()

    # Read all Rust output
    while True:
        line = rust_proc.stdout.readline()
        if not line:
            break
        line = line.decode().rstrip()
        if line:
            print(f"  {line}")

    rust_proc.wait()
    exit_code = rust_proc.returncode
    print()

    if exit_code == 0:
        print("\033[0;32m╔══════════════════════════════════════════════════════════════╗\033[0m")
        print("\033[0;32m║  ✓ INTEROP TEST PASSED                                      ║\033[0m")
        print("\033[0;32m║  Rust clients communicated through Elixir relay successfully ║\033[0m")
        print("\033[0;32m╚══════════════════════════════════════════════════════════════╝\033[0m")
    else:
        print(f"\033[0;31m╔══════════════════════════════════════════════════════════════╗\033[0m")
        print(f"\033[0;31m║  ✗ INTEROP TEST FAILED (exit code: {exit_code})                        ║\033[0m")
        print(f"\033[0;31m╚══════════════════════════════════════════════════════════════╝\033[0m")

    # Clean up relay
    relay_proc.stdin.write(b"QUIT\n")
    relay_proc.stdin.flush()
    relay_proc.wait(timeout=3)

    sys.exit(exit_code)

except Exception as e:
    print(f"  ✗ Error: {e}")
    cleanup()
    sys.exit(1)
finally:
    cleanup()
