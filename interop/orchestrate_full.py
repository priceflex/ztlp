#!/usr/bin/env python3
"""
ZTLP Full Interop Test Orchestrator

Starts Elixir test servers, runs Rust test binaries, collects results.

Test Suites:
1. Noise_XX Handshake (Rust snow ↔ Elixir :crypto)
2. Pipeline Header Validation (magic, session, auth tag)
3. Edge Cases (truncation, MTU, bursts, etc.)
4. Gateway End-to-End (handshake + data + TCP backend echo)
5. Original Relay Forwarding (backward compat)
"""

import subprocess
import sys
import os
import time
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ZTLP_ROOT = os.path.dirname(SCRIPT_DIR)
PROTO_DIR = os.path.join(ZTLP_ROOT, "proto")
RUST_TARGET_DIR = os.path.join(PROTO_DIR, "target", "debug")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
RESET = "\033[0m"

def print_header(title):
    print(f"\n{CYAN}{'━' * 60}")
    print(f"  {title}")
    print(f"{'━' * 60}{RESET}")

def start_elixir_server(script_name, mix_project=None, port_key=None):
    """Start an Elixir test server. Returns (process, port) or (None, None)."""
    script_path = os.path.join(SCRIPT_DIR, script_name)

    if mix_project:
        project_dir = os.path.join(ZTLP_ROOT, mix_project)
        cmd = ["mix", "run", "--no-halt", script_path]
        working_dir = project_dir
    else:
        cmd = ["elixir", script_path]
        working_dir = SCRIPT_DIR

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=working_dir,
        env={**os.environ, "PATH": os.path.expanduser("~/.cargo/bin") + ":" + os.environ.get("PATH", "")},
    )

    if port_key is None:
        port_key = "_PORT="

    port = None
    start_time = time.time()
    while time.time() - start_time < 15:
        line = proc.stdout.readline().decode("utf-8").strip()
        if line:
            print(f"    [{script_name}] {line}")
            match = re.search(rf'{re.escape(port_key)}(\d+)', line)
            if match:
                port = int(match.group(1))
                break

    if port is None:
        print(f"  {RED}✗ Failed to start {script_name} (no port detected){RESET}")
        proc.kill()
        # Print stderr for debugging
        try:
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            if stderr.strip():
                for line in stderr.strip().split("\n")[:10]:
                    print(f"    [stderr] {line}")
        except:
            pass
        return None, None

    return proc, port

def run_rust_binary(binary_name, *args):
    """Run a Rust test binary. Returns (passed, failed, output)."""
    binary_path = os.path.join(RUST_TARGET_DIR, binary_name)
    if not os.path.exists(binary_path):
        return 0, 1, f"Binary not found: {binary_path}"

    try:
        result = subprocess.run(
            [binary_path] + list(args),
            capture_output=True, text=True, timeout=30, cwd=PROTO_DIR,
        )
        output = result.stdout + result.stderr

        passed = 0
        failed = 0
        for line in output.split("\n"):
            if "Results:" in line:
                match = re.search(r'(\d+) passed, (\d+) failed', line)
                if match:
                    passed = int(match.group(1))
                    failed = int(match.group(2))
                    break

        return passed, failed, output

    except subprocess.TimeoutExpired:
        return 0, 1, "TIMEOUT"
    except Exception as e:
        return 0, 1, str(e)

def cleanup(procs):
    for proc in procs:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()

def run_suite(suite_name, server_script, binary_name, mix_project=None, port_key=None):
    """Run a single test suite. Returns (passed, failed, procs)."""
    print_header(suite_name)
    print(f"  Starting {server_script}...")

    proc, port = start_elixir_server(server_script, mix_project=mix_project, port_key=port_key)
    if proc is None:
        return 0, 1, []

    time.sleep(0.5)

    server_addr = f"127.0.0.1:{port}"
    print(f"  Running {binary_name} → {server_addr}")

    passed, failed, output = run_rust_binary(binary_name, server_addr)

    for line in output.strip().split("\n"):
        line = line.strip()
        if line:
            print(f"    {line}")

    return passed, failed, [proc]


def main():
    total_passed = 0
    total_failed = 0
    all_procs = []

    print(f"""
{GREEN}╔══════════════════════════════════════════════════════════════╗
║     ZTLP Full Cross-Language Interop Test Suite              ║
║     Rust ↔ Elixir — Handshake, Pipeline, Gateway, E2E       ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

    try:
        # ── Suite 1: Handshake ─────────────────────────────────────
        p, f, procs = run_suite(
            "Suite 1: Noise_XX Handshake Interop",
            "handshake_server.exs",
            "ztlp-handshake-interop",
            mix_project="gateway",
            port_key="HANDSHAKE_SERVER_PORT=",
        )
        total_passed += p; total_failed += f
        all_procs.extend(procs)
        cleanup(procs)

        # ── Suite 2: Pipeline ──────────────────────────────────────
        p, f, procs = run_suite(
            "Suite 2: Pipeline Header Validation",
            "pipeline_server.exs",
            "ztlp-pipeline-interop",
            port_key="PIPELINE_SERVER_PORT=",
        )
        total_passed += p; total_failed += f
        all_procs.extend(procs)
        cleanup(procs)

        # ── Suite 3: Edge Cases ────────────────────────────────────
        p, f, procs = run_suite(
            "Suite 3: Edge Cases & Error Handling",
            "pipeline_server.exs",
            "ztlp-edge-cases",
            port_key="PIPELINE_SERVER_PORT=",
        )
        total_passed += p; total_failed += f
        all_procs.extend(procs)
        cleanup(procs)

        # ── Suite 4: Gateway E2E ───────────────────────────────────
        p, f, procs = run_suite(
            "Suite 4: Gateway End-to-End",
            "gateway_test_server.exs",
            "ztlp-gateway-e2e",
            mix_project="gateway",
            port_key="GATEWAY_TEST_PORT=",
        )
        total_passed += p; total_failed += f
        all_procs.extend(procs)
        cleanup(procs)

        # ── Suite 5: Original relay tests ──────────────────────────
        print_header("Suite 5: Original Relay Forwarding (backward compat)")
        print(f"  Running existing run_test.sh...")
        try:
            result = subprocess.run(
                ["bash", os.path.join(SCRIPT_DIR, "run_test.sh")],
                capture_output=True, text=True, timeout=60, cwd=ZTLP_ROOT,
                env={**os.environ, "PATH": os.path.expanduser("~/.cargo/bin") + ":" + os.environ.get("PATH", "")},
            )
            output = result.stdout + result.stderr
            for line in output.strip().split("\n"):
                if line.strip():
                    print(f"    {line.strip()}")

            s5p, s5f = 0, 0
            for line in output.split("\n"):
                if "Results:" in line:
                    m = re.search(r'(\d+) passed, (\d+) failed', line)
                    if m:
                        s5p = int(m.group(1)); s5f = int(m.group(2))
                        break
            total_passed += s5p; total_failed += s5f
        except Exception as e:
            print(f"  {RED}✗ Original test failed: {e}{RESET}")
            total_failed += 1

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted{RESET}")
    finally:
        cleanup(all_procs)

    # ── Summary ────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  TOTAL: {total_passed} passed, {total_failed} failed")
    print(f"{'═' * 60}")

    if total_failed == 0:
        print(f"""
{GREEN}╔══════════════════════════════════════════════════════════════╗
║  ✓ ALL INTEROP TESTS PASSED                                 ║
║  Full Rust ↔ Elixir protocol stack verified                  ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
        return 0
    else:
        print(f"""
{RED}╔══════════════════════════════════════════════════════════════╗
║  ✗ SOME TESTS FAILED ({total_failed} failures)                           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
        return 1


if __name__ == "__main__":
    sys.exit(main())
