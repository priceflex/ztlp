#!/usr/bin/env bash
#
# ZTLP Cross-Language Interop Test
#
# Proves Rust ZTLP clients can communicate through an Elixir relay over real UDP.
#
# Architecture:
#   1. Start Elixir relay (stdin-controlled, prints READY <port>)
#   2. Start Rust interop binary (prints PORTS <a> <b> <sid>, waits for SESSION_REGISTERED)
#   3. Send REGISTER command to relay stdin
#   4. Send SESSION_REGISTERED to Rust stdin
#   5. Rust runs 5 tests, exits 0 on success

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RELAY_DIR="$PROJECT_DIR/relay"
PROTO_DIR="$PROJECT_DIR/proto"

export PATH="$HOME/.cargo/bin:$PATH"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ZTLP Cross-Language Interop Test                        ║"
echo "║     Rust clients ↔ Elixir relay over real UDP               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Compile both
echo "━━━ Compiling ━━━"
cd "$RELAY_DIR" && mix compile --no-deps-check 2>&1 | tail -1
cd "$PROTO_DIR" && cargo build --bin ztlp-interop-test 2>&1 | tail -1
echo "  ✓ Both projects compiled"
echo

# Use Python to orchestrate the subprocess dance
exec python3 "$SCRIPT_DIR/orchestrate.py" "$SCRIPT_DIR" "$PROJECT_DIR" "$PROTO_DIR"
