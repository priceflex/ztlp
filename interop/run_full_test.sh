#!/usr/bin/env bash
set -euo pipefail

# ZTLP Full Cross-Language Interop Test Suite
#
# Compiles all Rust test binaries and runs the full orchestrator.
# This is the master test runner for all interop tests.
#
# Usage: bash interop/run_full_test.sh
#
# Prerequisites:
#   - Rust/Cargo installed
#   - Elixir installed
#   - All Mix projects compiled (relay, gateway, ns)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZTLP_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$ZTLP_ROOT/proto"

export PATH="$HOME/.cargo/bin:$PATH"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ZTLP Full Cross-Language Interop Test                   ║"
echo "║     Rust ↔ Elixir protocol stack verification               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# ── Step 1: Compile Rust binaries ──────────────────────────────────
echo "━━━ Compiling Rust test binaries ━━━"
cd "$PROTO_DIR"

BINS="ztlp-interop-test ztlp-handshake-interop ztlp-pipeline-interop ztlp-ns-interop ztlp-gateway-e2e ztlp-edge-cases"

for bin in $BINS; do
    echo -n "  Compiling $bin... "
    if cargo build --bin "$bin" 2>/dev/null; then
        echo "✓"
    else
        echo "✗ (compilation failed)"
        echo "Attempting with full output:"
        cargo build --bin "$bin" 2>&1 | tail -20
        exit 1
    fi
done
echo "  ✓ All binaries compiled"
echo

# ── Step 2: Compile Elixir projects ───────────────────────────────
echo "━━━ Compiling Elixir projects ━━━"
for project in relay gateway ns; do
    echo -n "  Compiling $project... "
    cd "$ZTLP_ROOT/$project"
    if mix deps.get --no-deps-check > /dev/null 2>&1 && mix compile --no-deps-check > /dev/null 2>&1; then
        echo "✓"
    else
        echo "✗"
        mix compile 2>&1 | tail -10
        exit 1
    fi
done
echo "  ✓ All Elixir projects compiled"
echo

# ── Step 3: Run the orchestrator ──────────────────────────────────
echo "━━━ Running full interop test suite ━━━"
echo
cd "$ZTLP_ROOT"
python3 "$SCRIPT_DIR/orchestrate_full.py"
exit $?
