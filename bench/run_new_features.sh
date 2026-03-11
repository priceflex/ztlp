#!/usr/bin/env bash
# ZTLP New Feature Benchmarks Runner
# Run from the ztlp repo root: bash bench/run_new_features.sh
set -euo pipefail

ZTLP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

echo "============================================================"
echo "  ZTLP New Feature Benchmarks"
echo "  Started: $TIMESTAMP"
echo "============================================================"
echo ""

# ── System Info ──────────────────────────────────────────────────

echo "--- System Information ---"
echo ""
echo "Date:       $TIMESTAMP"
echo "OS:         $(uname -s -r -m)"
echo "CPU:        $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo 'unknown')"
echo "CPU Cores:  $(nproc 2>/dev/null || echo 'unknown')"
echo "Memory:     $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo 'unknown')"
echo "Elixir:     $(elixir --version 2>/dev/null | tail -1 || echo 'unknown')"
echo "Erlang/OTP: $(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().' 2>/dev/null || echo 'unknown')"
echo "Rust:       $(rustc --version 2>/dev/null || echo 'not available')"
echo ""

# ── Relay Benchmarks ─────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Relay: Backpressure, Component Auth, Mesh, Metrics"
echo "============================================================"
echo ""

cd "$ZTLP_ROOT/relay"
RELAY_OUT=$(mix run -e "ZtlpRelay.Bench.run()" 2>&1) || true
echo "$RELAY_OUT"
echo ""

# ── Gateway Benchmarks ───────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Gateway: Circuit Breaker, Component Auth, Identity"
echo "============================================================"
echo ""

cd "$ZTLP_ROOT/gateway"
GATEWAY_OUT=$(mix run -e "ZtlpGateway.Bench.run()" 2>&1) || true
echo "$GATEWAY_OUT"
echo ""

# ── NS Benchmarks ───────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  NS: Rate Limiter, Anti-Entropy, Replication, Auth"
echo "============================================================"
echo ""

cd "$ZTLP_ROOT/ns"
NS_OUT=$(ZTLP_NS_STORAGE_MODE=ram mix run -e "ZtlpNs.Bench.run()" 2>&1) || true
echo "$NS_OUT"
echo ""

# ── Rust note ────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Rust Benchmarks"
echo "============================================================"
echo ""
if command -v cargo &>/dev/null; then
  echo "Cargo available — Rust benchmarks would run here"
else
  echo "Rust benchmarks unavailable (no cargo)"
fi
echo ""

echo "============================================================"
echo "  New feature benchmarks complete!"
echo "  Timestamp: $(date -u +"%Y-%m-%d %H:%M UTC")"
echo "============================================================"
