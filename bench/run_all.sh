#!/usr/bin/env bash
# ZTLP Performance Benchmark Runner
# Run from the ztlp repo root: bash bench/run_all.sh
set -euo pipefail

ZTLP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_FILE="$ZTLP_ROOT/bench/RESULTS.md"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

echo "============================================================"
echo "  ZTLP Performance Benchmarks"
echo "  Started: $TIMESTAMP"
echo "============================================================"
echo ""

# ── System Info ──────────────────────────────────────────────────

echo "--- System Information ---"
echo ""

SYSTEM_INFO=$(cat <<EOF
## System Information

| Property | Value |
|----------|-------|
| Date | $TIMESTAMP |
| OS | $(uname -s -r -m) |
| CPU | $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "unknown") |
| CPU Cores | $(nproc 2>/dev/null || echo "unknown") |
| Memory | $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "unknown") |
| Elixir | $(cd "$ZTLP_ROOT/gateway" && mix --version 2>/dev/null | tail -1 || echo "unknown") |
| Erlang/OTP | $(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().' 2>/dev/null || echo "unknown") |
| Rust | $(rustc --version 2>/dev/null || echo "unknown") |
| Cargo | $(cargo --version 2>/dev/null || echo "unknown") |
EOF
)

echo "$SYSTEM_INFO"
echo ""

# ── Elixir Benchmarks ────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Running Elixir Benchmarks"
echo "============================================================"
echo ""

GATEWAY_PIPELINE_OUT=""
GATEWAY_HANDSHAKE_OUT=""
GATEWAY_THROUGHPUT_OUT=""
NS_OUT=""
RELAY_OUT=""

echo "--- Gateway: Pipeline ---"
cd "$ZTLP_ROOT/gateway"
GATEWAY_PIPELINE_OUT=$(mix run bench/bench_pipeline.exs 2>&1) || true
echo "$GATEWAY_PIPELINE_OUT"
echo ""

echo "--- Gateway: Handshake & Crypto ---"
cd "$ZTLP_ROOT/gateway"
GATEWAY_HANDSHAKE_OUT=$(mix run bench/bench_handshake.exs 2>&1) || true
echo "$GATEWAY_HANDSHAKE_OUT"
echo ""

echo "--- Gateway: Throughput ---"
cd "$ZTLP_ROOT/gateway"
GATEWAY_THROUGHPUT_OUT=$(mix run bench/bench_gateway.exs 2>&1) || true
echo "$GATEWAY_THROUGHPUT_OUT"
echo ""

echo "--- ZTLP-NS ---"
cd "$ZTLP_ROOT/ns"
NS_OUT=$(mix run bench/bench_ns.exs 2>&1) || true
echo "$NS_OUT"
echo ""

echo "--- Relay ---"
cd "$ZTLP_ROOT/relay"
RELAY_OUT=$(mix run bench/bench_relay.exs 2>&1) || true
echo "$RELAY_OUT"
echo ""

# ── Rust Benchmarks ──────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Running Rust Benchmarks"
echo "============================================================"
echo ""

cd "$ZTLP_ROOT/proto"
RUST_OUT=$(cargo run --release --bin ztlp-bench 2>&1) || true
echo "$RUST_OUT"
echo ""

# ── Throughput Benchmarks (GSO/GRO) ─────────────────────────────

echo ""
echo "============================================================"
echo "  Running Throughput Benchmarks (GSO/GRO)"
echo "============================================================"
echo ""

cd "$ZTLP_ROOT/proto"
THROUGHPUT_OUT=$(cargo run --release --bin ztlp-throughput -- --mode all --size 104857600 --repeat 3 2>&1) || true
echo "$THROUGHPUT_OUT"
echo ""

# ── Generate RESULTS.md ─────────────────────────────────────────

cat > "$RESULTS_FILE" <<RESULTS_EOF
# ZTLP Performance Benchmark Results

$SYSTEM_INFO

---

## Elixir Benchmarks

### Gateway: Pipeline Admission

\`\`\`
$GATEWAY_PIPELINE_OUT
\`\`\`

### Gateway: Handshake & Crypto

\`\`\`
$GATEWAY_HANDSHAKE_OUT
\`\`\`

### Gateway: Throughput

\`\`\`
$GATEWAY_THROUGHPUT_OUT
\`\`\`

### ZTLP-NS: Namespace

\`\`\`
$NS_OUT
\`\`\`

### Relay: Pipeline & Packet Processing

\`\`\`
$RELAY_OUT
\`\`\`

---

## Rust Benchmarks (Proto)

\`\`\`
$RUST_OUT
\`\`\`

---

## Throughput Benchmarks (GSO/GRO)

\`\`\`
$THROUGHPUT_OUT
\`\`\`

---

## Analysis

_Analysis will be written after benchmarks run._

RESULTS_EOF

echo ""
echo "============================================================"
echo "  Benchmarks complete!"
echo "  Results written to: $RESULTS_FILE"
echo "============================================================"
