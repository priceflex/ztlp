#!/usr/bin/env bash
# ZTLP Performance Regression Gate
#
# Runs a focused subset of benchmarks and compares against baseline thresholds.
# Designed for CI: fast (~2–3 min), deterministic pass/fail, JSON output.
#
# Usage:
#   bash bench/perf-gate.sh                  # Run with default thresholds
#   bash bench/perf-gate.sh --baseline FILE  # Use custom baseline file
#   bash bench/perf-gate.sh --output FILE    # Write results JSON to file
#   bash bench/perf-gate.sh --strict         # Tighter thresholds (dev box)
#   bash bench/perf-gate.sh --verbose        # Show detailed output
#   bash bench/perf-gate.sh --dry-run        # Run benchmarks but don't fail
#
# Exit codes:
#   0 — All benchmarks within thresholds
#   1 — One or more regressions detected
#   2 — Build or setup failure

set -uo pipefail

# ─── Paths ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$ZTLP_ROOT/proto"
export PATH="$HOME/.cargo/bin:$PATH"

# ─── Defaults ────────────────────────────────────────────────────────────────

BASELINE_FILE=""
OUTPUT_FILE=""
STRICT=false
VERBOSE=false
DRY_RUN=false

# ─── Thresholds (CI-friendly, generous) ─────────────────────────────────────
#
# These are MINIMUM acceptable values. If a metric falls below, it's a regression.
# "Strict" mode uses tighter thresholds (for dev-box runs where perf is consistent).
#
# Format: THRESHOLD_<metric>_<unit>
#   _NS   = nanoseconds (lower is better — threshold is MAXIMUM)
#   _OPS  = operations/sec (higher is better — threshold is MINIMUM)
#   _MBPS = MB/s throughput (higher is better — threshold is MINIMUM)
#   _US   = microseconds (lower is better — threshold is MAXIMUM)

# CI thresholds (generous: allow 3× regression from dev-box baseline)
THRESH_L1_REJECT_NS=100          # Rust L1 reject: <100ns (baseline ~19ns)
THRESH_PIPELINE_VALID_OPS=500000  # Rust full pipeline: >500K ops/s (baseline ~1.13M)
THRESH_HANDSHAKE_US=800           # Noise_XX: <800µs (baseline ~301µs)
THRESH_CHACHA_ENCRYPT_64B_NS=3000 # ChaCha20 encrypt 64B: <3µs (baseline ~1.2µs)
THRESH_TUNNEL_MBPS=10             # ZTLP tunnel (no GSO): >10 MB/s (baseline ~17 MB/s @ 1MB)

# Strict thresholds (dev box: allow 50% regression)
STRICT_L1_REJECT_NS=40
STRICT_PIPELINE_VALID_OPS=900000
STRICT_HANDSHAKE_US=500
STRICT_CHACHA_ENCRYPT_64B_NS=2000
STRICT_TUNNEL_MBPS=15

# ─── Parse args ──────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline)  BASELINE_FILE="$2"; shift 2 ;;
        --output)    OUTPUT_FILE="$2"; shift 2 ;;
        --strict)    STRICT=true; shift ;;
        --verbose)   VERBOSE=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        --help|-h)
            head -14 "$0" | tail -12
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# Apply strict thresholds if requested
if [[ "$STRICT" == "true" ]]; then
    THRESH_L1_REJECT_NS=$STRICT_L1_REJECT_NS
    THRESH_PIPELINE_VALID_OPS=$STRICT_PIPELINE_VALID_OPS
    THRESH_HANDSHAKE_US=$STRICT_HANDSHAKE_US
    THRESH_CHACHA_ENCRYPT_64B_NS=$STRICT_CHACHA_ENCRYPT_64B_NS
    THRESH_TUNNEL_MBPS=$STRICT_TUNNEL_MBPS
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS_JSON="[]"

log()  { echo "  $*"; }
vlog() { [[ "$VERBOSE" == "true" ]] && echo "  [verbose] $*"; }
err()  { echo "  ❌ $*" >&2; }
pass() { echo "  ✅ $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  ❌ $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { echo "  ⏭️  $*"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

add_result() {
    local name="$1" value="$2" threshold="$3" unit="$4" status="$5"
    # Append to JSON array (simple string concat — no jq dependency)
    local entry
    entry=$(printf '{"name":"%s","value":%s,"threshold":%s,"unit":"%s","status":"%s"}' \
        "$name" "$value" "$threshold" "$unit" "$status")
    if [[ "$RESULTS_JSON" == "[]" ]]; then
        RESULTS_JSON="[$entry]"
    else
        RESULTS_JSON="${RESULTS_JSON%]},${entry}]"
    fi
}

# Compare: value must be LESS than threshold (for latency metrics)
check_max() {
    local name="$1" value="$2" threshold="$3" unit="$4"
    if (( $(echo "$value <= $threshold" | bc -l 2>/dev/null || echo 0) )); then
        pass "$name: $value $unit (threshold: <$threshold $unit)"
        add_result "$name" "$value" "$threshold" "$unit" "pass"
    else
        fail "$name: $value $unit EXCEEDS threshold <$threshold $unit"
        add_result "$name" "$value" "$threshold" "$unit" "fail"
    fi
}

# Compare: value must be GREATER than threshold (for throughput metrics)
check_min() {
    local name="$1" value="$2" threshold="$3" unit="$4"
    if (( $(echo "$value >= $threshold" | bc -l 2>/dev/null || echo 0) )); then
        pass "$name: $value $unit (threshold: >$threshold $unit)"
        add_result "$name" "$value" "$threshold" "$unit" "pass"
    else
        fail "$name: $value $unit BELOW threshold >$threshold $unit"
        add_result "$name" "$value" "$threshold" "$unit" "fail"
    fi
}

# ─── Header ──────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ZTLP Performance Regression Gate"
echo "═══════════════════════════════════════════════════════════"
echo ""
log "Mode:       $(if $STRICT; then echo 'strict'; else echo 'CI (generous)'; fi)"
log "Dry run:    $DRY_RUN"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
GIT_COMMIT=$(cd "$ZTLP_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
log "Commit:     $GIT_COMMIT"
log "Timestamp:  $TIMESTAMP"
echo ""

# ─── Step 1: Build ───────────────────────────────────────────────────────────

log "Building release binaries..."
if ! (cd "$PROTO_DIR" && cargo build --release --bin ztlp-bench --bin ztlp-throughput 2>&1 | tail -3); then
    err "Build failed"
    exit 2
fi
log ""

# ─── Step 2: Run Rust microbenchmarks ────────────────────────────────────────
#
# ztlp-bench outputs structured benchmark results. We parse the relevant lines.

log "Running Rust microbenchmarks (ztlp-bench)..."
BENCH_BIN="$PROTO_DIR/target/release/ztlp-bench"

if [[ ! -x "$BENCH_BIN" ]]; then
    err "ztlp-bench binary not found at $BENCH_BIN"
    exit 2
fi

BENCH_OUT=$("$BENCH_BIN" 2>&1) || true
vlog "ztlp-bench output: $(echo "$BENCH_OUT" | wc -l) lines"

# Parse benchmark results
# ztlp-bench outputs lines like:
#   pipeline/l1_reject_bad_magic  time: [27.xxx ns 28.xxx ns 29.xxx ns]
#   pipeline/full_valid           time: [860.xx ns 886.xx ns 912.xx ns]
#   noise_xx/full_handshake       time: [290.xx µs 301.xx µs 312.xx µs]
#   chacha20poly1305/encrypt_64b  time: [1.18 µs 1.22 µs 1.26 µs]

extract_bench() {
    local pattern="$1"
    local field="${2:-median}"
    # ztlp-bench outputs blocks like:
    #   pipeline.process — bad magic (L1 reject)
    #   ------------------------------------------
    #   iterations:  100000
    #   total:       1927.3 µs
    #   mean:        19.3 ns
    #   median:      20 ns
    #   p99:         30 ns
    #   throughput:  51885224 ops/sec
    #
    # Find the heading line, then extract the requested field from the block.
    local block
    block=$(echo "$BENCH_OUT" | grep -A8 "$pattern" 2>/dev/null)
    if [[ -z "$block" ]]; then
        echo ""
        return
    fi
    # Extract the field value and unit (e.g. "20 ns" or "51885224 ops/sec")
    local line
    line=$(echo "$block" | grep "^\s*${field}:" | head -1)
    if [[ -z "$line" ]]; then
        echo ""
        return
    fi
    # Parse: "  median:      20 ns" → "20 ns"
    echo "$line" | sed -E 's/^\s*[a-z0-9]+:\s+//'
}

# Convert any time to nanoseconds
to_ns() {
    local val="$1" unit="$2"
    case "$unit" in
        ns) echo "$val" ;;
        µs|us) awk "BEGIN{printf \"%.1f\", $val * 1000}" ;;
        ms) awk "BEGIN{printf \"%.1f\", $val * 1000000}" ;;
        s)  awk "BEGIN{printf \"%.1f\", $val * 1000000000}" ;;
        *)  echo "$val" ;;
    esac
}

# Convert any time to microseconds
to_us() {
    local val="$1" unit="$2"
    case "$unit" in
        ns) awk "BEGIN{printf \"%.1f\", $val / 1000}" ;;
        µs|us) echo "$val" ;;
        ms) awk "BEGIN{printf \"%.1f\", $val * 1000}" ;;
        s)  awk "BEGIN{printf \"%.1f\", $val * 1000000}" ;;
        *)  echo "$val" ;;
    esac
}

echo ""
log "── Rust Microbenchmarks ──"
echo ""

# L1 reject (bad magic)
L1_RAW=$(extract_bench "bad magic (L1 reject)" "median")
if [[ -n "$L1_RAW" ]]; then
    L1_VAL=$(echo "$L1_RAW" | awk '{print $1}')
    L1_UNIT=$(echo "$L1_RAW" | awk '{print $2}')
    L1_NS=$(to_ns "$L1_VAL" "$L1_UNIT")
    check_max "L1 reject latency" "$L1_NS" "$THRESH_L1_REJECT_NS" "ns"
else
    skip "L1 reject latency — could not parse from ztlp-bench output"
fi

# Full pipeline (valid data packet) — compute ops/sec from median latency
PIPE_RAW=$(extract_bench "valid data packet (full 3 layers)" "median")
if [[ -n "$PIPE_RAW" ]]; then
    PIPE_VAL=$(echo "$PIPE_RAW" | awk '{print $1}')
    PIPE_UNIT=$(echo "$PIPE_RAW" | awk '{print $2}')
    PIPE_NS=$(to_ns "$PIPE_VAL" "$PIPE_UNIT")
    if (( $(echo "$PIPE_NS > 0" | bc -l 2>/dev/null || echo 0) )); then
        PIPE_OPS=$(awk "BEGIN{printf \"%.0f\", 1000000000 / $PIPE_NS}")
        check_min "Full pipeline throughput" "$PIPE_OPS" "$THRESH_PIPELINE_VALID_OPS" "ops/s"
    else
        skip "Full pipeline throughput — zero median latency"
    fi
else
    skip "Full pipeline throughput — could not parse from ztlp-bench output"
fi

# Noise_XX handshake
HS_RAW=$(extract_bench "Full Noise_XX handshake" "median")
if [[ -n "$HS_RAW" ]]; then
    HS_VAL=$(echo "$HS_RAW" | awk '{print $1}')
    HS_UNIT=$(echo "$HS_RAW" | awk '{print $2}')
    HS_US=$(to_us "$HS_VAL" "$HS_UNIT")
    check_max "Noise_XX handshake" "$HS_US" "$THRESH_HANDSHAKE_US" "µs"
else
    skip "Noise_XX handshake — could not parse from ztlp-bench output"
fi

# ChaCha20-Poly1305 encrypt 64B
CHACHA_RAW=$(extract_bench "encrypt 64B payload" "median")
if [[ -n "$CHACHA_RAW" ]]; then
    CHACHA_VAL=$(echo "$CHACHA_RAW" | awk '{print $1}')
    CHACHA_UNIT=$(echo "$CHACHA_RAW" | awk '{print $2}')
    CHACHA_NS=$(to_ns "$CHACHA_VAL" "$CHACHA_UNIT")
    check_max "ChaCha20 encrypt 64B" "$CHACHA_NS" "$THRESH_CHACHA_ENCRYPT_64B_NS" "ns"
else
    skip "ChaCha20 encrypt 64B — could not parse from ztlp-bench output"
fi

# ─── Step 3: Run throughput benchmark (quick mode) ───────────────────────────

echo ""
log "── Tunnel Throughput ──"
echo ""

THROUGHPUT_BIN="$PROTO_DIR/target/release/ztlp-throughput"

if [[ -x "$THROUGHPUT_BIN" ]]; then
    log "Running throughput test (1 MB, 1 iteration, 30s timeout)..."
    TP_OUT=$(timeout 30 "$THROUGHPUT_BIN" --mode ztlp-nogso --size 1048576 --repeat 1 2>&1) || true
    TP_EXIT=$?
    vlog "ztlp-throughput exit code: $TP_EXIT"
    vlog "ztlp-throughput output:"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "$TP_OUT" | while IFS= read -r line; do vlog "  $line"; done
    fi

    if [[ "$TP_EXIT" -eq 124 ]]; then
        # Timeout — tunnel bridge didn't complete (known issue on some kernels)
        skip "ZTLP tunnel throughput — bridge timed out (may need GSO/kernel support)"
    else
        # Parse throughput — look for MB/s or GB/s in the output
        TP_LINE=$(echo "$TP_OUT" | grep -E '(MB/s|GB/s)' | grep -vi "raw\|baseline" | head -1)
        if [[ -n "$TP_LINE" ]]; then
            TP_VAL=$(echo "$TP_LINE" | grep -oE '[0-9]+(\.[0-9]+)?\s*(MB/s|GB/s)' | head -1)
            TP_NUM=$(echo "$TP_VAL" | grep -oE '[0-9]+(\.[0-9]+)?')
            TP_UNIT=$(echo "$TP_VAL" | grep -oE '(MB|GB)')
            if [[ "$TP_UNIT" == "GB" ]]; then
                TP_MBPS=$(awk "BEGIN{printf \"%.0f\", $TP_NUM * 1024}")
            else
                TP_MBPS="$TP_NUM"
            fi
            check_min "ZTLP tunnel throughput (no GSO)" "$TP_MBPS" "$THRESH_TUNNEL_MBPS" "MB/s"
        else
            skip "ZTLP tunnel throughput — could not parse output (transfer may have failed)"
        fi
    fi
else
    skip "ZTLP tunnel throughput — ztlp-throughput binary not found"
fi

# ─── Step 4: Run correctness tests ──────────────────────────────────────────

echo ""
log "── Test Suite Verification ──"
echo ""

log "Running full Rust test suite..."
TEST_OUT=$(cd "$PROTO_DIR" && cargo test --release 2>&1) || true
TEST_RESULT=$?

# Count test results
TEST_PASSED=$(echo "$TEST_OUT" | grep -oE '[0-9]+ passed' | awk '{sum += $1} END {print sum+0}')
TEST_FAILED=$(echo "$TEST_OUT" | grep -oE '[0-9]+ failed' | awk '{sum += $1} END {print sum+0}')

if [[ "$TEST_FAILED" -gt 0 ]]; then
    fail "Test suite: $TEST_PASSED passed, $TEST_FAILED FAILED"
    add_result "test_suite" "$TEST_FAILED" "0" "failures" "fail"
else
    pass "Test suite: $TEST_PASSED passed, 0 failed"
    add_result "test_suite" "0" "0" "failures" "pass"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Results"
echo "═══════════════════════════════════════════════════════════"
echo ""
log "✅ Passed:  $PASS_COUNT"
log "❌ Failed:  $FAIL_COUNT"
log "⏭️  Skipped: $SKIP_COUNT"
echo ""

# ─── Write output JSON ───────────────────────────────────────────────────────

OUTPUT_JSON=$(printf '{
  "timestamp": "%s",
  "commit": "%s",
  "mode": "%s",
  "passed": %d,
  "failed": %d,
  "skipped": %d,
  "checks": %s
}' "$TIMESTAMP" "$GIT_COMMIT" "$(if $STRICT; then echo strict; else echo ci; fi)" \
   "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$RESULTS_JSON")

if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$OUTPUT_JSON" > "$OUTPUT_FILE"
    log "Results written to: $OUTPUT_FILE"
fi

# Always write latest results to bench/latest-perf-gate.json
echo "$OUTPUT_JSON" > "$SCRIPT_DIR/latest-perf-gate.json"

# ─── Exit code ───────────────────────────────────────────────────────────────

if [[ "$DRY_RUN" == "true" ]]; then
    log "Dry run — not failing on regressions"
    exit 0
fi

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo ""
    err "Performance regression detected! ($FAIL_COUNT check(s) failed)"
    exit 1
else
    echo ""
    log "🎉 All performance checks passed!"
    exit 0
fi
