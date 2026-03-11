#!/usr/bin/env bash
# ZTLP Throughput Benchmark Runner
#
# Measures file-transfer performance across transport optimization modes:
# - Raw TCP loopback (baseline ceiling)
# - ZTLP tunnel with no optimizations
# - ZTLP tunnel with GSO (send-side offload)
# - ZTLP tunnel with GRO (receive-side offload)
# - ZTLP tunnel with GSO + GRO (both)
# - ZTLP tunnel with auto detection
#
# Usage:
#   bash bench/run_throughput.sh                    # default: 100MB, 5 iterations
#   bash bench/run_throughput.sh --size 1073741824  # 1GB transfer
#   bash bench/run_throughput.sh --repeat 10        # 10 iterations
#   bash bench/run_throughput.sh --quick            # 10MB, 1 iteration (quick test)
#   bash bench/run_throughput.sh --mode raw         # just raw TCP baseline
#   bash bench/run_throughput.sh --json             # machine-readable JSON output
#   bash bench/run_throughput.sh --debug            # show tunnel debug stats
#   bash bench/run_throughput.sh --debug --quick    # quick debug run
#
# Debug mode (--debug) sets ZTLP_DEBUG=1 and RUST_LOG=ztlp_proto=debug, which
# enables per-batch timing stats and periodic summaries from the tunnel:
#   [TX] batch=14 pkts=8 tcp_bytes=131072 encrypt=42µs send=18µs strategy=sendmmsg
#   [RX] batch=7 gro_segs=3 pkts_ok=3 recv=12µs decrypt=31µs reassembly=2µs
#   [STATS] elapsed=5.0s tx_rate=100.0MB/s cwnd=512 encrypt_time=134ms(2.7%)
#
# Exit codes:
#   0 — all benchmarks completed (even if some modes failed)
#   1 — fatal error (can't build, sanity check failed, etc.)
set -uo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$ZTLP_ROOT/proto"
BIN_NAME="ztlp-throughput"
BIN_PATH="$PROTO_DIR/target/release/$BIN_NAME"
export PATH="$HOME/.cargo/bin:$PATH"

# ─── Defaults ────────────────────────────────────────────────────────────────

SIZE=104857600       # 100 MB
REPEAT=5
MODE="all"
BIND="127.0.0.1"
QUICK=false
JSON=false
DEBUG=false
OUTPUT=""

# ─── Parse CLI arguments ────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)    SIZE="$2"; shift 2 ;;
        --repeat)  REPEAT="$2"; shift 2 ;;
        --mode)    MODE="$2"; shift 2 ;;
        --bind)    BIND="$2"; shift 2 ;;
        --quick)   QUICK=true; SIZE=10485760; REPEAT=1; shift ;;
        --json)    JSON=true; shift ;;
        --debug)   DEBUG=true; shift ;;
        --output)  OUTPUT="$2"; shift 2 ;;
        --help|-h)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────

log() { [[ "$JSON" == "false" ]] && echo "$@"; }
err() { echo "ERROR: $*" >&2; }

format_bytes() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        awk "BEGIN{printf \"%.1f GB\", $bytes/1073741824}"
    elif (( bytes >= 1048576 )); then
        awk "BEGIN{printf \"%.1f MB\", $bytes/1048576}"
    elif (( bytes >= 1024 )); then
        awk "BEGIN{printf \"%.1f KB\", $bytes/1024}"
    else
        echo "${bytes} B"
    fi
}

# ─── System information ─────────────────────────────────────────────────────

gather_system_info() {
    TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
    GIT_COMMIT=$(cd "$ZTLP_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    OS_INFO=$(uname -s -r -m 2>/dev/null || echo "unknown")
    CPU_MODEL=$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "unknown")
    CPU_CORES=$(nproc 2>/dev/null || echo "unknown")
    MEMORY=$(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "unknown")
    RUST_VERSION=$(rustc --version 2>/dev/null | awk '{print $2}' || echo "unknown")
    KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")
}

# ─── Pre-flight checks ──────────────────────────────────────────────────────

preflight() {
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "  ZTLP Throughput Benchmark — Pre-flight"
    log "═══════════════════════════════════════════════════════════"
    log ""

    # 1. Check cargo
    if ! command -v cargo &>/dev/null; then
        err "cargo not found. Install Rust: https://rustup.rs"
        exit 1
    fi
    log "  ✓ cargo $(cargo --version 2>/dev/null | awk '{print $2}')"

    # 2. Build the binary
    log "  → Building $BIN_NAME (release)..."
    if ! (cd "$PROTO_DIR" && cargo build --release --bin "$BIN_NAME" 2>&1 | tail -5); then
        err "Failed to build $BIN_NAME"
        exit 1
    fi
    if [[ ! -x "$BIN_PATH" ]]; then
        err "Binary not found at $BIN_PATH after build"
        exit 1
    fi
    log "  ✓ Binary built: $BIN_PATH"

    # 3. Sanity test: 1 MB raw TCP transfer
    log "  → Sanity check: 1 MB raw TCP..."
    local sanity_out
    sanity_out=$("$BIN_PATH" --mode raw --size 1048576 --repeat 1 --bind "$BIND" 2>&1) || true
    if ! echo "$sanity_out" | grep -qi "Raw TCP"; then
        err "Sanity check failed — raw TCP benchmark produced no output"
        err "Output: $sanity_out"
        exit 1
    fi
    log "  ✓ Sanity check passed"

    # 4. Detect GSO/GRO by running a tiny transfer and examining output
    log "  → Detecting GSO/GRO capabilities..."
    local detect_out
    detect_out=$("$BIN_PATH" --mode raw --size 1048576 --repeat 1 --bind "$BIND" 2>&1) || true

    # The binary prints "GSO: available/unavailable" and "GRO: available/unavailable"
    GSO_AVAILABLE="unavailable"
    GRO_AVAILABLE="unavailable"
    if echo "$detect_out" | grep -q "GSO: available"; then
        GSO_AVAILABLE="available"
    fi
    if echo "$detect_out" | grep -q "GRO: available"; then
        GRO_AVAILABLE="available"
    fi
    log "  ✓ GSO: $GSO_AVAILABLE"
    log "  ✓ GRO: $GRO_AVAILABLE"

    log ""
    log "  Pre-flight complete. Starting benchmarks..."
    log ""
}

# ─── Run a single benchmark mode ────────────────────────────────────────────

# Associative arrays for results
declare -a RESULT_MODES=()
declare -a RESULT_THROUGHPUTS=()
declare -a RESULT_TIMES=()
declare -a RESULT_NOTES=()

run_mode() {
    local mode_flag="$1"
    local mode_label="$2"
    local note="$3"

    log "  Running: $mode_label ($REPEAT iterations, $(format_bytes "$SIZE"))..."

    local out
    local env_prefix=""
    if [[ "$DEBUG" == "true" ]]; then
        env_prefix="ZTLP_DEBUG=1 RUST_LOG=ztlp_proto=debug"
    fi
    if [[ -n "$env_prefix" ]]; then
        out=$(env $env_prefix "$BIN_PATH" --mode "$mode_flag" --size "$SIZE" --repeat "$REPEAT" --bind "$BIND" 2>&1) || true
    else
        out=$("$BIN_PATH" --mode "$mode_flag" --size "$SIZE" --repeat "$REPEAT" --bind "$BIND" 2>&1) || true
    fi

    # In debug mode, print the full output for analysis
    if [[ "$DEBUG" == "true" ]]; then
        log ""
        log "  ┌─── Debug output for: $mode_label ───"
        echo "$out" | while IFS= read -r dline; do
            log "  │ $dline"
        done
        log "  └───────────────────────────────────────"
        log ""
    fi

    # Parse the output table — look for the line matching our mode label
    # The binary outputs lines like: "Raw TCP        3.56 GB/s    28.2ms     N/A   baseline"
    # We need to extract throughput and time from the relevant line

    local throughput="" time_val=""

    # Try to extract from the formatted table output
    # The binary prints a table with columns: Mode, Throughput, Time, Packets, Overhead
    while IFS= read -r line; do
        # Skip header and separator lines
        if echo "$line" | grep -qE '^\s*(Mode|─)'; then
            continue
        fi
        # Match lines that look like result rows (contain MB/s or GB/s)
        if echo "$line" | grep -qE '(MB/s|GB/s)'; then
            throughput=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+)?\s*(MB/s|GB/s)' | head -1)
            time_val=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+)?\s*(ms|s)\b' | head -1)
            break
        fi
    done <<< "$out"

    if [[ -z "$throughput" ]]; then
        log "    ✗ FAILED (no throughput parsed)"
        throughput="FAILED"
        time_val="N/A"
        note="benchmark failed"
    else
        log "    ✓ $throughput in $time_val"
    fi

    RESULT_MODES+=("$mode_label")
    RESULT_THROUGHPUTS+=("$throughput")
    RESULT_TIMES+=("$time_val")
    RESULT_NOTES+=("$note")
}

# ─── Compute overhead vs raw ────────────────────────────────────────────────

parse_throughput_mbps() {
    local val="$1"
    if [[ "$val" == "FAILED" ]]; then
        echo "0"
        return
    fi
    local num unit
    num=$(echo "$val" | grep -oE '[0-9]+(\.[0-9]+)?')
    unit=$(echo "$val" | grep -oE '(MB/s|GB/s)')
    if [[ "$unit" == "GB/s" ]]; then
        awk "BEGIN{printf \"%.2f\", $num * 1024}"
    else
        echo "$num"
    fi
}

# ─── Main benchmark run ─────────────────────────────────────────────────────

main() {
    gather_system_info
    preflight

    log "═══════════════════════════════════════════════════════════"
    log "  ZTLP Throughput Benchmark"
    log "═══════════════════════════════════════════════════════════"
    log "  Transfer: $(format_bytes "$SIZE") × $REPEAT iterations"
    log "  Bind:     $BIND"
    log "  System:   $OS_INFO"
    log "  CPU:      $CPU_MODEL ($CPU_CORES cores)"
    log "  Memory:   $MEMORY"
    log "  GSO:      $GSO_AVAILABLE | GRO: $GRO_AVAILABLE"
    log ""

    # Determine which modes to run
    case "$MODE" in
        all)
            run_mode "raw"         "Raw TCP"         "baseline"
            run_mode "ztlp-nogso"  "ZTLP (no opts)"  "-"
            if [[ "$GSO_AVAILABLE" == "available" ]]; then
                run_mode "ztlp-gso" "ZTLP (GSO)" "-"
            fi
            if [[ "$GRO_AVAILABLE" == "available" ]]; then
                run_mode "ztlp-gro" "ZTLP (GRO)" "-"
            fi
            if [[ "$GSO_AVAILABLE" == "available" && "$GRO_AVAILABLE" == "available" ]]; then
                run_mode "ztlp-gso-gro" "ZTLP (GSO+GRO)" "-"
            fi
            run_mode "ztlp" "ZTLP (auto)" "auto-detected"
            ;;
        raw)
            run_mode "raw" "Raw TCP" "baseline"
            ;;
        ztlp-nogso|ztlp-gso|ztlp-gro|ztlp-gso-gro|ztlp)
            run_mode "$MODE" "$MODE" "-"
            ;;
        *)
            err "Unknown mode: $MODE"
            err "Valid modes: all, raw, ztlp-nogso, ztlp-gso, ztlp-gro, ztlp-gso-gro, ztlp"
            exit 1
            ;;
    esac

    # ─── Compute overhead ────────────────────────────────────────────────

    local raw_mbps=0
    for i in "${!RESULT_MODES[@]}"; do
        if [[ "${RESULT_MODES[$i]}" == "Raw TCP" ]]; then
            raw_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}")
            break
        fi
    done

    declare -a RESULT_OVERHEADS=()
    for i in "${!RESULT_MODES[@]}"; do
        if [[ "${RESULT_MODES[$i]}" == "Raw TCP" ]]; then
            RESULT_OVERHEADS+=("baseline")
        elif [[ "${RESULT_THROUGHPUTS[$i]}" == "FAILED" ]]; then
            RESULT_OVERHEADS+=("N/A")
        elif (( $(echo "$raw_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local this_mbps
            this_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}")
            local overhead
            overhead=$(awk "BEGIN{printf \"%.1f%%\", (1 - $this_mbps / $raw_mbps) * 100}")
            RESULT_OVERHEADS+=("$overhead")
        else
            RESULT_OVERHEADS+=("N/A")
        fi
    done

    # ─── Print summary table ─────────────────────────────────────────────

    log ""
    log "═══════════════════════════════════════════════════════════"
    log "  Results Summary"
    log "═══════════════════════════════════════════════════════════"
    log ""
    printf "  %-20s %12s %10s %16s %s\n" "Mode" "Throughput" "Time" "Overhead vs Raw" "Notes"
    printf "  %-20s %12s %10s %16s %s\n" "────────────────────" "────────────" "──────────" "────────────────" "─────"
    for i in "${!RESULT_MODES[@]}"; do
        printf "  %-20s %12s %10s %16s %s\n" \
            "${RESULT_MODES[$i]}" \
            "${RESULT_THROUGHPUTS[$i]}" \
            "${RESULT_TIMES[$i]}" \
            "${RESULT_OVERHEADS[$i]}" \
            "${RESULT_NOTES[$i]}"
    done
    log ""

    # ─── Analysis ────────────────────────────────────────────────────────

    local nogso_mbps=0 gso_mbps=0 gro_mbps=0 gsogro_mbps=0 auto_mbps=0
    for i in "${!RESULT_MODES[@]}"; do
        case "${RESULT_MODES[$i]}" in
            "ZTLP (no opts)")  nogso_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}") ;;
            "ZTLP (GSO)")      gso_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}") ;;
            "ZTLP (GRO)")      gro_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}") ;;
            "ZTLP (GSO+GRO)")  gsogro_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}") ;;
            "ZTLP (auto)")     auto_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}") ;;
        esac
    done

    ANALYSIS=""
    if (( $(echo "$nogso_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$gso_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local gso_ratio
            gso_ratio=$(awk "BEGIN{printf \"%.1f\", $gso_mbps / $nogso_mbps}")
            ANALYSIS="${ANALYSIS}- GSO improvement: ${gso_ratio}x over no-opts"$'\n'
        fi
        if (( $(echo "$gro_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local gro_ratio
            gro_ratio=$(awk "BEGIN{printf \"%.1f\", $gro_mbps / $nogso_mbps}")
            ANALYSIS="${ANALYSIS}- GRO improvement: ${gro_ratio}x over no-opts"$'\n'
        fi
        if (( $(echo "$gsogro_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local gsogro_ratio
            gsogro_ratio=$(awk "BEGIN{printf \"%.1f\", $gsogro_mbps / $nogso_mbps}")
            ANALYSIS="${ANALYSIS}- GSO+GRO improvement: ${gsogro_ratio}x over no-opts"$'\n'
        fi
    fi
    if (( $(echo "$raw_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$gsogro_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local best_overhead
            best_overhead=$(awk "BEGIN{printf \"%.1f\", (1 - $gsogro_mbps / $raw_mbps) * 100}")
            ANALYSIS="${ANALYSIS}- ZTLP overhead vs raw: ${best_overhead}% (GSO+GRO)"$'\n'
        fi
        if (( $(echo "$nogso_mbps > 0" | bc -l 2>/dev/null || echo 0) )); then
            local worst_overhead
            worst_overhead=$(awk "BEGIN{printf \"%.1f\", (1 - $nogso_mbps / $raw_mbps) * 100}")
            ANALYSIS="${ANALYSIS}- ZTLP overhead vs raw: ${worst_overhead}% (no opts)"$'\n'
        fi
    fi

    if [[ -n "$ANALYSIS" ]]; then
        log "  Analysis:"
        echo "$ANALYSIS" | while IFS= read -r line; do
            [[ -n "$line" ]] && log "  $line"
        done
        log ""
    fi

    # ─── Generate markdown report ────────────────────────────────────────

    local report_file="${OUTPUT:-$SCRIPT_DIR/THROUGHPUT.md}"
    generate_markdown "$report_file"
    log "  Results written to: $report_file"
    log ""

    # ─── JSON output ─────────────────────────────────────────────────────

    if [[ "$JSON" == "true" ]]; then
        generate_json
    fi
}

# ─── Markdown report generation ──────────────────────────────────────────────

generate_markdown() {
    local outfile="$1"
    cat > "$outfile" <<MDEOF
# ZTLP Throughput Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | $TIMESTAMP |
| Commit | $GIT_COMMIT |
| OS | $OS_INFO |
| CPU | $CPU_MODEL |
| Cores | $CPU_CORES |
| Memory | $MEMORY |
| Rust | $RUST_VERSION |
| GSO | $GSO_AVAILABLE |
| GRO | $GRO_AVAILABLE |

## Configuration

| Parameter | Value |
|-----------|-------|
| Transfer size | $(format_bytes "$SIZE") |
| Iterations | $REPEAT |
| Bind address | $BIND |

## Results

| Mode | Throughput | Time | Overhead vs Raw | Notes |
|------|-----------|------|-----------------|-------|
MDEOF

    for i in "${!RESULT_MODES[@]}"; do
        echo "| ${RESULT_MODES[$i]} | ${RESULT_THROUGHPUTS[$i]} | ${RESULT_TIMES[$i]} | ${RESULT_OVERHEADS[$i]} | ${RESULT_NOTES[$i]} |" >> "$outfile"
    done

    if [[ -n "$ANALYSIS" ]]; then
        echo "" >> "$outfile"
        echo "## Analysis" >> "$outfile"
        echo "" >> "$outfile"
        echo "$ANALYSIS" >> "$outfile"
    fi
}

# ─── JSON output ─────────────────────────────────────────────────────────────

generate_json() {
    echo "{"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"commit\": \"$GIT_COMMIT\","
    echo "  \"os\": \"$OS_INFO\","
    echo "  \"cpu\": \"$CPU_MODEL\","
    echo "  \"cores\": \"$CPU_CORES\","
    echo "  \"memory\": \"$MEMORY\","
    echo "  \"rust\": \"$RUST_VERSION\","
    echo "  \"gso\": \"$GSO_AVAILABLE\","
    echo "  \"gro\": \"$GRO_AVAILABLE\","
    echo "  \"config\": {"
    echo "    \"size_bytes\": $SIZE,"
    echo "    \"repeat\": $REPEAT,"
    echo "    \"bind\": \"$BIND\""
    echo "  },"
    echo "  \"results\": ["
    for i in "${!RESULT_MODES[@]}"; do
        local comma=","
        if [[ $i -eq $(( ${#RESULT_MODES[@]} - 1 )) ]]; then
            comma=""
        fi
        local tp_mbps
        tp_mbps=$(parse_throughput_mbps "${RESULT_THROUGHPUTS[$i]}")
        echo "    {"
        echo "      \"mode\": \"${RESULT_MODES[$i]}\","
        echo "      \"throughput\": \"${RESULT_THROUGHPUTS[$i]}\","
        echo "      \"throughput_mbps\": $tp_mbps,"
        echo "      \"time\": \"${RESULT_TIMES[$i]}\","
        echo "      \"overhead\": \"${RESULT_OVERHEADS[$i]}\","
        echo "      \"notes\": \"${RESULT_NOTES[$i]}\""
        echo "    }$comma"
    done
    echo "  ]"
    echo "}"
}

# ─── Run ─────────────────────────────────────────────────────────────────────

main
