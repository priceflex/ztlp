#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test — Results Formatting & JSON Output
# ─────────────────────────────────────────────────────────────
#
# Reads scenario result files and generates:
#   1. Pretty ASCII table to stdout
#   2. results.json with full structured data
#
# Source this: source "$(dirname "$0")/../lib/report.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Result File Parsing ──────────────────────────────────────

# Parse a scenario result file (key=value format) into variables
# Usage: parse_result_file "/path/to/result.txt"
parse_result_file() {
    local file="$1"
    while IFS='=' read -r key value; do
        [ -z "$key" ] && continue
        [[ "$key" =~ ^# ]] && continue
        export "RESULT_${key}=${value}"
    done < "$file"
}

# ── Verdict Logic ────────────────────────────────────────────

# Determine verdict based on results
# Usage: compute_verdict <result_file> <baseline_throughput_1mb>
# Returns: PASS, DEGRADED, or FAIL
compute_verdict() {
    local file="$1"
    local baseline_tp="${2:-0}"

    parse_result_file "$file"

    # FAIL: handshake timeout or SSH echo fail
    if [ "$RESULT_handshake_time_ms" = "TIMEOUT" ]; then
        echo "FAIL"
        return
    fi
    if [ "$RESULT_ssh_echo" = "FAIL" ]; then
        echo "FAIL"
        return
    fi

    # FAIL: any transfer timeout or checksum fail
    for size in 1 10 50; do
        local time_var="RESULT_scp_${size}mb_time_ms"
        local cksum_var="RESULT_scp_${size}mb_checksum"
        if [ "${!time_var}" = "TIMEOUT" ] || [ "${!cksum_var}" = "FAIL" ]; then
            echo "FAIL"
            return
        fi
    done

    # DEGRADED: throughput below 50% of baseline
    if [ -n "$baseline_tp" ] && [ "$baseline_tp" != "0" ]; then
        local tp_1mb="${RESULT_scp_1mb_throughput_mbps:-0}"
        local threshold
        threshold=$(echo "scale=2; $baseline_tp * 0.5" | bc 2>/dev/null || echo "0")
        local is_degraded
        is_degraded=$(echo "$tp_1mb < $threshold" | bc 2>/dev/null || echo "0")
        if [ "$is_degraded" = "1" ]; then
            echo "DEGRADED"
            return
        fi
    fi

    echo "PASS"
}

# ── ASCII Table ──────────────────────────────────────────────

# Print a pretty summary table
# Usage: print_summary_table <results_dir>
print_summary_table() {
    local results_dir="$1"
    local baseline_tp=""

    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║                              ZTLP Extreme Stress Test Results                                              ║${NC}"
    echo -e "${BOLD}${CYAN}╠════╤══════════════════════════════╤═══════════╤═══════════╤════════════╤════════════╤════════════╤═══════════╣${NC}"
    echo -e "${BOLD}${CYAN}║ ## │ Scenario                     │ Handshake │ SSH Echo  │  1MB Xfer  │ 10MB Xfer  │ 50MB Xfer  │  Verdict  ║${NC}"
    echo -e "${BOLD}${CYAN}╠════╪══════════════════════════════╪═══════════╪═══════════╪════════════╪════════════╪════════════╪═══════════╣${NC}"

    local total=0 passed=0 degraded=0 failed=0

    for result_file in "$results_dir"/scenario-*.txt; do
        [ -f "$result_file" ] || continue
        total=$((total + 1))

        parse_result_file "$result_file"
        local num="${RESULT_scenario_id:-?}"
        local name="${RESULT_scenario_name:-unknown}"

        # Grab baseline throughput from scenario 1
        if [ "$num" = "1" ]; then
            baseline_tp="${RESULT_scp_1mb_throughput_mbps:-0}"
        fi

        local verdict
        verdict=$(compute_verdict "$result_file" "$baseline_tp")

        local verdict_color="$GREEN"
        case "$verdict" in
            PASS) passed=$((passed + 1)) ;;
            DEGRADED) degraded=$((degraded + 1)); verdict_color="$YELLOW" ;;
            FAIL) failed=$((failed + 1)); verdict_color="$RED" ;;
        esac

        # Format columns
        local hs="${RESULT_handshake_time_ms:-?}ms"
        local echo_status="${RESULT_ssh_echo:-?}"
        local xfer_1mb="${RESULT_scp_1mb_throughput_mbps:-?} Mbps"
        local xfer_10mb="${RESULT_scp_10mb_throughput_mbps:-?} Mbps"
        local xfer_50mb="${RESULT_scp_50mb_throughput_mbps:-?} Mbps"

        if [ "$RESULT_handshake_time_ms" = "TIMEOUT" ]; then hs="TIMEOUT"; fi
        if [ "$RESULT_scp_1mb_time_ms" = "TIMEOUT" ]; then xfer_1mb="TIMEOUT"; fi
        if [ "$RESULT_scp_10mb_time_ms" = "TIMEOUT" ]; then xfer_10mb="TIMEOUT"; fi
        if [ "$RESULT_scp_50mb_time_ms" = "TIMEOUT" ]; then xfer_50mb="TIMEOUT"; fi

        printf "${CYAN}║${NC} %2s │ %-28s │ %9s │ %9s │ %10s │ %10s │ %10s │ ${verdict_color}%9s${NC} ${CYAN}║${NC}\n" \
            "$num" "$name" "$hs" "$echo_status" "$xfer_1mb" "$xfer_10mb" "$xfer_50mb" "$verdict"
    done

    echo -e "${BOLD}${CYAN}╚════╧══════════════════════════════╧═══════════╧═══════════╧════════════╧════════════╧════════════╧═══════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Summary:${NC} ${GREEN}${passed} passed${NC}, ${YELLOW}${degraded} degraded${NC}, ${RED}${failed} failed${NC} (${total} total)"
    echo ""
}

# ── JSON Output ──────────────────────────────────────────────

# Generate results.json from all scenario result files
# Usage: generate_json <results_dir> <output_file>
generate_json() {
    local results_dir="$1"
    local output_file="$2"
    local baseline_tp=""
    local total=0 passed=0 degraded=0 failed=0
    local total_time=0
    local scenarios_json=""

    local ztlp_version
    ztlp_version=$(docker exec stress-client ztlp --version 2>/dev/null | head -1 || echo "unknown")

    for result_file in "$results_dir"/scenario-*.txt; do
        [ -f "$result_file" ] || continue
        total=$((total + 1))

        parse_result_file "$result_file"
        local num="${RESULT_scenario_id:-0}"
        local name="${RESULT_scenario_name:-unknown}"
        local desc="${RESULT_scenario_description:-}"
        local duration="${RESULT_scenario_duration_s:-0}"
        total_time=$((total_time + duration))

        if [ "$num" = "1" ]; then
            baseline_tp="${RESULT_scp_1mb_throughput_mbps:-0}"
        fi

        local verdict
        verdict=$(compute_verdict "$result_file" "$baseline_tp")
        case "$verdict" in
            PASS) passed=$((passed + 1)) ;;
            DEGRADED) degraded=$((degraded + 1)) ;;
            FAIL) failed=$((failed + 1)) ;;
        esac

        # Build transfers array
        local transfers=""
        for size in 1 10 50; do
            local time_var="RESULT_scp_${size}mb_time_ms"
            local tp_var="RESULT_scp_${size}mb_throughput_mbps"
            local ck_var="RESULT_scp_${size}mb_checksum"
            local t="${!time_var:-0}"
            local tp="${!tp_var:-0}"
            local ck="${!ck_var:-FAIL}"
            [ "$t" = "TIMEOUT" ] && t=0
            [ "$tp" = "TIMEOUT" ] && tp=0
            if [ -n "$transfers" ]; then transfers+=","; fi
            transfers+="{\"size_mb\":$size,\"time_ms\":$t,\"throughput_mbps\":$tp,\"checksum\":\"$ck\"}"
        done

        local hs="${RESULT_handshake_time_ms:-0}"
        [ "$hs" = "TIMEOUT" ] && hs=0
        local echo_result="${RESULT_ssh_echo:-FAIL}"
        local retransmits="${RESULT_retransmit_count:-0}"

        if [ -n "$scenarios_json" ]; then scenarios_json+=","; fi
        scenarios_json+="{\"id\":$num,\"name\":\"$name\",\"description\":\"$desc\",\"results\":{\"handshake_time_ms\":$hs,\"ssh_echo\":\"$echo_result\",\"transfers\":[$transfers],\"retransmit_count\":$retransmits,\"verdict\":\"$verdict\"}}"
    done

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "$output_file" << EOF
{
  "timestamp": "$timestamp",
  "ztlp_version": "$ztlp_version",
  "scenarios": [$scenarios_json],
  "summary": {
    "total": $total,
    "passed": $passed,
    "degraded": $degraded,
    "failed": $failed,
    "total_time_s": $total_time
  }
}
EOF

    # Pretty-print if jq available
    if command -v jq &>/dev/null; then
        local tmp
        tmp=$(mktemp)
        jq '.' "$output_file" > "$tmp" && mv "$tmp" "$output_file"
    fi
}

# ── Scenario Result Writer ───────────────────────────────────

# Write scenario metadata + test results to a file
# Usage: write_scenario_header <output_file> <id> <name> <description>
write_scenario_header() {
    local file="$1"
    local id="$2"
    local name="$3"
    local desc="$4"

    cat > "$file" << EOF
scenario_id=$id
scenario_name=$name
scenario_description=$desc
EOF
}

# Append test results (key=value from run_scenario_tests) to scenario file
# Usage: append_results <output_file> <results_string>
append_results() {
    local file="$1"
    local results="$2"
    echo "$results" >> "$file"
}

# Record scenario duration
# Usage: write_scenario_duration <output_file> <start_epoch> <end_epoch>
write_scenario_duration() {
    local file="$1"
    local start="$2"
    local end="$3"
    local duration=$((end - start))
    echo "scenario_duration_s=$duration" >> "$file"
}
