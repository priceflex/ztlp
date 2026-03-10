#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Network Tests — Assertion Functions
# ─────────────────────────────────────────────────────────────
#
# Source this file from test scenarios:
#   source "$(dirname "$0")/../lib/assert.sh"
#
# All assert functions record pass/fail and continue (no exit on failure).

# ── Equality ─────────────────────────────────────────────────

# Assert two values are equal
# Usage: assert_eq <label> <expected> <actual>
assert_eq() {
    local label="$1"
    local expected="$2"
    local actual="$3"

    if [[ "$expected" == "$actual" ]]; then
        record_pass "$label (expected='$expected')"
    else
        record_fail "$label (expected='$expected', got='$actual')"
    fi
}

# Assert two values are NOT equal
# Usage: assert_neq <label> <expected> <actual>
assert_neq() {
    local label="$1"
    local not_expected="$2"
    local actual="$3"

    if [[ "$not_expected" != "$actual" ]]; then
        record_pass "$label (got='$actual', not '$not_expected')"
    else
        record_fail "$label (got '$actual' which should not be '$not_expected')"
    fi
}

# ── String Contains ──────────────────────────────────────────

# Assert output contains a substring
# Usage: assert_contains <label> <substring> <output>
assert_contains() {
    local label="$1"
    local substring="$2"
    local output="$3"

    if echo "$output" | grep -qF "$substring"; then
        record_pass "$label (contains '$substring')"
    else
        record_fail "$label (expected to contain '$substring', got: '${output:0:200}')"
    fi
}

# Assert output does NOT contain a substring
# Usage: assert_not_contains <label> <substring> <output>
assert_not_contains() {
    local label="$1"
    local substring="$2"
    local output="$3"

    if ! echo "$output" | grep -qF "$substring"; then
        record_pass "$label (does not contain '$substring')"
    else
        record_fail "$label (should not contain '$substring', got: '${output:0:200}')"
    fi
}

# Assert output matches a regex
# Usage: assert_matches <label> <regex> <output>
assert_matches() {
    local label="$1"
    local regex="$2"
    local output="$3"

    if echo "$output" | grep -qE "$regex"; then
        record_pass "$label (matches '$regex')"
    else
        record_fail "$label (expected to match '$regex', got: '${output:0:200}')"
    fi
}

# ── Exit Codes ───────────────────────────────────────────────

# Assert a command exits with a specific code
# Usage: assert_exit_code <label> <expected_code> <command...>
assert_exit_code() {
    local label="$1"
    local expected_code="$2"
    shift 2

    local actual_code=0
    "$@" || actual_code=$?

    if [[ $actual_code -eq $expected_code ]]; then
        record_pass "$label (exit code $actual_code)"
    else
        record_fail "$label (expected exit code $expected_code, got $actual_code)"
    fi
}

# Assert a command succeeds (exit code 0)
# Usage: assert_success <label> <command...>
assert_success() {
    local label="$1"
    shift

    local exit_code=0
    "$@" || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        record_pass "$label (exit 0)"
    else
        record_fail "$label (expected exit 0, got $exit_code)"
    fi
}

# Assert a command fails (exit code != 0)
# Usage: assert_failure <label> <command...>
assert_failure() {
    local label="$1"
    shift

    local exit_code=0
    "$@" || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        record_pass "$label (exit $exit_code, non-zero as expected)"
    else
        record_fail "$label (expected non-zero exit, got 0)"
    fi
}

# ── Numeric Comparisons ─────────────────────────────────────

# Assert a number is greater than a threshold
# Usage: assert_gt <label> <threshold> <actual>
assert_gt() {
    local label="$1"
    local threshold="$2"
    local actual="$3"

    if (( actual > threshold )); then
        record_pass "$label ($actual > $threshold)"
    else
        record_fail "$label (expected > $threshold, got $actual)"
    fi
}

# Assert a number is less than a threshold
# Usage: assert_lt <label> <threshold> <actual>
assert_lt() {
    local label="$1"
    local threshold="$2"
    local actual="$3"

    if (( actual < threshold )); then
        record_pass "$label ($actual < $threshold)"
    else
        record_fail "$label (expected < $threshold, got $actual)"
    fi
}

# Assert a number is within a range (inclusive)
# Usage: assert_in_range <label> <min> <max> <actual>
assert_in_range() {
    local label="$1"
    local min="$2"
    local max="$3"
    local actual="$4"

    if (( actual >= min && actual <= max )); then
        record_pass "$label ($actual in [$min, $max])"
    else
        record_fail "$label (expected $actual in [$min, $max])"
    fi
}

# ── Container/Network ───────────────────────────────────────

# Assert a container is running
# Usage: assert_container_running <label> <container_name>
assert_container_running() {
    local label="$1"
    local container="$2"

    if docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q "true"; then
        record_pass "$label ($container is running)"
    else
        record_fail "$label ($container is NOT running)"
    fi
}

# Assert a UDP port is reachable from a container
# Usage: assert_port_reachable <label> <from_container> <host> <port>
assert_port_reachable() {
    local label="$1"
    local container="$2"
    local host="$3"
    local port="$4"

    if docker exec "$container" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'\xff', ('$host', $port))
try:
    s.recvfrom(4096)
except socket.timeout:
    pass  # timeout is OK for UDP — just proves we can send
s.close()
" 2>/dev/null; then
        record_pass "$label (UDP $host:$port reachable from $container)"
    else
        record_fail "$label (UDP $host:$port NOT reachable from $container)"
    fi
}
