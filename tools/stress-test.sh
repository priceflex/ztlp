#!/bin/bash
# ZTLP VIP Proxy Stress Test
# Run from Mac client: bash ~/ztlp/tools/stress-test.sh
#
# Tests HTTP through the ZTLP tunnel via VIP proxy:
#   curl → 127.0.55.1:80 → pf redirect → 127.0.55.1:8080 → VIP proxy → ZTLP tunnel → gateway → Vaultwarden

set -e

HOST="http://beta.techrockstars.ztlp"
DIRECT="http://127.0.55.1:8080"
LOG="/tmp/ztlp-recv-debug.log"
RESULTS="/tmp/ztlp-stress-results.txt"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ PASS${NC} $1"; }
fail() { echo -e "${RED}❌ FAIL${NC} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${YELLOW}→${NC} $1"; }

FAILURES=0
TOTAL=0

# ── Pre-flight ──────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════"
echo " ZTLP VIP Proxy Stress Test"
echo "═══════════════════════════════════════════════════════"
echo ""

info "Checking prerequisites..."
ZTLP_PID=$(pgrep -x ZTLP 2>/dev/null || true)
if [ -z "$ZTLP_PID" ]; then
    fail "ZTLP app not running"
    exit 1
fi

# Check TCP listeners
if ! lsof -p $ZTLP_PID -iTCP -P -n 2>/dev/null | grep -q "8080.*LISTEN"; then
    fail "VIP proxy not listening on 8080"
    exit 1
fi

# Check DNS
if ! host beta.techrockstars.ztlp 127.0.55.53 -p 5354 >/dev/null 2>&1; then
    if ! dig @127.0.55.53 -p 5354 beta.techrockstars.ztlp +short >/dev/null 2>&1; then
        info "DNS resolver check skipped (dig/host not available)"
    fi
fi

# Warm up
info "Warming up..."
curl -s -o /dev/null --max-time 10 "$HOST" || true

# Clear log
> "$LOG" 2>/dev/null || true
> "$RESULTS"

# Record initial session count
INITIAL_SESSIONS=$(grep -c "recv_loop started" "$LOG" 2>/dev/null || echo 0)

echo ""

# ── Test 1: Sequential requests ─────────────────────────────────────────

TOTAL=$((TOTAL + 1))
echo "━━━ Test 1: 20 sequential requests ━━━"
SUCCESSES=0
for i in $(seq 1 20); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$HOST" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
        SUCCESSES=$((SUCCESSES + 1))
    else
        echo "  Request $i: HTTP $CODE"
    fi
done
echo "  $SUCCESSES/20 succeeded"
if [ "$SUCCESSES" -eq 20 ]; then
    pass "20/20 sequential requests"
else
    fail "$SUCCESSES/20 sequential requests ($(( 20 - SUCCESSES)) failed)"
fi
echo "$SUCCESSES/20 sequential" >> "$RESULTS"

# Check for reconnects
SESSIONS=$(grep -c "recv_loop started" "$LOG" 2>/dev/null || echo 0)
RECONNECTS=$((SESSIONS - INITIAL_SESSIONS))
if [ "$RECONNECTS" -gt 0 ]; then
    echo -e "  ${RED}⚠️  $RECONNECTS tunnel reconnects during test${NC}"
fi
echo ""

# ── Test 2: Parallel burst (5 concurrent) ───────────────────────────────

TOTAL=$((TOTAL + 1))
echo "━━━ Test 2: 50 requests, 5 concurrent ━━━"
SUCCESSES=0
FAILS=0
for batch in $(seq 1 10); do
    PIDS=""
    for j in $(seq 1 5); do
        (curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$HOST" 2>/dev/null) &
        PIDS="$PIDS $!"
    done
    for pid in $PIDS; do
        CODE=$(wait $pid 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            SUCCESSES=$((SUCCESSES + 1))
        else
            FAILS=$((FAILS + 1))
        fi
    done
done
echo "  $SUCCESSES/50 succeeded ($FAILS failed)"
if [ "$SUCCESSES" -ge 48 ]; then
    pass "50 requests @ 5 concurrent ($SUCCESSES/50)"
else
    fail "50 requests @ 5 concurrent ($SUCCESSES/50)"
fi
echo "$SUCCESSES/50 parallel-5" >> "$RESULTS"
echo ""

# ── Test 3: Rapid-fire (10 concurrent) ──────────────────────────────────

TOTAL=$((TOTAL + 1))
echo "━━━ Test 3: 100 requests, 10 concurrent ━━━"
SUCCESSES=0
FAILS=0
for batch in $(seq 1 10); do
    PIDS=""
    for j in $(seq 1 10); do
        (curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$HOST" 2>/dev/null) &
        PIDS="$PIDS $!"
    done
    for pid in $PIDS; do
        CODE=$(wait $pid 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            SUCCESSES=$((SUCCESSES + 1))
        else
            FAILS=$((FAILS + 1))
        fi
    done
done
echo "  $SUCCESSES/100 succeeded ($FAILS failed)"
if [ "$SUCCESSES" -ge 95 ]; then
    pass "100 requests @ 10 concurrent ($SUCCESSES/100)"
else
    fail "100 requests @ 10 concurrent ($SUCCESSES/100)"
fi
echo "$SUCCESSES/100 parallel-10" >> "$RESULTS"
echo ""

# ── Test 4: Sustained load ──────────────────────────────────────────────

TOTAL=$((TOTAL + 1))
echo "━━━ Test 4: 200 requests, 20 concurrent ━━━"
SUCCESSES=0
FAILS=0
for batch in $(seq 1 10); do
    PIDS=""
    for j in $(seq 1 20); do
        (curl -s -o /dev/null -w "%{http_code}" --connect-timeout 15 --max-time 20 "$HOST" 2>/dev/null) &
        PIDS="$PIDS $!"
    done
    for pid in $PIDS; do
        CODE=$(wait $pid 2>/dev/null || echo "000")
        if [ "$CODE" = "200" ]; then
            SUCCESSES=$((SUCCESSES + 1))
        else
            FAILS=$((FAILS + 1))
        fi
    done
done
echo "  $SUCCESSES/200 succeeded ($FAILS failed)"
if [ "$SUCCESSES" -ge 190 ]; then
    pass "200 requests @ 20 concurrent ($SUCCESSES/200)"
else
    fail "200 requests @ 20 concurrent ($SUCCESSES/200)"
fi
echo "$SUCCESSES/200 parallel-20" >> "$RESULTS"
echo ""

# ── Test 5: Latency check ──────────────────────────────────────────────

TOTAL=$((TOTAL + 1))
echo "━━━ Test 5: Latency (10 requests) ━━━"
TOTAL_TIME=0
for i in $(seq 1 10); do
    TIME=$(curl -s -o /dev/null -w "%{time_total}" --connect-timeout 10 --max-time 15 "$HOST" 2>/dev/null)
    TIME_MS=$(echo "$TIME * 1000" | bc 2>/dev/null || echo "0")
    TOTAL_TIME=$(echo "$TOTAL_TIME + $TIME_MS" | bc 2>/dev/null || echo "0")
    echo "  Request $i: ${TIME_MS}ms"
done
AVG=$(echo "$TOTAL_TIME / 10" | bc 2>/dev/null || echo "0")
echo "  Average: ${AVG}ms"
if [ "$(echo "$AVG < 500" | bc 2>/dev/null || echo 1)" = "1" ]; then
    pass "Average latency ${AVG}ms (< 500ms)"
else
    fail "Average latency ${AVG}ms (> 500ms)"
fi
echo "avg_latency=${AVG}ms" >> "$RESULTS"
echo ""

# ── Summary ─────────────────────────────────────────────────────────────

FINAL_SESSIONS=$(grep -c "recv_loop started" "$LOG" 2>/dev/null || echo 0)
TOTAL_RECONNECTS=$((FINAL_SESSIONS - INITIAL_SESSIONS))

echo "═══════════════════════════════════════════════════════"
echo " Results"
echo "═══════════════════════════════════════════════════════"
echo ""
cat "$RESULTS"
echo ""
echo "Tunnel reconnects during test: $TOTAL_RECONNECTS"
echo "Failures: $FAILURES / $TOTAL tests"
echo ""

if [ "$FAILURES" -eq 0 ] && [ "$TOTAL_RECONNECTS" -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED — zero reconnects${NC}"
elif [ "$FAILURES" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  All tests passed but $TOTAL_RECONNECTS reconnect(s) occurred${NC}"
else
    echo -e "${RED}💥 $FAILURES test(s) failed${NC}"
fi

# Log size
LOG_SIZE=$(du -h "$LOG" 2>/dev/null | cut -f1)
echo ""
echo "Log size: $LOG_SIZE"
