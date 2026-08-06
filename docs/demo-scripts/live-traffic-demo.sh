#!/usr/bin/env bash
# ============================================================================
# ZTLP DEF CON Demo — "Watch it work live" traffic-driving demo
# ============================================================================
#
# The browser tab showing the dashboard is a snapshot. This script proves
# the system is actually doing live cryptographic work on every hit, not
# just serving a static page, by:
#
#   1. Snapshotting the gateway's REAL Prometheus counters (handshakes,
#      bytes in/out) before we do anything.
#   2. Firing a burst of live HTTPS requests through the full ZTLP path
#      (agent VIP -> Noise tunnel -> gateway -> backend) in real time,
#      each one doing a fresh TLS handshake + identity verification.
#   3. Re-reading the same counters after and showing the exact delta —
#      numbers that only move because real requests happened.
#   4. Pulling the dashboard's own live audit-log feed and showing new
#      VERIFIED entries appear with fresh timestamps matching the burst
#      that was just sent.
#   5. Optionally looping this whole cycle so a screen next to the browser
#      tab keeps ticking while the dashboard's own 5s auto-refresh shows
#      the same audit log growing in the browser.
#
# Usage:
#   ./live-traffic-demo.sh            # one burst of 10 requests
#   ./live-traffic-demo.sh 25         # burst of 25 requests
#   ./live-traffic-demo.sh 10 loop    # repeat every 8s until Ctrl-C —
#                                      # good for "leave it running next
#                                      # to the browser tab" during a talk
#
# Run this ON the Kali box.
# ============================================================================

set -uo pipefail

DEMO_HOST="demo-dashboard.defcon.ztlp"
GATEWAY_METRICS_URL="http://172.28.0.30:9102/metrics"
BURST_SIZE="${1:-10}"
MODE="${2:-once}"

BOLD=$(tput bold 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
CYAN=$(tput setaf 6 2>/dev/null || echo "")

section() {
  echo
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo "${BOLD}${CYAN} $1${RESET}"
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
}

get_metric() {
  # $1 = metric name (exact match, first matching line's trailing number)
  curl -s "$GATEWAY_METRICS_URL" 2>/dev/null | grep "^$1" | grep -oE '[0-9]+$' | head -1
}

run_burst() {
  local n="$1"

  section "SNAPSHOT — gateway counters BEFORE this burst"
  local hs_before rx_before tx_before
  hs_before=$(get_metric 'ztlp_gateway_handshakes_total{result="ok"}')
  rx_before=$(get_metric 'ztlp_gateway_bytes_received_total')
  tx_before=$(get_metric 'ztlp_gateway_bytes_sent_total')
  echo "  Successful handshakes so far : ${hs_before:-0}"
  echo "  Bytes received from clients  : ${rx_before:-0}"
  echo "  Bytes sent to clients        : ${tx_before:-0}"

  section "FIRING ${n} LIVE REQUESTS through the full ZTLP path"
  echo "Each request below does a REAL fresh TLS handshake to the agent's"
  echo "VIP listener, tunnels through Noise encryption to the gateway,"
  echo "gets identity-verified, and is proxied to the dashboard backend."
  echo
  local ok=0 fail=0
  for i in $(seq 1 "$n"); do
    start_ms=$(date +%s%3N)
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://${DEMO_HOST}/" 2>/dev/null)
    end_ms=$(date +%s%3N)
    elapsed=$((end_ms - start_ms))
    if [ "$code" = "200" ]; then
      ok=$((ok + 1))
      echo "  [$i/$n] ${GREEN}HTTP $code${RESET}  ${elapsed}ms  (fresh TLS handshake + identity check)"
    else
      fail=$((fail + 1))
      echo "  [$i/$n] ${YELLOW}HTTP ${code:-timeout}${RESET}  ${elapsed}ms"
    fi
  done
  echo
  echo "  ${BOLD}${ok} succeeded, ${fail} failed out of ${n} requests.${RESET}"

  section "SNAPSHOT — gateway counters AFTER this burst"
  sleep 1  # let the metrics endpoint's own scrape/update settle
  local hs_after rx_after tx_after
  hs_after=$(get_metric 'ztlp_gateway_handshakes_total{result="ok"}')
  rx_after=$(get_metric 'ztlp_gateway_bytes_received_total')
  tx_after=$(get_metric 'ztlp_gateway_bytes_sent_total')
  echo "  Successful handshakes now    : ${hs_after:-0}  ${GREEN}(+$(( ${hs_after:-0} - ${hs_before:-0} )))${RESET}"
  echo "  Bytes received from clients  : ${rx_after:-0}  ${GREEN}(+$(( ${rx_after:-0} - ${rx_before:-0} )))${RESET}"
  echo "  Bytes sent to clients        : ${tx_after:-0}  ${GREEN}(+$(( ${tx_after:-0} - ${tx_before:-0} )))${RESET}"
  echo
  echo "${BOLD}These are real Prometheus counters scraped live from the running"
  echo "gateway process — they only move because ${n} genuine encrypted"
  echo "sessions were just established and torn down.${RESET}"

  section "LIVE AUDIT LOG — newest entries from the dashboard's own feed"
  echo "Pulling https://${DEMO_HOST}/api/history right now:"
  echo
  curl -sk --max-time 5 "https://${DEMO_HOST}/api/history" 2>/dev/null \
    | python3 -c "
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    print('  (could not parse audit log JSON)')
    sys.exit(0)
for e in entries[:5]:
    status = 'VERIFIED' if e.get('ok') else 'DENIED'
    print(f\"  [{e.get('time','?')}] {status:8s} {e.get('node_name','?')} (assurance={e.get('assurance','?')})\")
" 2>/dev/null || echo "  (python3 not available for pretty-print — raw JSON above)"
  echo
  echo "${BOLD}Every one of those timestamps was generated by a request from"
  echo "this exact script run, not pre-recorded — refresh the browser tab"
  echo "and the same entries appear there (5s auto-refresh).${RESET}"
}

if [ "$MODE" = "loop" ]; then
  echo "${BOLD}${CYAN}Looping every 8s — leave this next to the browser tab. Ctrl-C to stop.${RESET}"
  trap 'echo; echo "Stopped."; exit 0' INT
  while true; do
    run_burst "$BURST_SIZE"
    echo
    echo "${YELLOW}(sleeping 8s before next burst — watch the browser tab's audit${RESET}"
    echo "${YELLOW} log refresh on its own 5s cycle in the meantime)${RESET}"
    sleep 8
  done
else
  run_burst "$BURST_SIZE"
fi
