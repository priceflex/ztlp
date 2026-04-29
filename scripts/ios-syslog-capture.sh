#!/usr/bin/env bash
set -euo pipefail

MAC_HOST="${MAC_HOST:-stevenprice@10.78.72.234}"
UDID="${UDID:-00008130-000255C11A88001C}"
REMOTE_PMD3="${REMOTE_PMD3:-/Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/ztlp-ios-syslog}"
DURATION="${1:-180}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
REMOTE_RAW="$REMOTE_DIR/ztlp-ios-syslog-$TS.raw.log"
REMOTE_FILTERED="$REMOTE_DIR/ztlp-ios-syslog-$TS.filtered.log"
REMOTE_PID="$REMOTE_DIR/ztlp-ios-syslog.pid"

ssh "$MAC_HOST" "mkdir -p '$REMOTE_DIR'; rm -f '$REMOTE_PID'; \
  ( '$REMOTE_PMD3' --no-color syslog live --udid '$UDID' --out '$REMOTE_RAW' --label \
      -ei 'ztlp|networkextension|packet tunnel|packettunnel|nesession|neagent|nehelper|nesm|vpn|jetsam|memorystatus|crash|exception|watchdog|termination|terminated|runningboard|assertion|com\\.ztlp|ZTLPTunnel' \
      > '$REMOTE_FILTERED' 2>&1 & echo \$! > '$REMOTE_PID' ); \
  echo 'Started iOS syslog capture'; echo 'PID='\$(cat '$REMOTE_PID'); echo 'RAW=$REMOTE_RAW'; echo 'FILTERED=$REMOTE_FILTERED'; \
  sleep '$DURATION'; \
  if [ -f '$REMOTE_PID' ] && kill -0 \$(cat '$REMOTE_PID') 2>/dev/null; then kill \$(cat '$REMOTE_PID') 2>/dev/null || true; fi; \
  sleep 1; \
  echo '--- filtered tail ---'; tail -n 220 '$REMOTE_FILTERED' || true"

echo "Remote raw log: $MAC_HOST:$REMOTE_RAW"
echo "Remote filtered log: $MAC_HOST:$REMOTE_FILTERED"
