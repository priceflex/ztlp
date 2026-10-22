#!/usr/bin/env bash
# Build-loop lock + heartbeat for the ZTLP admin directory UI loop
# (docs/admin-panel/BUILD_LOOP.md §6 rule 1). Adapted from the
# autonomous-cron-build-loop skill.
#
# A Hermes tick runs each shell command in a separate process, so a flock held
# by this script would be released as soon as it exits. The lock is therefore
# the heartbeat file itself: status in_progress younger than STALE_MIN minutes (default 12: cron runs never overlap and the
# next run starts 15 min after the previous one ENDS, so a cron tick that sees in_progress
# is looking at a tick that died, e.g. hit its iteration limit)
# = another tick is working -> print LOCKED and exit 0. flock only makes the
# check-and-write atomic.
#
#   bash scripts/build_lock.sh "<slice intent>"      -> LOCK_ACQUIRED | LOCKED
#   bash scripts/build_lock.sh --done <short sha>    -> MARKED_DONE
#   bash scripts/build_lock.sh --blocked "<reason>"  -> MARKED_BLOCKED (releases)
set -euo pipefail

ADMIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ADMIN_DIR/.build_state"
LOCK="$ADMIN_DIR/tmp/.build.lock"
STALE_MIN="${STALE_MIN:-12}"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$ADMIN_DIR/tmp"

exec 9>"$LOCK"
flock -w 10 9

case "${1:-}" in
  --done)
    printf 'status: done\nfinished: %s\nlast_commit: %s\n' "$TS" "${2:-unknown}" > "$STATE"
    echo "MARKED_DONE: ${2:-unknown}"; exit 0 ;;
  --blocked)
    printf 'status: blocked\nfinished: %s\nnote: %s\n' "$TS" "${2:-}" > "$STATE"
    echo "MARKED_BLOCKED"; exit 0 ;;
esac

if [ -f "$STATE" ] && grep -q '^status: in_progress' "$STATE"; then
  started=$(sed -n 's/^started: //p' "$STATE")
  age_min=$(( ( $(date -u +%s) - $(date -u -d "$started" +%s) ) / 60 ))
  if [ "$age_min" -lt "$STALE_MIN" ]; then
    echo "LOCKED: tick started $started (${age_min}m ago) still in progress — exiting."
    exit 0
  fi
  echo "STALE: previous tick started $started (${age_min}m ago) never finished — taking over."
fi

printf 'status: in_progress\nstarted: %s\nnote: %s\n' "$TS" "${1:-build tick}" > "$STATE"
echo "LOCK_ACQUIRED: $TS — ${1:-build tick}"
