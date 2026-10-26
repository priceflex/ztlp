#!/usr/bin/env bash
# ZTLP Admin panel — CI gate for the admin/ app.
#
# The admin slice queue (docs/admin-panel/BUILD_LOOP.md §4) lists this as the
# canonical "all gates pass" command. Every slice ends by running this script
# before committing. It must stay green for the branch to ship.
#
# Gates (in order):
#   1. SKIP_CLAIM_BOOT=1 bin/rails test            (full Rails minitest suite)
#   2. bundle exec rubocop -A                      (auto-fix, then re-run)
#   3. bundle exec rubocop                         (must be clean)
#   4. bundle exec brakeman -q --no-pager          (EOLRuby/EOLRails are known
#                                                  non-code findings; anything
#                                                  else is a real finding)
#   5. node --check app/assets/javascripts/directory.js
#   6. node --test "test/javascript/*.mjs"         (pure-function unit tests
#                                                  for directory.js)
#
# Usage:
#   export HOME=/home/trs
#   cd /home/trs/ztlp-admin/admin
#   bash scripts/ci-admin.sh
#
# Exit code: 0 if every gate passes, non-zero on the first failure.

set -euo pipefail

NODE="${NODE:-/home/trs/.local/bin/node}"

# Run from the admin/ directory regardless of where the caller was.
cd "$(dirname "$0")/.."

# ---------------------------------------------------------------------------
# 1. Full Rails minitest suite
# ---------------------------------------------------------------------------
echo "== 1/6 SKIP_CLAIM_BOOT=1 bin/rails test"
SKIP_CLAIM_BOOT=1 timeout 600 bin/rails test  # a hung test must not run away (4-5 GB seen)

# ---------------------------------------------------------------------------
# 2 + 3. Rubocop (auto-fix, then verify clean)
# ---------------------------------------------------------------------------
# On CI (GitHub sets CI=true) never auto-fix: a fix on the runner would hide unformatted code.
if [ "${CI:-}" = "true" ]; then
  echo "== 2/6 rubocop auto-fix skipped on CI"
else
  echo "== 2/6 bundle exec rubocop -A"
  bundle exec rubocop -A
fi
echo "== 3/6 bundle exec rubocop (must be clean)"
bundle exec rubocop

# ---------------------------------------------------------------------------
# 4. Brakeman — EOLRuby/EOLRails are known non-code findings on this app
#    (Rails 7.1.6 is pinned; do not upgrade inside the loop, per the
#    build-loop spec). Anything else is a real finding and must be fixed.
# ---------------------------------------------------------------------------
echo "== 4/6 bundle exec brakeman -q --no-pager (EOL findings tolerated)"
set +e
BRK_LOG="${TMPDIR:-/tmp}/brakeman_2b.log"
bundle exec brakeman -q --no-pager > "$BRK_LOG" 2>&1
BRK_EXIT=$?
set -e
# If the only findings are EOLRuby / EOLRails, exit 0. Otherwise surface the
# real warnings and fail.
# Any "Check:" other than EOLRuby/EOLRails is a real finding (reviewed exceptions live in
# config/brakeman.ignore, which brakeman applies before reporting).
REAL_FINDING=$(grep -E "^Check: " "$BRK_LOG" | grep -vE "^Check: (EOLRuby|EOLRails)$" || true)
if [ -n "$REAL_FINDING" ]; then
  echo "brakeman: real finding(s):"
  cat "$BRK_LOG"
  exit 1
fi
if [ "$BRK_EXIT" -ne 0 ] && ! grep -qE "^Check: (EOLRuby|EOLRails)$" "$BRK_LOG"; then
  echo "brakeman failed (exit $BRK_EXIT):"
  cat "$BRK_LOG"
  exit "$BRK_EXIT"
fi
echo "brakeman: no findings beyond EOLRuby/EOLRails"

# ---------------------------------------------------------------------------
# 5. node --check the only JS file
# ---------------------------------------------------------------------------
echo "== 5/6 ${NODE} --check app/assets/javascripts/directory.js"
"${NODE}" --check app/assets/javascripts/directory.js

# ---------------------------------------------------------------------------
# 6. node --test on the pure-function unit tests
# ---------------------------------------------------------------------------
echo "== 6/6 ${NODE} --test test/javascript/"
"${NODE}" --test test/javascript/directory_test.mjs

echo "== all gates passed"
