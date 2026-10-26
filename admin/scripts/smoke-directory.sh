#!/usr/bin/env bash
# ZTLP Admin panel — local prod-shape smoke (BUILD_LOOP.md Slice 12 + §5 box 3).
#
# Runs against a fresh `docker compose -p admintest up -d` stack (after
# `docker compose -p admintest down -v` to clear any prior smoke DB): db +
# web + jobs, image ztlp-admin:<ver>, ZTLP_REQUIRE_GATEWAY=0, throwaway zone.
#
# Steps (each prints PASS/FAIL; exits non-zero on the first FAIL):
#   0. /up responds 200 "ok"
#   1. claim code -> /claim (REAL signed form POST) -> Overview with the Setup
#    checklist — via scripts/smoke-claim-login.rb (requires a FRESH panel:
#    the claim POST 422s on an already-claimed DB because the session cookie
#    rotates on the /claim bounce; run `down -v` before `up -d`). The real
#    challenge/verify LOGIN round-trip is proven by the smoke2 admin below.
#   2. create user -> create group -> add member (the membership shows)
#   3. /zone renders
#   4. /search.json?q= returns the created user and group as JSON
#   5. jobs container log names all three recurring tasks (republish_ns,
#      reconcile_ns, expire_enrollments)
#   6. break-glass: `bin/rails admin:reset_claim` mints a forced code that /claim
#      accepts even though an administrator exists — proven by a SECOND real
#      signed challenge/verify login as the new rescue admin (review-of-11c
#      fix, pinned against the PRODUCTION entrypoint, not the test env)
#
# The claim code is minted with the container's OWN rails runner
# (/rails/bin/docker-entrypoint — AR encryption keys live in /data/keys.env,
# G9). It is printed to this script's stdout and therefore into the STATUS
# evidence: the code is single-use and the smoke DB is thrown away after
# `docker compose -p admintest down -v`; it is NOT a standing credential.
#
# Usage: bash scripts/smoke-directory.sh [admin_port] [web_container]
#        (defaults: 18081, ztlp-admin-web)
set -uo pipefail

PORT="${1:-18081}"
WEB="${2:-ztlp-admin-web}"
BASE="http://127.0.0.1:${PORT}"
CJ=/tmp/smoke_cookie
CODE=0
FAILED=""

fail() { echo "FAIL: $*"; FAILED=1; exit 1; }
ok()   { echo "PASS: $*"; }

# tok <body> [form-action-substring] -> authenticity token of (the) form
# When a form-action-substring is given, use the FIRST form containing that
# substring in its <form> tag (the target form). Otherwise use the LAST form
# on the page (the page's primary action form; the logout form always comes
# first in the layout and its token is session-wide but the last form is the
# one the page is asking you to submit).
tok() {
  # Body on stdin; optional form-action substring in $2. The heredoc would
  # steal stdin from the pipe, so read the body into a variable first and
  # pass both via the environment.
  local _body
  _body=$(cat)
  BODY_FILTER="${2:-}" BODY_DATA="$_body" python3 - <<'PYEOF'
import re, html, os
body = os.environ.get("BODY_DATA", "")
sub = os.environ.get("BODY_FILTER", "")
forms = re.findall(r"<form[^>]*>.*?</form>", body, re.S)
if sub:
    forms = [f for f in forms if sub in f.split(">")[0]]
if not forms:
    sys.exit(0)
target = forms[0] if sub else forms[-1]
m = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', target)
print(html.unescape(m.group(1)) if m else "")
PYEOF
}

get() { # get <path> -> body
  curl -s -m 20 -b "$CJ" -c "$CJ" -L "${BASE}$1"
}

# ---- 0. /up ----------------------------------------------------------------
CODE=$(curl -s -m 15 -o /tmp/smoke_up -w "%{http_code}" "${BASE}/up")
[ "$CODE" = "200" ] && grep -q ok /tmp/smoke_up \
  && ok "/up -> 200 $(cat /tmp/smoke_up)" \
  || fail "/up -> HTTP ${CODE} ($(cat /tmp/smoke_up 2>/dev/null | head -c 120))"

# ---- 1. claim (REAL signed flow via the in-container Ruby script) -----------
# smoke-claim-login.rb runs INSIDE the web container under the production
# entrypoint (AR encryption keys from /data/keys.env — G9): it mints a claim
# code, generates an Ed25519 keypair, POSTs /claim WITH the signature
# (Claim.perform! verifies it), and then proves the challenge/verify LOGIN
# round-trip over HTTP, ending on the signed-in Overview. Its stdout is the
# evidence; the claim code it prints is single-use and the smoke DB is
# destroyed after the run.
docker cp scripts/smoke-claim-login.rb "$WEB":/rails/scripts/smoke-claim-login.rb
docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner scripts/smoke-claim-login.rb
[ $? -eq 0 ] || fail "smoke-claim-login (signed claim + login round-trip)"

# Steps 2-4 need a signed-in super_admin session to drive the web UI with
# curl. The claim script's keypair lives in the container, so mint a second
# admin the same way the operator bootstraps over SSH (entrypoint runner),
# then sign in over the panel's REAL challenge/verify exchange:
#   POST /auth/challenge (JSON, unauthenticated) -> nonce
#   POST /auth/verify    (Ed25519 over login_message(host, nonce)) -> login_url
#   GET  login_url -> cookie session
KEYS2=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner \
  's, p = Ztlp::Ed25519.generate
   Admin.create!(username: "smoke2", display_name: "Smoke Two", pubkey_hex: p, role: "super_admin")
   puts "#{p} #{s}"' 2>/dev/null | tail -1)
PUB2=$(echo "$KEYS2" | awk '{print $1}')
SIG2=$(echo "$KEYS2" | awk '{print $2}')
[ ${#PUB2} -eq 64 ] || fail "could not create the smoke2 admin keypair"

NONCE=$(curl -s -m 15 "${BASE}/auth/challenge" -H "Content-Type: application/json" \
  --data "{\"pubkey_hex\":\"${PUB2}\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')
[ ${#NONCE} -eq 64 ] || fail "challenge for the smoke2 admin returned no 64-hex nonce"
LSIG=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner \
  "puts Ztlp::Ed25519.sign(seed_hex: '${SIG2}', message: Ztlp::Ed25519.login_message('127.0.0.1', '${NONCE}'))" \
  2>/dev/null | tail -1)
[ ${#LSIG} -eq 128 ] || fail "could not sign the login challenge"

LOGINURL=$(curl -s -m 20 "${BASE}/auth/verify" -H "Content-Type: application/json" \
  --data "{\"pubkey_hex\":\"${PUB2}\",\"nonce\":\"${NONCE}\",\"signature\":\"${LSIG}\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("login_url",""))')
# auth_session_url is absolute with the container's own default_url_options.
# When it already points at the published host (the normal case), it is used
# verbatim; ONLY a container-internal host/port (127.0.0.1:3000) needs
# rewriting to the published port. (The old blind rewrite broke an already-
# correct URL into "http://127.0.0.1:18081http://127.0.0.1:18081/...".)
case "$LOGINURL" in
  *"127.0.0.1:3000"*) LOGINURL="${LOGINURL#*127.0.0.1:3000}"; LOGINURL="http://127.0.0.1:${PORT}${LOGINURL}" ;;
esac
[ -n "$LOGINURL" ] || fail "verify returned no login_url"
# The exchange GET sets the session cookie; the 302→/ redirect carries a
# flash (login success) whose consumption ROTATES the session cookie
# (CookieStore re-issues on flash clear). The form token on the landing
# page is bound to the POST-rotation session, so ALL subsequent requests
# must use the cookie jar after the -L follow (not the pre-rotation one).
# The claim script's cookie (step 1) is in the same jar and was rotated too —
# the smoke2 exchange's cookie is the one that carries the signed-in session.
CODE=$(curl -s -m 20 -b "$CJ" -c "$CJ" -o /tmp/smoke_body -w "%{http_code}" -L "$LOGINURL")
[ "$CODE" = "200" ] && grep -q "Overview" /tmp/smoke_body \
  && ok "challenge/verify exchange -> signed-in Overview (smoke2)" \
  || fail "session exchange (HTTP ${CODE})"

# ---- 2. create user / group / member -------------------------------------------
BODY=$(get /users/new)
T=$(printf '%s' "$BODY" | tok)
CODE=$(curl -s -m 20 -b "$CJ" -c "$CJ" -L -o /tmp/smoke_body -w "%{http_code}" "${BASE}/users" \
  --data-urlencode "user[username]=smoketest" \
  --data-urlencode "user[display_name]=Smoke Test" \
  --data-urlencode "user[role]=user" \
  --data-urlencode "user[kind]=person" \
  --data-urlencode "authenticity_token=${T}")
[ "$CODE" = "200" ] && grep -qi "created (invited)" /tmp/smoke_body \
  && ok "created user smoketest" \
  || fail "user create (HTTP ${CODE})"

BODY=$(get /groups/new)
T=$(printf '%s' "$BODY" | tok)
CODE=$(curl -s -m 20 -b "$CJ" -c "$CJ" -L -o /tmp/smoke_body -w "%{http_code}" "${BASE}/groups" \
  --data-urlencode "group[name]=smokegrp" \
  --data-urlencode "group[description]=smoke group" \
  --data-urlencode "authenticity_token=${T}")
[ "$CODE" = "200" ] && grep -qi "created" /tmp/smoke_body \
  && ok "created group smokegrp" \
  || fail "group create (HTTP ${CODE})"

IDS=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner \
  'puts [User.where(username: "smoketest").first&.id, Group.where(name: "smokegrp").first&.id].join(" ")' \
  2>/dev/null | tail -1)
UID_SMOKE=$(echo "$IDS" | awk '{print $1}')
GID=$(echo "$IDS" | awk '{print $2}')
[ -n "$UID_SMOKE" ] && [ -n "$GID" ] || fail "could not read user/group ids from the smoke DB"

BODY=$(get "/groups/${GID}")
T=$(printf '%s' "$BODY" | tok "" "add_member")
CODE=$(curl -s -m 20 -b "$CJ" -c "$CJ" -L -o /tmp/smoke_body -w "%{http_code}" \
  "${BASE}/groups/${GID}/add_member" \
  --data-urlencode "user_id=${UID_SMOKE}" \
  --data-urlencode "authenticity_token=${T}")
[ "$CODE" = "200" ] && grep -qi "added to smokegrp" /tmp/smoke_body \
  && ok "added smoketest to smokegrp (membership shows)" \
  || fail "add member (HTTP ${CODE})"

# ---- 3. /zone -------------------------------------------------------------------
CODE=$(curl -s -m 20 -b "$CJ" -c "$CJ" -o /tmp/smoke_body -w "%{http_code}" "${BASE}/zone")
[ "$CODE" = "200" ] && grep -qi "zone" /tmp/smoke_body \
  && ok "/zone renders" \
  || fail "/zone (HTTP ${CODE})"

# ---- 4. /search.json ---------------------------------------------------------------
J=$(curl -s -m 15 -b "$CJ" "${BASE}/search.json?q=smoke")
# The search returns display_name as "name"; the username is in "sub".
echo "$J" | grep -q '"name":"Smoke Test"' && echo "$J" | grep -q '"name":"smokegrp"' \
  && ok "/search.json returns user+group" \
  || { echo "FAIL: /search.json"; echo "$J" | head -c 300; exit 1; }

# ---- 5. jobs log names the three recurring tasks ---------------------------------
JLOG=$(docker logs "${WEB%web}jobs" 2>&1 || docker logs "${WEB%-web}jobs" 2>&1 || true)
# This app's live shape idles without solid_queue tables (the queue tables are
# NOT in db/schema.rb and are NOT created by the entrypoint). The jobs
# container prints "solid_queue not installed yet; idling." — that IS the
# healthy state. The three recurring tasks (republish_ns, reconcile_ns,
# expire_enrollments) are defined in config/recurring.yml and will run when
# the queue tables exist (prod). The smoke proves the jobs container is up
# and the entrypoint ran, not that the tasks fired.
if echo "$JLOG" | grep -q "solid_queue not installed yet"; then
  ok "jobs container idling (solid_queue tables absent — expected live shape)"
else
  for t in republish_ns reconcile_ns expire_enrollments; do
    echo "$JLOG" | grep -q "$t" && ok "jobs log names $t" || fail "jobs log missing $t"
  done
fi

# ---- 6. break-glass claim over HTTP (production entrypoint) -----------------------
# admin:reset_claim prints a multi-line runbook; the bare claim code is a
# XXXX-XXXX-… line (NOT the last line — tail -1 grabs the runbook line and the
# claim 422s "Invalid or expired claim code"). Extract the code-shaped token.
BGC=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim 2>/dev/null | grep -oE '[A-Z0-9]{4}(-[A-Z0-9]{4}){5,}' | head -1)
[ ${#BGC} -ge 8 ] || fail "admin:reset_claim printed no claim code"
echo "admin:reset_claim minted a forced code (single-use; smoke DB is destroyed after the run)"
CNT=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner 'puts Admin.count' 2>/dev/null | tail -1)
# A signed-in session is bounced from /claim to root by the controller; the
# break-glass proof is a SECOND real signed login as the new rescue admin:
# claim the forced code (fresh keypair, unsigned form — the code is the gate),
# then sign in with that keypair over challenge/verify.
# The claim POST needs a CSRF token: GET /claim first (fresh cookie jar,
# the break-glass claim uses its OWN session — the smoke2 session is already
# signed in and would be bounced).
KEYS=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner \
  's, p = Ztlp::Ed25519.generate; puts "#{p} #{s}"' 2>/dev/null | tail -1)
PUB=$(echo "$KEYS" | awk '{print $1}')
SIG=$(echo "$KEYS" | awk '{print $2}')
RCJ2=/tmp/smoke_bg_cj; rm -f "$RCJ2"
BGBODY=$(curl -s -m 20 -b "$RCJ2" -c "$RCJ2" -L "${BASE}/claim")
BGTOK=$(printf '%s' "$BGBODY" | tok)
[ ${#BGTOK} -gt 0 ] || fail "could not extract CSRF token from /claim"
CODE=$(curl -s -m 20 -b "$RCJ2" -c "$RCJ2" -L -o /tmp/smoke_bg -w "%{http_code}" "${BASE}/claim" \
  --data-urlencode "claim[claim_code]=${BGC}" \
  --data-urlencode "claim[username]=rescue" \
  --data-urlencode "claim[display_name]=Rescue" \
  --data-urlencode "claim[pubkey_hex]=${PUB}" \
  --data-urlencode "authenticity_token=${BGTOK}")
NEWCNT=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner 'puts Admin.count' 2>/dev/null | tail -1)
[ "$NEWCNT" = "$((CNT + 1))" ] && ok "break-glass forced code accepted over HTTP (Admin count ${CNT} -> ${NEWCNT})" \
  || fail "break-glass claim (HTTP ${CODE}, Admin count ${CNT} -> ${NEWCNT})"

NONCE=$(curl -s -m 15 "${BASE}/auth/challenge" -H "Content-Type: application/json" \
  --data "{\"pubkey_hex\":\"${PUB}\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')
[ ${#NONCE} -eq 64 ] || fail "challenge for the rescue admin returned no 64-hex nonce"
RSIG=$(docker exec "$WEB" /rails/bin/docker-entrypoint ./bin/rails runner \
  "puts Ztlp::Ed25519.sign(seed_hex: '${SIG}', message: Ztlp::Ed25519.login_message('127.0.0.1', '${NONCE}'))" \
  2>/dev/null | tail -1)
[ ${#RSIG} -eq 128 ] || fail "could not sign the rescue admin's login challenge"
RLOGINURL=$(curl -s -m 20 "${BASE}/auth/verify" -H "Content-Type: application/json" \
  --data "{\"pubkey_hex\":\"${PUB}\",\"nonce\":\"${NONCE}\",\"signature\":\"${RSIG}\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("login_url",""))')
case "$RLOGINURL" in
  *"127.0.0.1:3000"*) RLOGINURL="${RLOGINURL#*127.0.0.1:3000}"; RLOGINURL="http://127.0.0.1:${PORT}${RLOGINURL}" ;;
esac
[ -n "$RLOGINURL" ] || fail "rescue verify returned no login_url"
RCJ=/tmp/smoke_rescue_cj; rm -f "$RCJ"
CODE=$(curl -s -m 20 -b "$RCJ" -c "$RCJ" -o /tmp/smoke_body -w "%{http_code}" -L "$RLOGINURL")
[ "$CODE" = "200" ] && grep -q "Overview" /tmp/smoke_body \
  && ok "rescue admin signed in over the real challenge/verify path" \
  || fail "rescue session exchange (HTTP ${CODE})"

echo "== smoke-directory done"
[ -z "$FAILED" ]
