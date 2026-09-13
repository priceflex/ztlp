#!/usr/bin/env bash
# ==============================================================================
# ZTLP cloud demo — one-shot SHIP + BRINGUP from a fast workstation
# ==============================================================================
# Runs on your workstation (where docker can build quickly). Builds the five
# demo images, ships them + the config files to the cloud box, and brings the
# stack up from a clean slate, then runs the green checks from
# demo/CLOUD-QUICKSTART.md. Exits non-zero if any check fails.
#
# Usage (from the repo root or demo/):
#   demo/ship-cloud-demo.sh [--no-wipe] [--no-build] [ubuntu@44.240.16.59] [~/.ssh/ztlp-defcon-demo.pem]
#
#   --no-wipe   restart without wiping /var/lib/ztlp/{ca,gateway}. Keeps the
#               gateway QUIC cert, so existing clients keep their TOFU pin.
#               Default (wipe) = true clean slate; every previously-enrolled
#               client must `rm ~/.ztlp/quic_pins/localhost.pin`.
#   --no-build  skip `docker compose build` (reuse local images).
#
# Env overrides: BOX, KEY, REMOTE_DIR (default ~/ztlp/demo on the box).
# ==============================================================================
set -euo pipefail

WIPE=1; BUILD=1
POSITIONAL=()
for a in "$@"; do
    case "$a" in
        --no-wipe)  WIPE=0 ;;
        --no-build) BUILD=0 ;;
        -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
        *) POSITIONAL+=("$a") ;;
    esac
done
BOX="${POSITIONAL[0]:-${BOX:-ubuntu@44.240.16.59}}"
KEY="${POSITIONAL[1]:-${KEY:-$HOME/.ssh/ztlp-defcon-demo.pem}}"
REMOTE_DIR="${REMOTE_DIR:-~/ztlp/demo}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
COMPOSE="$HERE/defcon-cloud-compose.yml"
TAR=/tmp/ztlp-demo-images.tar
IMAGES=(demo-ns demo-relay1 demo-relay2 demo-gateway demo-dashboard)
# Everything the compose file mounts. scp preserves 0600; ns/gateway run as
# uid 999 and need world-readable, so EVERY file here gets chmod 644 remotely.
SHIP_FILES=(defcon-cloud-compose.yml gateway-config.yaml gateway-identity.key ns-config.yaml ns-registration.key)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
step()    { echo -e "${GREEN}▶${RESET} ${BOLD}$1${RESET}"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; }
ok()      { echo -e "  ${GREEN}✓${RESET} $1"; }

SSH=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=15 "$BOX")
SCP=(scp -q -i "$KEY")

[[ -f "$COMPOSE" ]] || { fail "compose file missing: $COMPOSE"; exit 1; }
[[ -r "$KEY" ]]     || { fail "ssh key not readable: $KEY"; exit 1; }
for f in "${SHIP_FILES[@]}"; do [[ -f "$HERE/$f" ]] || { fail "missing $HERE/$f"; exit 1; }; done

step "Target: $BOX  (key $KEY, remote dir $REMOTE_DIR, wipe=$WIPE, build=$BUILD)"
"${SSH[@]}" 'echo ok' >/dev/null || { fail "cannot ssh to $BOX"; exit 1; }
ok "ssh reachable"

if (( BUILD )); then
    step "Building images locally"
    docker compose -f "$COMPOSE" build
fi
for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || { fail "image $img not present (run without --no-build)"; exit 1; }
done

step "Saving images -> $TAR"
docker save "${IMAGES[@]}" -o "$TAR"
ok "$(du -h "$TAR" | cut -f1)"

step "Shipping tar + config files"
"${SSH[@]}" "mkdir -p $REMOTE_DIR /tmp"
"${SCP[@]}" "$TAR" "$BOX:/tmp/"
( cd "$HERE" && "${SCP[@]}" "${SHIP_FILES[@]}" "$BOX:$REMOTE_DIR/" )
ok "shipped ${#SHIP_FILES[@]} files + images"

step "Remote: chmod 644, load, $( ((WIPE)) && echo 'clean-slate' || echo 'restart (no wipe)' ), up -d"
"${SSH[@]}" "set -e
cd $REMOTE_DIR
chmod 644 ${SHIP_FILES[*]}
sudo mkdir -p /var/lib/ztlp/ca /var/lib/ztlp/gateway && sudo chmod 777 /var/lib/ztlp/ca /var/lib/ztlp/gateway
sudo docker load -i /tmp/ztlp-demo-images.tar >/dev/null && rm -f /tmp/ztlp-demo-images.tar
sudo docker compose -f defcon-cloud-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
if [ $WIPE = 1 ]; then sudo rm -rf /var/lib/ztlp/ca/* /var/lib/ztlp/gateway/*; fi
sudo docker compose -f defcon-cloud-compose.yml up -d
"
ok "stack started"

step "Waiting for health (up to 90 s)"
for i in $(seq 1 18); do
    healthy=$("${SSH[@]}" "sudo docker ps --filter health=healthy --format '{{.Names}}' | grep -c defcon || true")
    provisioned=$("${SSH[@]}" "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -c 'All certs provisioned' || true")
    if [[ "$healthy" -ge 4 && "$provisioned" -ge 1 ]]; then break; fi
    sleep 5
done

step "Green checks"
FAILS=0
check() {  # check <label> <remote-cmd> <expected-grep-regex>
    local label=$1 cmd=$2 want=$3 out
    out=$("${SSH[@]}" "$cmd" 2>&1 || true)
    if grep -qE -- "$want" <<<"$out"; then ok "$label"; else fail "$label"; echo "      got: ${out:0:300}"; FAILS=$((FAILS+1)); fi
}
check "5 containers up, 4 healthy"            "sudo docker ps --filter health=healthy --format '{{.Names}}' | grep -c defcon" '^4$'
check "ns: Config loaded (component_auth)"    "sudo docker logs ztlp-ns-defcon 2>&1 | grep -c 'Config loaded'" '^[1-9]'
check "ns: no eacces"                         "sudo docker logs ztlp-ns-defcon 2>&1 | grep -ci eacces" '^0$'
check "gateway: Config loaded"                "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -c 'Config loaded'" '^[1-9]'
check "gateway: QUIC listening :23097"        "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -c 'QUIC listening on UDP 23097'" '^[1-9]'
check "gateway: SVC registered"               "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -c 'Registered demo-dashboard.defcon.ztlp'" '^[1-9]'
check "gateway: All certs provisioned"        "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -c 'All certs provisioned'" '^[1-9]'
check "gateway: 0 unauthorized/eacces"        "sudo docker logs ztlp-gateway-defcon 2>&1 | grep -ciE 'unauthorized|eacces'" '^0$'
check "relay1: gateway registered (0x0D)"     "sudo docker logs ztlp-relay1-defcon 2>&1 | grep GATEWAY_REGISTER_ADDR | tail -1" 'declares \{\{172, ?42, ?90, ?30\}, ?23097\}'
check "dashboard: /api/health ok"             "curl -s localhost:8420/api/health" '"status":"ok"'

echo
if (( FAILS )); then fail "$FAILS check(s) failed"; exit 1; fi
ok "ALL GREEN — stack ready on $BOX"
if (( WIPE )); then
    info "clean slate regenerated the gateway QUIC cert: existing clients must  rm ~/.ztlp/quic_pins/localhost.pin"
fi
