#!/usr/bin/env bash
set -euo pipefail

# ZTLP server-side preflight validation
# Runs infra checks that should be green before Steve tests on phone.

NS_HOST="${NS_HOST:-34.217.62.46}"
RELAY_HOST="${RELAY_HOST:-34.219.64.205}"
GATEWAY_HOST="${GATEWAY_HOST:-44.246.33.34}"
BOOTSTRAP_API="${BOOTSTRAP_API:-http://10.69.95.12:3000/api/benchmarks?limit=5}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-2f07983068c5dd5ffdf22cf24e4724389b4430c12659942f0af735f86c010079}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=8)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

FAILS=0
WARNS=0

section() {
  echo
  echo -e "${BLUE}== $1 ==${NC}"
}

pass() {
  echo -e "${GREEN}PASS${NC} $1"
}

warn() {
  echo -e "${YELLOW}WARN${NC} $1"
  WARNS=$((WARNS + 1))
}

fail() {
  echo -e "${RED}FAIL${NC} $1"
  FAILS=$((FAILS + 1))
}

run_ssh() {
  local host="$1"
  shift
  ssh "${SSH_OPTS[@]}" "ubuntu@${host}" "$@"
}

section "NS checks (${NS_HOST})"
if run_ssh "$NS_HOST" "docker ps --filter name=ztlp-ns --format '{{.Names}} {{.Status}} {{.Ports}}'" >/tmp/ztlp_ns_status.txt 2>/tmp/ztlp_ns_err.txt; then
  cat /tmp/ztlp_ns_status.txt
  if grep -q 'ztlp-ns Up' /tmp/ztlp_ns_status.txt; then
    pass "NS container is running"
  else
    fail "NS container is not running"
  fi
else
  fail "Cannot SSH to NS host"
fi

if run_ssh "$NS_HOST" "docker inspect ztlp-ns --format '{{range .Config.Env}}{{println .}}{{end}}'" >/tmp/ztlp_ns_env.txt 2>/dev/null; then
  grep -q 'ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false' /tmp/ztlp_ns_env.txt && pass "NS registration auth disabled for current bootstrap path" || fail "NS registration auth flag missing"
  grep -q 'ZTLP_NS_RELAY_RECORDS=name=techrockstars,' /tmp/ztlp_ns_env.txt && pass "NS relay record typo fixed" || fail "NS relay record still wrong"
fi

if run_ssh "$NS_HOST" "docker logs ztlp-ns --tail 20 2>&1" >/tmp/ztlp_ns_logs.txt 2>/dev/null; then
  grep -q 'Seeded relay: techrockstars' /tmp/ztlp_ns_logs.txt && pass "NS seeded relay record on startup" || warn "Did not see relay seeding in recent NS logs"
fi

section "Relay checks (${RELAY_HOST})"
if run_ssh "$RELAY_HOST" "docker ps --filter name=ztlp-relay --format '{{.Names}} {{.Image}} {{.Status}}'" >/tmp/ztlp_relay_status.txt 2>/tmp/ztlp_relay_err.txt; then
  cat /tmp/ztlp_relay_status.txt
  grep -q 'ztlp-relay .* Up' /tmp/ztlp_relay_status.txt && pass "Relay container is running" || fail "Relay container is not running"
else
  fail "Cannot SSH to relay host"
fi

if run_ssh "$RELAY_HOST" "docker logs ztlp-relay --since 2m 2>&1" >/tmp/ztlp_relay_logs.txt 2>/dev/null; then
  if grep -q 'Registered dynamic gateway' /tmp/ztlp_relay_logs.txt; then
    pass "Relay is receiving gateway registrations"
  else
    fail "Relay is not seeing fresh gateway registrations"
  fi
fi

section "Gateway checks (${GATEWAY_HOST})"
if run_ssh "$GATEWAY_HOST" "docker ps --filter name=ztlp-gateway --format '{{.Names}} {{.Image}} {{.Status}}'" >/tmp/ztlp_gw_status.txt 2>/tmp/ztlp_gw_err.txt; then
  cat /tmp/ztlp_gw_status.txt
  grep -q 'ztlp-gateway .* Up' /tmp/ztlp_gw_status.txt && pass "Gateway container is running" || fail "Gateway container is not running"
else
  fail "Cannot SSH to gateway host"
fi

if run_ssh "$GATEWAY_HOST" "docker inspect ztlp-gateway --format '{{.HostConfig.NetworkMode}}'" >/tmp/ztlp_gw_net.txt 2>/dev/null; then
  cat /tmp/ztlp_gw_net.txt
  grep -qx 'host' /tmp/ztlp_gw_net.txt && pass "Gateway uses host networking" || fail "Gateway is not using host networking"
fi

if run_ssh "$GATEWAY_HOST" "docker exec ztlp-gateway /app/bin/ztlp_gateway rpc \"IO.inspect({ZtlpGateway.Config.get(:ns_server_host), ZtlpGateway.Config.get(:ns_server_port)})\"" >/tmp/ztlp_gw_ns_rpc.txt 2>/dev/null; then
  cat /tmp/ztlp_gw_ns_rpc.txt
  grep -q '{{172, 26, 13, 85}, 23096}' /tmp/ztlp_gw_ns_rpc.txt && pass "Gateway runtime NS config is correct" || fail "Gateway runtime NS config is wrong"
else
  fail "Could not query gateway runtime NS config"
fi

if run_ssh "$GATEWAY_HOST" "for p in 8080 8180; do timeout 2 bash -lc '</dev/tcp/127.0.0.1/'\"\$p\"'' && echo PORT:\$p:OK || echo PORT:\$p:FAIL; done" >/tmp/ztlp_gw_ports.txt 2>/dev/null; then
  cat /tmp/ztlp_gw_ports.txt
  grep -q 'PORT:8080:OK' /tmp/ztlp_gw_ports.txt && pass "Gateway can reach backend 127.0.0.1:8080" || fail "Gateway cannot reach backend 127.0.0.1:8080"
  grep -q 'PORT:8180:OK' /tmp/ztlp_gw_ports.txt && pass "Gateway can reach backend 127.0.0.1:8180" || fail "Gateway cannot reach backend 127.0.0.1:8180"
fi

if run_ssh "$GATEWAY_HOST" "docker logs ztlp-gateway --since 10m 2>&1" >/tmp/ztlp_gw_logs.txt 2>/dev/null; then
  if grep -q 'Backend connect failed: {:connect_failed, :econnrefused}' /tmp/ztlp_gw_logs.txt; then
    fail "Gateway still shows backend econnrefused in recent logs"
  else
    pass "No backend econnrefused seen in recent gateway logs"
  fi

  if grep -q 'send_queue already overloaded' /tmp/ztlp_gw_logs.txt; then
    fail "Gateway still rejecting mux streams due to send_queue overload"
  else
    pass "No send_queue overload rejections seen in recent gateway logs"
  fi

  if grep -q 'Sent msg2' /tmp/ztlp_gw_logs.txt; then
    pass "Gateway is actively completing handshake step msg2"
  else
    warn "No recent handshake activity observed"
  fi
fi

section "Gateway -> NS UDP synthetic query"
if run_ssh "$GATEWAY_HOST" "docker exec ztlp-gateway /app/bin/ztlp_gateway rpc \"{:ok, sock} = :gen_udp.open(0, [:binary, active: false]); name = \\\"test\\\"; packet = <<0x01, byte_size(name)::16, name::binary, 0x02::8>>; :gen_udp.send(sock, {172,26,13,85}, 23096, packet); result = :gen_udp.recv(sock, 0, 3000); :gen_udp.close(sock); IO.inspect(result)\"" >/tmp/ztlp_ns_query.txt 2>/dev/null; then
  cat /tmp/ztlp_ns_query.txt
  grep -q '{:ok,' /tmp/ztlp_ns_query.txt && pass "Gateway can query NS over UDP" || fail "Gateway could not query NS over UDP"
else
  fail "Synthetic gateway->NS query failed"
fi

section "Bootstrap benchmark API"
if curl -fsS -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" "$BOOTSTRAP_API" >/tmp/ztlp_bench_api.json 2>/tmp/ztlp_bench_api.err; then
  pass "Bootstrap benchmark API reachable"
  python3 - <<'PY'
import json, sys
obj=json.load(open('/tmp/ztlp_bench_api.json'))
items=obj if isinstance(obj,list) else obj.get('benchmarks') or obj.get('data') or obj
if isinstance(items,dict): items=[items]
print(f"recent_records={len(items)}")
for b in items[:3]:
    print(f"id={b.get('id')} score={b.get('benchmarks_passed')}/{b.get('benchmarks_total')} err={b.get('error_details')} logs={'yes' if (b.get('device_logs') or '') else 'no'} gw={b.get('gateway_address')}")
PY
else
  fail "Bootstrap benchmark API unreachable"
fi

section "Summary"
echo "warnings=${WARNS} failures=${FAILS}"
if [[ "$FAILS" -eq 0 ]]; then
  echo -e "${GREEN}PRECHECK GREEN${NC} server-side stack is ready for phone testing"
  exit 0
else
  echo -e "${RED}PRECHECK RED${NC} fix the failures above before phone testing"
  exit 1
fi
