#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 12: NS Federation — Network Partition
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP-NS behavior during network partitions:
#   1. Start with healthy 3-node cluster
#   2. Insert records on ns-1, verify replicated to all
#   3. Partition ns-3 by disconnecting from the infra network
#   4. Insert a new record on ns-1 during partition
#   5. Verify ns-2 gets it but ns-3 doesn't
#   6. Heal the partition (reconnect ns-3)
#   7. Wait for anti-entropy sync
#   8. Verify ns-3 now has all records

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "ns-federation-partition"

NS1_CONTAINER="ztlp-test-ns"
NS2_CONTAINER="ztlp-test-ns-2"
NS3_CONTAINER="ztlp-test-ns-3"

COOKIE="ztlp_test_cookie"

# Docker network name (compose project prefixes it)
INFRA_NETWORK=$(docker inspect "$NS1_CONTAINER" --format='{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}{{"\n"}}{{end}}' 2>/dev/null | grep infra | head -1)

# Helper: insert a signed test record via RPC
ns_insert_record() {
    local container="$1"
    local target_node="$2"
    local record_name="$3"
    local serial="$4"
    local tmp_name="tmp_ins_$(date +%s%N)@$(hostname)"

    docker exec "$container" elixir \
        --name "$tmp_name" \
        --cookie "$COOKIE" \
        -e "
Node.connect(:\"$target_node\")
result = :rpc.call(:\"$target_node\", Code, :eval_string, [
  ~s(
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    record = %ZtlpNs.Record{
      name: \"$record_name\",
      type: :key,
      data: %{node_id: Base.encode16(pub, case: :lower), public_key: Base.encode16(pub, case: :lower), algorithm: \"Ed25519\"},
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: $serial
    }
    signed = ZtlpNs.Record.sign(record, priv)
    ZtlpNs.Store.insert(signed)
  )
])
case result do
  {:ok, _binding} -> IO.puts(\"INSERT_OK\")
  {val, _binding} -> IO.puts(inspect(val))
  {:badrpc, reason} -> IO.puts(\"BADRPC:\" <> inspect(reason))
end
" 2>/dev/null
}

# Helper: lookup a record by name on a given node
ns_lookup_record() {
    local container="$1"
    local target_node="$2"
    local record_name="$3"
    local tmp_name="tmp_lkp_$(date +%s%N)@$(hostname)"

    docker exec "$container" elixir \
        --name "$tmp_name" \
        --cookie "$COOKIE" \
        -e "
Node.connect(:\"$target_node\")
result = :rpc.call(:\"$target_node\", ZtlpNs.Store, :lookup, [\"$record_name\", :key])
case result do
  {:ok, rec} -> IO.puts(\"FOUND:serial=#{rec.serial}\")
  :not_found -> IO.puts(\"NOT_FOUND\")
  {:error, reason} -> IO.puts(\"ERROR:\" <> inspect(reason))
  {:badrpc, reason} -> IO.puts(\"BADRPC:\" <> inspect(reason))
end
" 2>/dev/null
}

# Helper: lookup a record locally via UDP (for use when ns-3 is network-partitioned)
# Uses UDP query to localhost:23096, which always works regardless of network state
ns_lookup_local() {
    local container="$1"
    local node_name="$2"  # unused but kept for API consistency
    local record_name="$3"

    docker exec "$container" python3 -c "
import socket, struct, sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
name = b'$record_name'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])  # type 1 = KEY
s.sendto(query, ('127.0.0.1', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    if status == 0x02:
        print('FOUND:serial=unknown')  # UDP response doesn't easily give serial
    elif status == 0x03:
        print('NOT_FOUND')
    else:
        print(f'ERROR:unexpected_status_0x{status:02x}')
except socket.timeout:
    print('ERROR:timeout')
s.close()
" 2>&1
}

# Helper: partition ns-3 from the infra network
ns3_partition() {
    log_info "Partitioning ns-3: disconnecting from infra network..."
    docker network disconnect "$INFRA_NETWORK" "$NS3_CONTAINER" 2>/dev/null
    log_info "  ns-3 disconnected from $INFRA_NETWORK"
}

# Helper: heal the ns-3 partition
ns3_heal() {
    log_info "Healing ns-3 partition: reconnecting to infra network..."
    docker network connect "$INFRA_NETWORK" "$NS3_CONTAINER" --alias ns-3 2>/dev/null || true
    log_info "  ns-3 reconnected to $INFRA_NETWORK"
}

# ── Step 1: Verify healthy 3-node cluster ────────────────────
log_header "Verify healthy 3-node cluster"

log_step "Waiting for all NS nodes..."
wait_for_service "$NS1_CONTAINER" 23096 60
wait_for_service "$NS2_CONTAINER" 23096 60
wait_for_service "$NS3_CONTAINER" 23096 60
sleep 10

log_step "Detected infra network: $INFRA_NETWORK"

log_step "Checking cluster membership..."
MEMBERS=$(docker exec "$NS1_CONTAINER" elixir \
    --name "tmp_chk_$(date +%s%N)@ns" \
    --cookie "$COOKIE" \
    -e "
Node.connect(:'ns@ns')
members = :rpc.call(:'ns@ns', ZtlpNs.Cluster, :members, [])
IO.puts(inspect(Enum.sort(members)))
" 2>/dev/null)
echo "  Cluster members: $MEMBERS"
assert_contains "Cluster has ns@ns" "ns@ns" "$MEMBERS"
assert_contains "Cluster has ns2@ns-2" "ns2@ns-2" "$MEMBERS"
assert_contains "Cluster has ns3@ns-3" "ns3@ns-3" "$MEMBERS"

# ── Step 2: Insert pre-partition record, verify replicated ───
log_header "Pre-partition record insertion"

PRE_RECORD="partition-pre.ztlp"

log_step "Inserting '$PRE_RECORD' on ns-1 (serial 100)..."
INSERT_PRE=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$PRE_RECORD" 100)
assert_contains "Pre-partition record inserted" "ok" "$INSERT_PRE"

sleep 3

log_step "Verifying replication to ns-2..."
LOOKUP_PRE_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$PRE_RECORD")
assert_contains "Pre-partition record on ns-2" "FOUND" "$LOOKUP_PRE_NS2"

log_step "Verifying replication to ns-3..."
LOOKUP_PRE_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_RECORD")
assert_contains "Pre-partition record on ns-3" "FOUND" "$LOOKUP_PRE_NS3"

# ── Step 3: Create network partition (isolate ns-3) ──────────
log_header "Creating network partition"

ns3_partition
sleep 3

# ── Step 4: Insert record during partition ───────────────────
log_header "Record insertion during partition"

DURING_RECORD="partition-during.ztlp"

log_step "Inserting '$DURING_RECORD' on ns-1 (serial 200)..."
INSERT_DURING=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$DURING_RECORD" 200)
assert_contains "During-partition record inserted" "ok" "$INSERT_DURING"

sleep 3

# ── Step 5: Verify ns-2 has it but ns-3 doesn't ─────────────
log_header "Partition verification"

log_step "Checking ns-2 has the new record..."
LOOKUP_DURING_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$DURING_RECORD")
echo "  ns-2 lookup: $LOOKUP_DURING_NS2"
assert_contains "During-partition record on ns-2" "FOUND" "$LOOKUP_DURING_NS2"

log_step "Checking ns-3 does NOT have the new record..."
# ns-3 is disconnected, so we query it locally
LOOKUP_DURING_NS3=$(ns_lookup_local "$NS3_CONTAINER" "ns3@ns-3" "$DURING_RECORD")
echo "  ns-3 lookup: $LOOKUP_DURING_NS3"
assert_contains "During-partition record missing from ns-3" "NOT_FOUND" "$LOOKUP_DURING_NS3"

# ── Step 6: Heal partition ───────────────────────────────────
log_header "Healing partition"

ns3_heal
sleep 5

# ── Step 7: Wait for anti-entropy sync ──────────────────────
log_header "Anti-entropy sync"

# Anti-entropy interval defaults to 30s. Wait up to 60 seconds.
log_step "Waiting for anti-entropy to sync ns-3 (up to 60s)..."

SYNC_SUCCESS=false
for attempt in $(seq 1 20); do
    LOOKUP_SYNC=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$DURING_RECORD" 2>/dev/null)
    if echo "$LOOKUP_SYNC" | grep -q "FOUND"; then
        SYNC_SUCCESS=true
        log_info "  ns-3 synced after ~$((attempt * 3))s"
        break
    fi
    sleep 3
done

# ── Step 8: Verify ns-3 has all records ──────────────────────
log_header "Post-heal verification"

if $SYNC_SUCCESS; then
    record_pass "Anti-entropy synced during-partition record to ns-3"
else
    record_fail "Anti-entropy did not sync to ns-3 within 60s"
fi

log_step "Verifying ns-3 has pre-partition record..."
LOOKUP_POST_PRE=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_RECORD")
assert_contains "Pre-partition record still on ns-3" "FOUND" "$LOOKUP_POST_PRE"

log_step "Verifying ns-3 has during-partition record..."
LOOKUP_POST_DURING=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$DURING_RECORD")
assert_contains "During-partition record now on ns-3" "FOUND" "$LOOKUP_POST_DURING"
assert_contains "During-partition record has correct serial" "serial=200" "$LOOKUP_POST_DURING"

# ── Cleanup ──────────────────────────────────────────────────
ns3_heal  # Ensure reconnected even if test failed mid-way

# ── Results ──────────────────────────────────────────────────
end_scenario
