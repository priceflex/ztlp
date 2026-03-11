#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 13: NS Federation — Conflict Resolution
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP-NS conflict resolution (higher serial wins):
#   1. Start 3-node cluster
#   2. Create a record on ns-1 with serial 100
#   3. Verify replicated to all nodes
#   4. Partition ns-3 (docker network disconnect)
#   5. Update the record on ns-1 with serial 200 (replicates to ns-2 only)
#   6. Reconnect ns-3 (still has serial 100)
#   7. Immediately insert conflicting record on ns-3 with serial 150
#   8. Wait for anti-entropy to propagate serial 200 to ns-3
#   9. Verify serial 200 wins everywhere (higher serial wins)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "ns-federation-conflict"

NS1_CONTAINER="ztlp-test-ns"
NS2_CONTAINER="ztlp-test-ns-2"
NS3_CONTAINER="ztlp-test-ns-3"

COOKIE="ztlp_test_cookie"

# Docker network name (compose project prefixes it)
INFRA_NETWORK=$(docker inspect "$NS1_CONTAINER" --format='{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}{{"\n"}}{{end}}' 2>/dev/null | grep infra | head -1)

# Helper: insert a signed test record via RPC with a deterministic keypair
# Uses the same key seed so the same name+type can be updated with higher serial
ns_insert_record_with_key() {
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
    seed = :crypto.hash(:sha256, \"ztlp-federation-conflict-test-key\")
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, seed)
    pub_hex = Base.encode16(pub, case: :lower)
    record = %ZtlpNs.Record{
      name: \"$record_name\",
      type: :key,
      data: %{node_id: pub_hex, public_key: pub_hex, algorithm: \"Ed25519\"},
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

# Helper: insert a record with replicated: true (skip eager replication)
ns_insert_no_replicate() {
    local container="$1"
    local target_node="$2"
    local record_name="$3"
    local serial="$4"
    local tmp_name="tmp_nr_$(date +%s%N)@$(hostname)"

    docker exec "$container" elixir \
        --name "$tmp_name" \
        --cookie "$COOKIE" \
        -e "
Node.connect(:\"$target_node\")
result = :rpc.call(:\"$target_node\", Code, :eval_string, [
  ~s(
    seed = :crypto.hash(:sha256, \"ztlp-federation-conflict-test-key\")
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, seed)
    pub_hex = Base.encode16(pub, case: :lower)
    record = %ZtlpNs.Record{
      name: \"$record_name\",
      type: :key,
      data: %{node_id: pub_hex, public_key: pub_hex, algorithm: \"Ed25519\"},
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: $serial
    }
    signed = ZtlpNs.Record.sign(record, priv)
    ZtlpNs.Store.insert(signed, replicated: true)
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

# Partition/heal helpers
ns3_partition() {
    log_info "Partitioning ns-3: disconnecting from infra network..."
    docker network disconnect "$INFRA_NETWORK" "$NS3_CONTAINER" 2>/dev/null
    log_info "  ns-3 disconnected from $INFRA_NETWORK"
}

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

# ── Step 2: Create record on ns-1 with serial 100 ───────────
log_header "Initial record creation"

CONFLICT_RECORD="conflict-test.ztlp"

log_step "Inserting '$CONFLICT_RECORD' on ns-1 (serial 100)..."
INSERT_INITIAL=$(ns_insert_record_with_key "$NS1_CONTAINER" "ns@ns" "$CONFLICT_RECORD" 100)
echo "  Insert result: $INSERT_INITIAL"
assert_contains "Initial record inserted on ns-1" "ok" "$INSERT_INITIAL"

# ── Step 3: Verify replicated to all nodes ───────────────────
log_header "Verify initial replication"

sleep 3

log_step "Checking ns-2..."
LOOKUP_INIT_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$CONFLICT_RECORD")
echo "  ns-2: $LOOKUP_INIT_NS2"
assert_contains "Initial record on ns-2" "FOUND" "$LOOKUP_INIT_NS2"
assert_contains "Serial 100 on ns-2" "serial=100" "$LOOKUP_INIT_NS2"

log_step "Checking ns-3..."
LOOKUP_INIT_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$CONFLICT_RECORD")
echo "  ns-3: $LOOKUP_INIT_NS3"
assert_contains "Initial record on ns-3" "FOUND" "$LOOKUP_INIT_NS3"
assert_contains "Serial 100 on ns-3" "serial=100" "$LOOKUP_INIT_NS3"

# ── Step 4: Partition ns-3 ───────────────────────────────────
log_header "Creating network partition"

ns3_partition
sleep 3

# ── Step 5: Update record on ns-1 with serial 200 ───────────
log_header "Update record on ns-1 during partition"

log_step "Updating '$CONFLICT_RECORD' on ns-1 (serial 200)..."
INSERT_UPDATE=$(ns_insert_record_with_key "$NS1_CONTAINER" "ns@ns" "$CONFLICT_RECORD" 200)
echo "  Update result: $INSERT_UPDATE"
assert_contains "Updated record on ns-1" "ok" "$INSERT_UPDATE"

sleep 3

# Verify ns-2 has serial 200
log_step "Checking ns-2 has serial 200..."
LOOKUP_UPD_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$CONFLICT_RECORD")
echo "  ns-2: $LOOKUP_UPD_NS2"
assert_contains "Updated record on ns-2" "serial=200" "$LOOKUP_UPD_NS2"

# ── Step 6: Reconnect ns-3 (still has serial 100) ───────────
log_header "Reconnecting ns-3 and inserting conflicting record"

ns3_heal
sleep 3

# ── Step 7: Immediately insert conflicting record on ns-3 ───
# ns-3 still has serial 100 from before the partition.
# Insert serial 150 (higher than 100 so it's accepted, but lower than 200).
# Use replicated: true to prevent eager replication from immediately overwriting.
log_step "Inserting '$CONFLICT_RECORD' on ns-3 (serial 150, conflicting with serial 200)..."
INSERT_CONFLICT=$(ns_insert_no_replicate "$NS3_CONTAINER" "ns3@ns-3" "$CONFLICT_RECORD" 150)
echo "  Conflict insert result: $INSERT_CONFLICT"
assert_contains "Conflicting record inserted on ns-3" "ok" "$INSERT_CONFLICT"

# Verify ns-3 has serial 150 (not yet synced with ns-1's 200)
log_step "Verifying ns-3 currently has serial 150..."
LOOKUP_CONFLICT_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$CONFLICT_RECORD")
echo "  ns-3: $LOOKUP_CONFLICT_NS3"
assert_contains "ns-3 has conflicting serial 150" "serial=150" "$LOOKUP_CONFLICT_NS3"

# ── Step 8: Wait for anti-entropy to resolve conflict ────────
log_header "Anti-entropy conflict resolution"

log_step "Waiting for anti-entropy to resolve conflict (up to 60s)..."

RESOLVED=false
for attempt in $(seq 1 20); do
    LOOKUP_RESOLVE=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$CONFLICT_RECORD")
    if echo "$LOOKUP_RESOLVE" | grep -q "serial=200"; then
        RESOLVED=true
        log_info "  Conflict resolved after ~$((attempt * 3))s"
        break
    fi
    sleep 3
done

# ── Step 9: Verify serial 200 wins everywhere ───────────────
log_header "Conflict resolution verification"

if $RESOLVED; then
    record_pass "Anti-entropy resolved conflict: serial 200 wins on ns-3"
else
    record_fail "Conflict not resolved on ns-3 within 60s (expected serial 200)"
fi

log_step "Final check: ns-1 has serial 200..."
FINAL_NS1=$(ns_lookup_record "$NS1_CONTAINER" "ns@ns" "$CONFLICT_RECORD")
echo "  ns-1: $FINAL_NS1"
assert_contains "ns-1 final serial is 200" "serial=200" "$FINAL_NS1"

log_step "Final check: ns-2 has serial 200..."
FINAL_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$CONFLICT_RECORD")
echo "  ns-2: $FINAL_NS2"
assert_contains "ns-2 final serial is 200" "serial=200" "$FINAL_NS2"

log_step "Final check: ns-3 has serial 200..."
FINAL_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$CONFLICT_RECORD")
echo "  ns-3: $FINAL_NS3"
assert_contains "ns-3 final serial is 200" "serial=200" "$FINAL_NS3"

# ── Cleanup ──────────────────────────────────────────────────
ns3_heal  # Ensure reconnected even if test failed mid-way

# ── Results ──────────────────────────────────────────────────
end_scenario
