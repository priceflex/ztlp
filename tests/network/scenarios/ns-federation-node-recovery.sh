#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 14: NS Federation — Node Recovery
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP-NS node failure and recovery:
#   1. Start 3-node cluster
#   2. Insert records, verify replicated
#   3. Kill ns-3 container (docker kill)
#   4. Insert more records on ns-1
#   5. Restart ns-3 container
#   6. Wait for ns-3 to rejoin cluster and sync via anti-entropy
#   7. Verify ns-3 has all records (both pre-crash and post-crash)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "ns-federation-node-recovery"

NS1_CONTAINER="ztlp-test-ns"
NS2_CONTAINER="ztlp-test-ns-2"
NS3_CONTAINER="ztlp-test-ns-3"

COOKIE="ztlp_test_cookie"
COMPOSE_FILE="$TESTS_DIR/docker-compose.test.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

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

# Helper: check cluster membership count from ns-1
ns_cluster_member_count() {
    local tmp_name="tmp_cnt_$(date +%s%N)@$(hostname)"

    docker exec "$NS1_CONTAINER" elixir \
        --name "$tmp_name" \
        --cookie "$COOKIE" \
        -e "
Node.connect(:'ns@ns')
members = :rpc.call(:'ns@ns', ZtlpNs.Cluster, :members, [])
IO.puts(\"MEMBER_COUNT=#{length(members)}\")
IO.puts(\"MEMBERS=#{inspect(Enum.sort(members))}\")
" 2>/dev/null
}

# ── Step 1: Verify healthy 3-node cluster ────────────────────
log_header "Verify healthy 3-node cluster"

log_step "Waiting for all NS nodes..."
wait_for_service "$NS1_CONTAINER" 23096 60
wait_for_service "$NS2_CONTAINER" 23096 60
wait_for_service "$NS3_CONTAINER" 23096 60
sleep 10

log_step "Checking cluster membership..."
MEMBERS_INFO=$(ns_cluster_member_count)
echo "  $MEMBERS_INFO"
assert_contains "Cluster has 3 members" "MEMBER_COUNT=3" "$MEMBERS_INFO"

# ── Step 2: Insert pre-crash records, verify replicated ──────
log_header "Pre-crash record insertion"

PRE_CRASH_1="recovery-pre-1.ztlp"
PRE_CRASH_2="recovery-pre-2.ztlp"

log_step "Inserting '$PRE_CRASH_1' on ns-1 (serial 100)..."
INSERT_PRE1=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$PRE_CRASH_1" 100)
assert_contains "Pre-crash record 1 inserted" "ok" "$INSERT_PRE1"

log_step "Inserting '$PRE_CRASH_2' on ns-1 (serial 200)..."
INSERT_PRE2=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$PRE_CRASH_2" 200)
assert_contains "Pre-crash record 2 inserted" "ok" "$INSERT_PRE2"

sleep 3

log_step "Verifying replication to ns-3..."
LOOKUP_PRE1_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_CRASH_1")
assert_contains "Pre-crash record 1 on ns-3" "FOUND" "$LOOKUP_PRE1_NS3"

LOOKUP_PRE2_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_CRASH_2")
assert_contains "Pre-crash record 2 on ns-3" "FOUND" "$LOOKUP_PRE2_NS3"

# ── Step 3: Kill ns-3 container ──────────────────────────────
log_header "Killing ns-3"

log_step "Sending SIGKILL to ns-3 container..."
docker kill "$NS3_CONTAINER" 2>/dev/null
sleep 3

log_step "Verifying ns-3 is stopped..."
NS3_RUNNING=$(docker inspect -f '{{.State.Running}}' "$NS3_CONTAINER" 2>/dev/null || echo "not_found")
echo "  ns-3 running: $NS3_RUNNING"
assert_eq "ns-3 is stopped" "false" "$NS3_RUNNING"

log_step "Checking cluster membership without ns-3..."
MEMBERS_AFTER_KILL=$(ns_cluster_member_count)
echo "  $MEMBERS_AFTER_KILL"
# The running count should be 2 (ns-3 is down)
# Note: members() returns running_db_nodes, so ns-3 should be gone

# ── Step 4: Insert more records while ns-3 is down ──────────
log_header "Records inserted while ns-3 is down"

POST_CRASH_1="recovery-post-1.ztlp"
POST_CRASH_2="recovery-post-2.ztlp"
POST_CRASH_3="recovery-post-3.ztlp"

log_step "Inserting '$POST_CRASH_1' on ns-1 (serial 300)..."
INSERT_POST1=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$POST_CRASH_1" 300)
assert_contains "Post-crash record 1 inserted" "ok" "$INSERT_POST1"

log_step "Inserting '$POST_CRASH_2' on ns-1 (serial 400)..."
INSERT_POST2=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$POST_CRASH_2" 400)
assert_contains "Post-crash record 2 inserted" "ok" "$INSERT_POST2"

log_step "Inserting '$POST_CRASH_3' on ns-2 (serial 500)..."
INSERT_POST3=$(ns_insert_record "$NS2_CONTAINER" "ns2@ns-2" "$POST_CRASH_3" 500)
assert_contains "Post-crash record 3 inserted" "ok" "$INSERT_POST3"

sleep 2

# Verify ns-2 has the new records (still connected)
log_step "Verifying ns-2 has post-crash records..."
LOOKUP_POST1_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$POST_CRASH_1")
assert_contains "Post-crash record 1 on ns-2" "FOUND" "$LOOKUP_POST1_NS2"

LOOKUP_POST2_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$POST_CRASH_2")
assert_contains "Post-crash record 2 on ns-2" "FOUND" "$LOOKUP_POST2_NS2"

# ── Step 5: Restart ns-3 container ──────────────────────────
log_header "Restarting ns-3"

log_step "Starting ns-3 container..."
docker start "$NS3_CONTAINER" 2>/dev/null
sleep 5

log_step "Waiting for ns-3 to become healthy..."
HEALTHY=false
for attempt in $(seq 1 20); do
    HEALTH=$(docker inspect -f '{{.State.Health.Status}}' "$NS3_CONTAINER" 2>/dev/null || echo "unknown")
    if [[ "$HEALTH" == "healthy" ]]; then
        HEALTHY=true
        log_info "  ns-3 healthy after ~$((attempt * 3))s"
        break
    fi
    sleep 3
done

if $HEALTHY; then
    record_pass "ns-3 restarted and healthy"
else
    record_fail "ns-3 did not become healthy within 60s"
fi

# Give time for cluster rejoin
sleep 10

# ── Step 6: Wait for ns-3 to rejoin and sync ────────────────
log_header "Cluster rejoin and anti-entropy sync"

log_step "Checking if ns-3 rejoined the cluster..."
REJOIN_SUCCESS=false
for attempt in $(seq 1 10); do
    MEMBERS_REJOIN=$(ns_cluster_member_count)
    if echo "$MEMBERS_REJOIN" | grep -q "MEMBER_COUNT=3"; then
        REJOIN_SUCCESS=true
        log_info "  ns-3 rejoined cluster after ~$((attempt * 3))s"
        break
    fi
    sleep 3
done

if $REJOIN_SUCCESS; then
    record_pass "ns-3 rejoined the cluster"
else
    record_fail "ns-3 did not rejoin the cluster within 30s"
fi

log_step "Waiting for anti-entropy to sync records to ns-3 (up to 45s)..."
SYNC_SUCCESS=false
for attempt in $(seq 1 15); do
    # Check for a post-crash record — if this is synced, anti-entropy worked
    LOOKUP_SYNC=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$POST_CRASH_1")
    if echo "$LOOKUP_SYNC" | grep -q "FOUND"; then
        SYNC_SUCCESS=true
        log_info "  Anti-entropy synced after ~$((attempt * 3))s"
        break
    fi
    sleep 3
done

# ── Step 7: Verify ns-3 has ALL records ──────────────────────
log_header "Full record verification on recovered ns-3"

if $SYNC_SUCCESS; then
    record_pass "Anti-entropy synced post-crash records to ns-3"
else
    record_fail "Anti-entropy did not sync to ns-3 within 45s"
fi

# Pre-crash records (should be in Mnesia but ns-3 uses ram_copies so they're lost)
# Anti-entropy should re-sync them
log_step "Checking pre-crash record 1..."
FINAL_PRE1=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_CRASH_1")
echo "  ns-3: $FINAL_PRE1"
assert_contains "Pre-crash record 1 recovered on ns-3" "FOUND" "$FINAL_PRE1"
assert_contains "Pre-crash record 1 has correct serial" "serial=100" "$FINAL_PRE1"

log_step "Checking pre-crash record 2..."
FINAL_PRE2=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$PRE_CRASH_2")
echo "  ns-3: $FINAL_PRE2"
assert_contains "Pre-crash record 2 recovered on ns-3" "FOUND" "$FINAL_PRE2"
assert_contains "Pre-crash record 2 has correct serial" "serial=200" "$FINAL_PRE2"

# Post-crash records (written while ns-3 was down)
log_step "Checking post-crash record 1..."
FINAL_POST1=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$POST_CRASH_1")
echo "  ns-3: $FINAL_POST1"
assert_contains "Post-crash record 1 synced to ns-3" "FOUND" "$FINAL_POST1"
assert_contains "Post-crash record 1 has correct serial" "serial=300" "$FINAL_POST1"

log_step "Checking post-crash record 2..."
FINAL_POST2=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$POST_CRASH_2")
echo "  ns-3: $FINAL_POST2"
assert_contains "Post-crash record 2 synced to ns-3" "FOUND" "$FINAL_POST2"
assert_contains "Post-crash record 2 has correct serial" "serial=400" "$FINAL_POST2"

log_step "Checking post-crash record 3 (inserted on ns-2)..."
FINAL_POST3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$POST_CRASH_3")
echo "  ns-3: $FINAL_POST3"
assert_contains "Post-crash record 3 synced to ns-3" "FOUND" "$FINAL_POST3"
assert_contains "Post-crash record 3 has correct serial" "serial=500" "$FINAL_POST3"

# ── Results ──────────────────────────────────────────────────
end_scenario
