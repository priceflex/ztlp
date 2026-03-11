#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 11: NS Federation — Basic Cluster Formation
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP-NS cluster formation and eager replication:
#   1. Wait for all 3 NS nodes to be healthy
#   2. Query cluster status on each node
#   3. Verify all 3 nodes see each other as members
#   4. Insert a record on ns-1, verify replication to ns-2 and ns-3
#   5. Insert a record on ns-2, verify replication to ns-1 and ns-3

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "ns-federation-basic"

NS1_CONTAINER="ztlp-test-ns"
NS2_CONTAINER="ztlp-test-ns-2"
NS3_CONTAINER="ztlp-test-ns-3"

COOKIE="ztlp_test_cookie"

# Helper: run an Elixir RPC command on a target NS node
# Usage: ns_rpc <container> <node_name> <elixir_expression>
ns_rpc() {
    local container="$1"
    local target_node="$2"
    local expression="$3"
    local tmp_name="tmp_$(date +%s%N)@$(hostname)"

    docker exec "$container" elixir \
        --name "$tmp_name" \
        --cookie "$COOKIE" \
        -e "
Node.connect(:\"$target_node\")
result = :rpc.call(:\"$target_node\", Code, :eval_string, [\"$expression\"])
case result do
  {val, _binding} -> IO.puts(inspect(val))
  {:badrpc, reason} -> IO.puts(\"BADRPC:\" <> inspect(reason))
end
" 2>/dev/null
}

# Helper: insert a signed test record via RPC
# Usage: ns_insert_record <container> <node_name> <record_name> <serial>
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
# Usage: ns_lookup_record <container> <node_name> <record_name>
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

# ── Step 1: Wait for all 3 NS nodes to be healthy ────────────
log_header "Wait for NS cluster nodes"

log_step "Waiting for ns-1 (primary)..."
wait_for_service "$NS1_CONTAINER" 23096 60

log_step "Waiting for ns-2..."
wait_for_service "$NS2_CONTAINER" 23096 60

log_step "Waiting for ns-3..."
wait_for_service "$NS3_CONTAINER" 23096 60

# Give nodes time to complete cluster join
log_step "Allowing cluster formation to settle (10s)..."
sleep 10

# ── Step 2: Query cluster status on each node ────────────────
log_header "Cluster status verification"

log_step "Querying cluster status on ns-1..."
STATUS_NS1=$(ns_rpc "$NS1_CONTAINER" "ns@ns" "ZtlpNs.Cluster.status()")
echo "  ns-1 status: $STATUS_NS1"

log_step "Querying cluster status on ns-2..."
STATUS_NS2=$(ns_rpc "$NS2_CONTAINER" "ns2@ns-2" "ZtlpNs.Cluster.status()")
echo "  ns-2 status: $STATUS_NS2"

log_step "Querying cluster status on ns-3..."
STATUS_NS3=$(ns_rpc "$NS3_CONTAINER" "ns3@ns-3" "ZtlpNs.Cluster.status()")
echo "  ns-3 status: $STATUS_NS3"

# ── Step 3: Verify all nodes see each other ──────────────────
log_header "Cluster membership verification"

log_step "Checking ns-1 sees all members..."
MEMBERS_NS1=$(ns_rpc "$NS1_CONTAINER" "ns@ns" "ZtlpNs.Cluster.members() |> Enum.sort() |> Enum.join(\\\",\\\")")
echo "  ns-1 members: $MEMBERS_NS1"
assert_contains "ns-1 sees ns@ns" "ns@ns" "$MEMBERS_NS1"
assert_contains "ns-1 sees ns2@ns-2" "ns2@ns-2" "$MEMBERS_NS1"
assert_contains "ns-1 sees ns3@ns-3" "ns3@ns-3" "$MEMBERS_NS1"

log_step "Checking ns-2 sees all members..."
MEMBERS_NS2=$(ns_rpc "$NS2_CONTAINER" "ns2@ns-2" "ZtlpNs.Cluster.members() |> Enum.sort() |> Enum.join(\\\",\\\")")
echo "  ns-2 members: $MEMBERS_NS2"
assert_contains "ns-2 sees ns@ns" "ns@ns" "$MEMBERS_NS2"
assert_contains "ns-2 sees ns2@ns-2" "ns2@ns-2" "$MEMBERS_NS2"
assert_contains "ns-2 sees ns3@ns-3" "ns3@ns-3" "$MEMBERS_NS2"

log_step "Checking ns-3 sees all members..."
MEMBERS_NS3=$(ns_rpc "$NS3_CONTAINER" "ns3@ns-3" "ZtlpNs.Cluster.members() |> Enum.sort() |> Enum.join(\\\",\\\")")
echo "  ns-3 members: $MEMBERS_NS3"
assert_contains "ns-3 sees ns@ns" "ns@ns" "$MEMBERS_NS3"
assert_contains "ns-3 sees ns2@ns-2" "ns2@ns-2" "$MEMBERS_NS3"
assert_contains "ns-3 sees ns3@ns-3" "ns3@ns-3" "$MEMBERS_NS3"

# ── Step 4: Insert record on ns-1, verify replication ────────
log_header "Eager replication: ns-1 → ns-2, ns-3"

RECORD_NAME_1="federation-test-1.ztlp"

log_step "Inserting record '$RECORD_NAME_1' on ns-1 (serial 100)..."
INSERT_RESULT=$(ns_insert_record "$NS1_CONTAINER" "ns@ns" "$RECORD_NAME_1" 100)
echo "  Insert result: $INSERT_RESULT"
assert_contains "Record inserted on ns-1" "ok" "$INSERT_RESULT"

# Wait briefly for eager replication
sleep 3

log_step "Querying '$RECORD_NAME_1' on ns-2..."
LOOKUP_NS2=$(ns_lookup_record "$NS2_CONTAINER" "ns2@ns-2" "$RECORD_NAME_1")
echo "  ns-2 lookup: $LOOKUP_NS2"
assert_contains "Record replicated to ns-2" "FOUND" "$LOOKUP_NS2"
assert_contains "Record has correct serial on ns-2" "serial=100" "$LOOKUP_NS2"

log_step "Querying '$RECORD_NAME_1' on ns-3..."
LOOKUP_NS3=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$RECORD_NAME_1")
echo "  ns-3 lookup: $LOOKUP_NS3"
assert_contains "Record replicated to ns-3" "FOUND" "$LOOKUP_NS3"
assert_contains "Record has correct serial on ns-3" "serial=100" "$LOOKUP_NS3"

# ── Step 5: Insert record on ns-2, verify replication ────────
log_header "Eager replication: ns-2 → ns-1, ns-3"

RECORD_NAME_2="federation-test-2.ztlp"

log_step "Inserting record '$RECORD_NAME_2' on ns-2 (serial 200)..."
INSERT_RESULT_2=$(ns_insert_record "$NS2_CONTAINER" "ns2@ns-2" "$RECORD_NAME_2" 200)
echo "  Insert result: $INSERT_RESULT_2"
assert_contains "Record inserted on ns-2" "ok" "$INSERT_RESULT_2"

# Wait briefly for eager replication
sleep 3

log_step "Querying '$RECORD_NAME_2' on ns-1..."
LOOKUP_NS1=$(ns_lookup_record "$NS1_CONTAINER" "ns@ns" "$RECORD_NAME_2")
echo "  ns-1 lookup: $LOOKUP_NS1"
assert_contains "Record replicated to ns-1" "FOUND" "$LOOKUP_NS1"
assert_contains "Record has correct serial on ns-1" "serial=200" "$LOOKUP_NS1"

log_step "Querying '$RECORD_NAME_2' on ns-3..."
LOOKUP_NS3_2=$(ns_lookup_record "$NS3_CONTAINER" "ns3@ns-3" "$RECORD_NAME_2")
echo "  ns-3 lookup: $LOOKUP_NS3_2"
assert_contains "Record replicated to ns-3" "FOUND" "$LOOKUP_NS3_2"
assert_contains "Record has correct serial on ns-3" "serial=200" "$LOOKUP_NS3_2"

# ── Step 6: Verify UDP query works on all nodes ──────────────
log_header "UDP query verification across cluster"

for host_label in "ns:ns-1" "ns-2:ns-2" "ns-3:ns-3"; do
    IFS=: read -r host label <<< "$host_label"

    log_step "UDP query for '$RECORD_NAME_1' on $label..."
    UDP_RESULT=$(docker exec "$NS1_CONTAINER" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
name = b'$RECORD_NAME_1'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
s.sendto(query, ('$host', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    if status == 0x02:
        print('RESULT=found')
    elif status == 0x03:
        print('RESULT=not_found')
    else:
        print(f'RESULT=other_0x{status:02x}')
except socket.timeout:
    print('RESULT=timeout')
s.close()
" 2>&1)

    RESULT=$(echo "$UDP_RESULT" | grep "^RESULT=" | cut -d= -f2)
    assert_eq "UDP query on $label returns found" "found" "${RESULT:-unknown}"
done

# ── Results ──────────────────────────────────────────────────
end_scenario
