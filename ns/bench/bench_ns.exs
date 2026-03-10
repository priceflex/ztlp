# ZTLP-NS Namespace Benchmarks
# Run: cd ns && mix run bench/bench_ns.exs
#
# Benchmarks:
#   - Record store insert throughput
#   - Lookup by name+type (ETS)
#   - Trust chain verification (1-level, 2-level)
#   - Signature verification throughput (Ed25519)
#   - Record serialization/deserialization

defmodule Bench do
  @moduledoc "Simple benchmark harness — zero deps."

  def run(name, fun, opts \\ []) do
    warmup = Keyword.get(opts, :warmup, 500)
    iterations = Keyword.get(opts, :iterations, 10_000)

    IO.puts("\n  #{name}")
    IO.puts("  #{String.duplicate("-", String.length(name))}")

    for _ <- 1..warmup, do: fun.()

    times =
      for _ <- 1..iterations do
        t0 = System.monotonic_time(:nanosecond)
        fun.()
        System.monotonic_time(:nanosecond) - t0
      end

    report(times, iterations)
  end

  defp report(times, iterations) do
    sorted = Enum.sort(times)
    total_ns = Enum.sum(sorted)
    total_us = total_ns / 1_000
    mean_ns = total_ns / iterations
    median_ns = Enum.at(sorted, div(iterations, 2))
    p99_ns = Enum.at(sorted, trunc(iterations * 0.99))
    min_ns = List.first(sorted)
    max_ns = List.last(sorted)
    ops_sec = if mean_ns > 0, do: 1_000_000_000 / mean_ns, else: 0

    IO.puts("  iterations:  #{iterations}")
    IO.puts("  total:       #{Float.round(total_us, 1)} µs")
    IO.puts("  mean:        #{Float.round(mean_ns / 1, 1)} ns")
    IO.puts("  median:      #{median_ns} ns")
    IO.puts("  p99:         #{p99_ns} ns")
    IO.puts("  min:         #{min_ns} ns")
    IO.puts("  max:         #{max_ns} ns")
    IO.puts("  throughput:  #{Float.round(ops_sec / 1, 0)} ops/sec")
  end
end

IO.puts("=" <> String.duplicate("=", 60))
IO.puts("  ZTLP-NS Namespace Benchmarks")
IO.puts("=" <> String.duplicate("=", 60))

alias ZtlpNs.{Record, Store, Crypto, TrustAnchor, Query}

# ---------------------------------------------------------------------------
# Setup: generate signing keys
# ---------------------------------------------------------------------------

{root_pub, root_priv} = Crypto.generate_keypair()
{zone_pub, zone_priv} = Crypto.generate_keypair()
{node_pub, node_priv} = Crypto.generate_keypair()

# Add root as trust anchor
TrustAnchor.add("bench-root", root_pub)

# ---------------------------------------------------------------------------
# Record Serialization / Deserialization
# ---------------------------------------------------------------------------

IO.puts("\n--- Record Serialization ---")

node_id = :crypto.strong_rand_bytes(16)
record = Record.new_key("node1.bench.ztlp", node_id, node_pub,
  created_at: System.system_time(:second), ttl: 86400, serial: 1)
signed_record = Record.sign(record, zone_priv)

Bench.run("Record.serialize/1 — ZTLP_KEY record", fn ->
  Record.serialize(signed_record)
end, iterations: 50_000)

canonical = Record.serialize(signed_record)

Bench.run("Record.deserialize/1 — ZTLP_KEY record", fn ->
  Record.deserialize(canonical)
end, iterations: 50_000)

Bench.run("Record.encode/1 — wire format (with sig)", fn ->
  Record.encode(signed_record)
end, iterations: 50_000)

wire = Record.encode(signed_record)

Bench.run("Record.decode/1 — wire format (with sig)", fn ->
  Record.decode(wire)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Ed25519 Signature Verification
# ---------------------------------------------------------------------------

IO.puts("\n--- Ed25519 Signature Verification ---")

Bench.run("Record.verify/1 — valid signature", fn ->
  Record.verify(signed_record)
end, iterations: 10_000)

# Tampered record (bad sig)
tampered = %{signed_record | name: "tampered.bench.ztlp"}

Bench.run("Record.verify/1 — invalid signature (tampered)", fn ->
  Record.verify(tampered)
end, iterations: 10_000)

Bench.run("Crypto.generate_keypair/0 (Ed25519)", fn ->
  Crypto.generate_keypair()
end, iterations: 5_000)

message = :crypto.strong_rand_bytes(128)

Bench.run("Crypto.sign/2 — 128 byte message", fn ->
  Crypto.sign(message, zone_priv)
end, iterations: 5_000)

sig = Crypto.sign(message, zone_priv)

Bench.run("Crypto.verify/3 — 128 byte message", fn ->
  Crypto.verify(message, sig, zone_pub)
end, iterations: 5_000)

# ---------------------------------------------------------------------------
# Store Insert Throughput
# ---------------------------------------------------------------------------

IO.puts("\n--- Store Insert Throughput ---")

# Clear the store for clean measurement
Store.clear()

# Pre-generate signed records for insertion
insert_records =
  for i <- 1..1000 do
    nid = :crypto.strong_rand_bytes(16)
    rec = Record.new_key("node#{i}.insert-bench.ztlp", nid, node_pub,
      created_at: System.system_time(:second), ttl: 86400, serial: 1)
    Record.sign(rec, zone_priv)
  end

counter = :counters.new(1, [])

Bench.run("Store.insert/1 — signed ZTLP_KEY records (serial insert)", fn ->
  idx = :counters.get(counter, 1)
  :counters.add(counter, 1, 1)
  rec = Enum.at(insert_records, rem(idx, 1000))
  # Bump serial to avoid stale_serial errors
  rec = %{rec | serial: idx + 2, name: "node#{idx}.insert-bench2.ztlp"}
  rec = Record.sign(rec, zone_priv)
  Store.insert(rec)
end, iterations: 5_000)

# ---------------------------------------------------------------------------
# Store Lookup Throughput
# ---------------------------------------------------------------------------

IO.puts("\n--- Store Lookup Throughput ---")

# Populate store with records for lookup benchmarks
Store.clear()

for i <- 1..1000 do
  nid = :crypto.strong_rand_bytes(16)
  rec = Record.new_key("node#{i}.lookup-bench.ztlp", nid, node_pub,
    created_at: System.system_time(:second), ttl: 86400, serial: 1)
  signed = Record.sign(rec, zone_priv)
  Store.insert(signed)
end

Bench.run("Store.lookup/2 — known record (ETS hit)", fn ->
  Store.lookup("node500.lookup-bench.ztlp", :key)
end, iterations: 50_000)

Bench.run("Store.lookup/2 — unknown record (ETS miss)", fn ->
  Store.lookup("nonexistent.lookup-bench.ztlp", :key)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Query with Signature Verification
# ---------------------------------------------------------------------------

IO.puts("\n--- Query (Lookup + Verify) ---")

Bench.run("Query.lookup/2 — known record (lookup + sig verify)", fn ->
  Query.lookup("node500.lookup-bench.ztlp", :key)
end, iterations: 10_000)

Bench.run("Query.lookup/2 — unknown record", fn ->
  Query.lookup("nonexistent.lookup-bench.ztlp", :key)
end, iterations: 10_000)

# ---------------------------------------------------------------------------
# Trust Chain Verification
# ---------------------------------------------------------------------------

IO.puts("\n--- Trust Chain Verification ---")

# Setup: root signs a zone delegation, zone signs a node record
Store.clear()

# Root-signed zone delegation
zone_delegation = %Record{
  name: "bench.ztlp",
  type: :key,
  data: %{
    node_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
    public_key: Base.encode16(zone_pub, case: :lower),
    algorithm: "Ed25519",
    delegation: true
  },
  created_at: System.system_time(:second),
  ttl: 86400,
  serial: 1
}
zone_delegation = Record.sign(zone_delegation, root_priv)
Store.insert(zone_delegation)

# Zone-signed node record
node_record = Record.new_key("node1.bench.ztlp", node_id, node_pub,
  created_at: System.system_time(:second), ttl: 86400, serial: 1)
node_record = Record.sign(node_record, zone_priv)
Store.insert(node_record)

Bench.run("Query.lookup_verified/2 — 1-level chain (zone → root)", fn ->
  Query.lookup_verified("node1.bench.ztlp", :key)
end, iterations: 2_000)

# Add a 2-level chain: root → org → zone → node
{org_pub, org_priv} = Crypto.generate_keypair()

org_delegation = %Record{
  name: "org.ztlp",
  type: :key,
  data: %{
    node_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
    public_key: Base.encode16(org_pub, case: :lower),
    algorithm: "Ed25519",
    delegation: true
  },
  created_at: System.system_time(:second),
  ttl: 86400,
  serial: 1
}
org_delegation = Record.sign(org_delegation, root_priv)
Store.insert(org_delegation)

{zone2_pub, zone2_priv} = Crypto.generate_keypair()

zone2_delegation = %Record{
  name: "dept.org.ztlp",
  type: :key,
  data: %{
    node_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
    public_key: Base.encode16(zone2_pub, case: :lower),
    algorithm: "Ed25519",
    delegation: true
  },
  created_at: System.system_time(:second),
  ttl: 86400,
  serial: 1
}
zone2_delegation = Record.sign(zone2_delegation, org_priv)
Store.insert(zone2_delegation)

deep_record = Record.new_key("node1.dept.org.ztlp", node_id, node_pub,
  created_at: System.system_time(:second), ttl: 86400, serial: 1)
deep_record = Record.sign(deep_record, zone2_priv)
Store.insert(deep_record)

Bench.run("Query.lookup_verified/2 — 2-level chain (zone → org → root)", fn ->
  Query.lookup_verified("node1.dept.org.ztlp", :key)
end, iterations: 1_000)

# ---------------------------------------------------------------------------
# TrustAnchor Operations
# ---------------------------------------------------------------------------

IO.puts("\n--- TrustAnchor Operations ---")

Bench.run("TrustAnchor.trusted?/1 — known anchor", fn ->
  TrustAnchor.trusted?(root_pub)
end, iterations: 50_000)

random_key = :crypto.strong_rand_bytes(32)

Bench.run("TrustAnchor.trusted?/1 — unknown key", fn ->
  TrustAnchor.trusted?(random_key)
end, iterations: 50_000)

IO.puts("\n" <> String.duplicate("=", 61))
IO.puts("  ZTLP-NS benchmarks complete.")
IO.puts(String.duplicate("=", 61))
