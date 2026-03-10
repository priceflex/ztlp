# ZTLP Relay Benchmarks
# Run: cd relay && mix run bench/bench_relay.exs
#
# Benchmarks:
#   - Relay pipeline admission (Layer 1, 2, 3)
#   - Relay packet parsing & serialization
#   - HeaderAuthTag computation & verification
#   - Session registry operations

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
IO.puts("  ZTLP Relay Benchmarks")
IO.puts("=" <> String.duplicate("=", 60))

alias ZtlpRelay.{Packet, Pipeline, Crypto, SessionRegistry}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

session_key = Crypto.generate_key()
session_id = Crypto.generate_session_id()

# Register session
peer_a = {{127, 0, 0, 1}, 10001}
peer_b = {{127, 0, 0, 1}, 10002}
SessionRegistry.register_session(session_id, peer_a, peer_b)

# Build packets
hello_pkt = Packet.build_handshake(:hello, <<0::96>>,
  src_node_id: :crypto.strong_rand_bytes(16),
  timestamp: System.system_time(:millisecond))
hello_raw = Packet.serialize(hello_pkt)

data_pkt = Packet.build_data(session_id, 42, payload: :crypto.strong_rand_bytes(64))
# Compute proper auth tag
{:ok, aad} = Packet.extract_aad(Packet.serialize(data_pkt))
tag = Crypto.compute_header_auth_tag(session_key, aad)
data_pkt = %{data_pkt | header_auth_tag: tag}
data_raw = Packet.serialize(data_pkt)

bad_magic = <<0xDE, 0xAD>> <> :crypto.strong_rand_bytes(40)
garbage = :crypto.strong_rand_bytes(100)

# Unknown session packet
unknown_sid = Crypto.generate_session_id()
unknown_pkt = Packet.build_data(unknown_sid, 1, payload: :crypto.strong_rand_bytes(64))
unknown_raw = Packet.serialize(unknown_pkt)

# ---------------------------------------------------------------------------
# Layer 1: Magic Check
# ---------------------------------------------------------------------------

IO.puts("\n--- Layer 1: Magic Byte Check ---")

Bench.run("Packet.valid_magic?/1 — valid", fn ->
  Packet.valid_magic?(data_raw)
end, iterations: 50_000)

Bench.run("Packet.valid_magic?/1 — invalid", fn ->
  Packet.valid_magic?(bad_magic)
end, iterations: 50_000)

Bench.run("Pipeline.layer1_magic/1 — valid", fn ->
  Pipeline.layer1_magic(data_raw)
end, iterations: 50_000)

Bench.run("Pipeline.layer1_magic/1 — reject", fn ->
  Pipeline.layer1_magic(bad_magic)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Layer 2: SessionID Lookup
# ---------------------------------------------------------------------------

IO.puts("\n--- Layer 2: SessionID Lookup ---")

# Populate with varying session counts
for count <- [100, 1_000, 10_000] do
  for _ <- 1..count do
    sid = Crypto.generate_session_id()
    pa = {{127, 0, 0, 1}, :rand.uniform(65535)}
    pb = {{127, 0, 0, 1}, :rand.uniform(65535)}
    SessionRegistry.register_session(sid, pa, pb)
  end

  Bench.run("Pipeline.layer2_session/1 — known session (#{count}+ sessions)", fn ->
    Pipeline.layer2_session(data_raw)
  end, iterations: 50_000)

  Bench.run("Pipeline.layer2_session/1 — unknown session (#{count}+ sessions)", fn ->
    Pipeline.layer2_session(unknown_raw)
  end, iterations: 50_000)
end

Bench.run("Pipeline.layer2_session/1 — HELLO (always pass)", fn ->
  Pipeline.layer2_session(hello_raw)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Layer 3: HeaderAuthTag Verification
# ---------------------------------------------------------------------------

IO.puts("\n--- Layer 3: HeaderAuthTag Verification ---")

Bench.run("Crypto.compute_header_auth_tag/2 — handshake header AAD", fn ->
  Crypto.compute_header_auth_tag(session_key, aad)
end, iterations: 10_000)

Bench.run("Crypto.verify_header_auth_tag/3 — valid tag", fn ->
  Crypto.verify_header_auth_tag(session_key, aad, tag)
end, iterations: 10_000)

bad_tag = :crypto.strong_rand_bytes(16)

Bench.run("Crypto.verify_header_auth_tag/3 — invalid tag", fn ->
  Crypto.verify_header_auth_tag(session_key, aad, bad_tag)
end, iterations: 10_000)

# ---------------------------------------------------------------------------
# Full Pipeline
# ---------------------------------------------------------------------------

IO.puts("\n--- Full Pipeline ---")

Bench.run("Pipeline.process/2 — valid data packet (no auth, relay mode)", fn ->
  Pipeline.process(data_raw)
end, iterations: 20_000)

Bench.run("Pipeline.process/2 — valid data packet (with auth)", fn ->
  Pipeline.process(data_raw, session_key)
end, iterations: 10_000)

Bench.run("Pipeline.process/2 — HELLO packet", fn ->
  Pipeline.process(hello_raw)
end, iterations: 20_000)

Bench.run("Pipeline.process/2 — bad magic (L1 reject)", fn ->
  Pipeline.process(bad_magic)
end, iterations: 50_000)

Bench.run("Pipeline.process/2 — unknown session (L2 reject)", fn ->
  Pipeline.process(unknown_raw)
end, iterations: 20_000)

# ---------------------------------------------------------------------------
# Packet Parsing & Serialization
# ---------------------------------------------------------------------------

IO.puts("\n--- Packet Parsing & Serialization ---")

Bench.run("Packet.parse/1 — handshake header", fn ->
  Packet.parse(hello_raw)
end, iterations: 50_000)

Bench.run("Packet.parse/1 — data compact header", fn ->
  Packet.parse(data_raw)
end, iterations: 50_000)

Bench.run("Packet.serialize/1 — handshake", fn ->
  Packet.serialize(hello_pkt)
end, iterations: 50_000)

Bench.run("Packet.serialize/1 — data compact", fn ->
  Packet.serialize(data_pkt)
end, iterations: 50_000)

Bench.run("Packet.extract_session_id/1", fn ->
  Packet.extract_session_id(data_raw)
end, iterations: 50_000)

Bench.run("Packet.extract_aad/1 — data header", fn ->
  Packet.extract_aad(data_raw)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Session Registry Operations
# ---------------------------------------------------------------------------

IO.puts("\n--- Session Registry Operations ---")

Bench.run("SessionRegistry.session_exists?/1 — known", fn ->
  SessionRegistry.session_exists?(session_id)
end, iterations: 50_000)

Bench.run("SessionRegistry.session_exists?/1 — unknown", fn ->
  SessionRegistry.session_exists?(unknown_sid)
end, iterations: 50_000)

Bench.run("SessionRegistry.lookup_session/1 — known", fn ->
  SessionRegistry.lookup_session(session_id)
end, iterations: 50_000)

Bench.run("SessionRegistry.lookup_peer/2 — known peer", fn ->
  SessionRegistry.lookup_peer(session_id, peer_a)
end, iterations: 50_000)

IO.puts("\n" <> String.duplicate("=", 61))
IO.puts("  Relay benchmarks complete.")
IO.puts(String.duplicate("=", 61))
