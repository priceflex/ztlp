# ZTLP Gateway Pipeline Benchmarks
# Run: cd gateway && mix run bench/bench_pipeline.exs
#
# Benchmarks the three-layer admission pipeline:
#   Layer 1: Magic byte check (nanoseconds)
#   Layer 2: SessionID lookup (microseconds, ETS)
#   Layer 3: HeaderAuthTag AEAD verification (crypto cost)

defmodule Bench do
  @moduledoc "Simple benchmark harness — zero deps."

  def run(name, fun, opts \\ []) do
    warmup = Keyword.get(opts, :warmup, 1_000)
    iterations = Keyword.get(opts, :iterations, 50_000)

    IO.puts("\n  #{name}")
    IO.puts("  #{String.duplicate("-", String.length(name))}")

    # Warmup
    for _ <- 1..warmup, do: fun.()

    # Measure
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
IO.puts("  ZTLP Gateway Pipeline Benchmarks")
IO.puts("=" <> String.duplicate("=", 60))

# ---------------------------------------------------------------------------
# Setup: build test packets
# ---------------------------------------------------------------------------

alias ZtlpGateway.{Packet, Pipeline, SessionRegistry, Crypto}

# Valid ZTLP HELLO packet (handshake, zero SessionID)
hello_packet = Packet.build_hello(<<>>)

# Valid data packet with a known session
session_id = :crypto.strong_rand_bytes(16)
auth_tag = :crypto.strong_rand_bytes(12)
payload = :crypto.strong_rand_bytes(64)
data_packet = Packet.build_data(session_id, 1, auth_tag, payload)

# Invalid magic packet
bad_magic_packet = <<0xDE, 0xAD>> <> :crypto.strong_rand_bytes(40)

# Random garbage
garbage = :crypto.strong_rand_bytes(100)

# Register a known session so Layer 2 can find it
SessionRegistry.register(session_id, self())

# ---------------------------------------------------------------------------
# Layer 1 — Magic Byte Check
# ---------------------------------------------------------------------------

IO.puts("\n--- Layer 1: Magic Byte Check ---")

Bench.run("Packet.valid_magic?/1 — valid ZTLP packet", fn ->
  Packet.valid_magic?(data_packet)
end)

Bench.run("Packet.valid_magic?/1 — invalid magic", fn ->
  Packet.valid_magic?(bad_magic_packet)
end)

Bench.run("Pipeline.layer1_magic/1 — valid", fn ->
  Pipeline.layer1_magic(data_packet)
end)

Bench.run("Pipeline.layer1_magic/1 — reject bad magic", fn ->
  Pipeline.layer1_magic(bad_magic_packet)
end)

Bench.run("Pipeline.layer1_magic/1 — reject garbage", fn ->
  Pipeline.layer1_magic(garbage)
end)

# ---------------------------------------------------------------------------
# Layer 2 — SessionID Lookup (varying session counts)
# ---------------------------------------------------------------------------

IO.puts("\n--- Layer 2: SessionID Lookup ---")

# Pre-populate ETS with varying session counts
for count <- [100, 1_000, 10_000] do
  # Clear and re-populate
  # Note: can't easily clear SessionRegistry, so we just add more sessions
  pids = for _ <- 1..count do
    sid = :crypto.strong_rand_bytes(16)
    # Use self() as dummy pid since register requires a pid
    SessionRegistry.register(sid, self())
    sid
  end

  # Pick a known session to look up
  known_sid = Enum.random(pids)
  known_packet = Packet.build_data(known_sid, 42, auth_tag, payload)

  # Unknown session
  unknown_sid = :crypto.strong_rand_bytes(16)
  unknown_packet = Packet.build_data(unknown_sid, 42, auth_tag, payload)

  Bench.run("Pipeline.layer2_session/1 — known session (#{count} sessions in ETS)", fn ->
    Pipeline.layer2_session(known_packet)
  end)

  Bench.run("Pipeline.layer2_session/1 — unknown session (#{count} sessions)", fn ->
    Pipeline.layer2_session(unknown_packet)
  end)
end

Bench.run("Pipeline.layer2_session/1 — HELLO packet (always pass)", fn ->
  Pipeline.layer2_session(hello_packet)
end)

# ---------------------------------------------------------------------------
# Full Pipeline Admission
# ---------------------------------------------------------------------------

IO.puts("\n--- Full Pipeline Admission ---")

Bench.run("Pipeline.admit/1 — valid known session", fn ->
  Pipeline.admit(data_packet)
end)

Bench.run("Pipeline.admit/1 — HELLO (new session)", fn ->
  Pipeline.admit(hello_packet)
end)

Bench.run("Pipeline.admit/1 — bad magic (rejected at L1)", fn ->
  Pipeline.admit(bad_magic_packet)
end)

unknown_data = Packet.build_data(:crypto.strong_rand_bytes(16), 1, auth_tag, payload)
Bench.run("Pipeline.admit/1 — unknown session (rejected at L2)", fn ->
  Pipeline.admit(unknown_data)
end)

# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

IO.puts("\n--- Packet Parsing ---")

Bench.run("Packet.parse/1 — data packet", fn ->
  Packet.parse(data_packet)
end)

Bench.run("Packet.parse/1 — handshake packet", fn ->
  Packet.parse(hello_packet)
end)

Bench.run("Packet.extract_session_id/1", fn ->
  Packet.extract_session_id(data_packet)
end)

Bench.run("Packet.hello?/1 — HELLO", fn ->
  Packet.hello?(hello_packet)
end)

Bench.run("Packet.hello?/1 — not HELLO", fn ->
  Packet.hello?(data_packet)
end)

IO.puts("\n" <> String.duplicate("=", 61))
IO.puts("  Pipeline benchmarks complete.")
IO.puts(String.duplicate("=", 61))
