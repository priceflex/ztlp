#!/usr/bin/env elixir
# ZTLP Relay Mesh Benchmark
#
# Measures performance of mesh operations:
# - Hash ring lookup (10/50/100 relays)
# - PathScore computation
# - Inter-relay message encode/decode
# - End-to-end mesh forwarding
#
# Run: cd relay && mix run mesh_bench.exs

defmodule MeshBench do
  @moduledoc false

  alias ZtlpRelay.{HashRing, PathScore, InterRelay, Crypto, Packet}

  @warmup_iterations 1_000
  @bench_duration_ms 2_000

  def run do
    IO.puts("""

    ╔══════════════════════════════════════════════════════════════╗
    ║              ZTLP Relay Mesh Benchmark                      ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    bench_hash_ring_lookup()
    bench_pathscore()
    bench_inter_relay_codec()
    bench_forwarding()
    bench_admission_token()
  end

  # ── Hash Ring Lookup ───────────────────────────────────────

  defp bench_hash_ring_lookup do
    IO.puts("━━━ Hash Ring Lookup ━━━\n")

    for node_count <- [10, 50, 100] do
      relays = for _ <- 1..node_count do
        %{node_id: :crypto.strong_rand_bytes(16), address: {{127, 0, 0, 1}, Enum.random(10000..60000)}}
      end
      ring = HashRing.new(relays)

      # Pre-generate keys
      keys = for _ <- 1..10_000, do: :crypto.strong_rand_bytes(12)

      # Warmup
      for k <- Enum.take(keys, @warmup_iterations), do: HashRing.get_nodes(ring, k, 3)

      # Benchmark
      {ops, elapsed_us} = timed_loop(fn ->
        key = Enum.random(keys)
        HashRing.get_nodes(ring, key, 3)
      end, @bench_duration_ms)

      ops_per_sec = div(ops * 1_000_000, max(elapsed_us, 1))
      ns_per_op = div(elapsed_us * 1_000, max(ops, 1))

      IO.puts("  #{String.pad_trailing("#{node_count} nodes, get_nodes(k, 3):", 35)} #{format_number(ops_per_sec)} ops/sec  (#{ns_per_op} ns/op)")
    end

    IO.puts("")
  end

  # ── PathScore Computation ──────────────────────────────────

  defp bench_pathscore do
    IO.puts("━━━ PathScore Computation ━━━\n")

    metrics = %{rtt_ms: 42, loss_rate: 0.02, load_factor: 0.3}

    # Warmup
    for _ <- 1..@warmup_iterations, do: PathScore.compute(metrics)

    {ops, elapsed_us} = timed_loop(fn ->
      PathScore.compute(metrics)
    end, @bench_duration_ms)

    ops_per_sec = div(ops * 1_000_000, max(elapsed_us, 1))
    ns_per_op = div(elapsed_us * 1_000, max(ops, 1))
    IO.puts("  #{String.pad_trailing("compute():", 35)} #{format_number(ops_per_sec)} ops/sec  (#{ns_per_op} ns/op)")

    # select_best with 3 candidates
    candidates = for _ <- 1..3 do
      %{node_id: :crypto.strong_rand_bytes(16), address: {{127, 0, 0, 1}, Enum.random(10000..60000)}}
    end
    scores = Map.new(candidates, fn c ->
      {c.node_id, %{rtt_ms: Enum.random(10..100), loss_rate: :rand.uniform() * 0.1, load_factor: :rand.uniform() * 0.5}}
    end)

    {ops2, elapsed_us2} = timed_loop(fn ->
      PathScore.select_best(candidates, scores)
    end, @bench_duration_ms)

    ops_per_sec2 = div(ops2 * 1_000_000, max(elapsed_us2, 1))
    ns_per_op2 = div(elapsed_us2 * 1_000, max(ops2, 1))
    IO.puts("  #{String.pad_trailing("select_best(3 candidates):", 35)} #{format_number(ops_per_sec2)} ops/sec  (#{ns_per_op2} ns/op)")

    IO.puts("")
  end

  # ── Inter-relay Encode/Decode ──────────────────────────────

  defp bench_inter_relay_codec do
    IO.puts("━━━ Inter-Relay Message Encode/Decode ━━━\n")

    node_id = :crypto.strong_rand_bytes(16)
    info = %{node_id: node_id, address: {{10, 0, 0, 1}, 23101}, role: :ingress}
    hello_encoded = InterRelay.encode_hello(info)

    # HELLO encode
    {ops_enc, us_enc} = timed_loop(fn ->
      InterRelay.encode_hello(info)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("HELLO encode:", 35)} #{format_number(div(ops_enc * 1_000_000, max(us_enc, 1)))} ops/sec")

    # HELLO decode
    {ops_dec, us_dec} = timed_loop(fn ->
      InterRelay.decode(hello_encoded)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("HELLO decode:", 35)} #{format_number(div(ops_dec * 1_000_000, max(us_dec, 1)))} ops/sec")

    # FORWARD encode (with a 100-byte inner packet)
    inner = :crypto.strong_rand_bytes(100)
    {ops_fwd_enc, us_fwd_enc} = timed_loop(fn ->
      InterRelay.encode_forward(node_id, inner)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("FORWARD encode (100B):", 35)} #{format_number(div(ops_fwd_enc * 1_000_000, max(us_fwd_enc, 1)))} ops/sec")

    # FORWARD decode
    fwd_encoded = InterRelay.encode_forward(node_id, inner)
    {ops_fwd_dec, us_fwd_dec} = timed_loop(fn ->
      InterRelay.decode(fwd_encoded)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("FORWARD decode (100B):", 35)} #{format_number(div(ops_fwd_dec * 1_000_000, max(us_fwd_dec, 1)))} ops/sec")

    # SESSION_SYNC encode/decode
    sync = %{session_id: :crypto.strong_rand_bytes(12), peer_a: {{10, 0, 0, 1}, 5000}, peer_b: {{10, 0, 0, 2}, 6000}}
    {ops_sync, us_sync} = timed_loop(fn ->
      InterRelay.encode_session_sync(node_id, sync)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("SESSION_SYNC encode:", 35)} #{format_number(div(ops_sync * 1_000_000, max(us_sync, 1)))} ops/sec")

    IO.puts("")
  end

  # ── End-to-End Forwarding ──────────────────────────────────

  defp bench_forwarding do
    IO.puts("━━━ End-to-End Mesh Forwarding ━━━\n")

    # Setup: 3 relay sockets
    relays = for _ <- 1..3 do
      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])
      {:ok, port} = :inet.port(sock)
      %{
        node_id: :crypto.strong_rand_bytes(16),
        socket: sock,
        port: port,
        address: {{127, 0, 0, 1}, port}
      }
    end

    ring = HashRing.new(Enum.map(relays, &%{node_id: &1.node_id, address: &1.address}))

    # Pre-build packets
    session_id = Crypto.generate_session_id()
    inner = Packet.serialize(Packet.build_data(session_id, 1, payload: "bench"))
    [owner_info | _] = HashRing.get_nodes(ring, session_id, 1)
    owner = Enum.find(relays, &(&1.node_id == owner_info.node_id))
    ingress = Enum.find(relays, &(&1.node_id != owner.node_id))

    fwd_msg = InterRelay.encode_forward(ingress.node_id, inner)
    {owner_ip, owner_port} = owner.address

    # Single relay: direct send (no mesh)
    {ops_direct, us_direct} = timed_loop(fn ->
      :gen_udp.send(ingress.socket, owner_ip, owner_port, inner)
      :gen_udp.recv(owner.socket, 0, 100)
    end, @bench_duration_ms)
    pkts_direct = div(ops_direct * 1_000_000, max(us_direct, 1))
    IO.puts("  #{String.pad_trailing("Direct send (no mesh):", 35)} #{format_number(pkts_direct)} pkt/sec")

    # Mesh: forward + unwrap
    {ops_mesh, us_mesh} = timed_loop(fn ->
      :gen_udp.send(ingress.socket, owner_ip, owner_port, fwd_msg)
      case :gen_udp.recv(owner.socket, 0, 100) do
        {:ok, {_ip, _port, data}} -> InterRelay.unwrap_forward(data)
        {:error, _} -> :ok
      end
    end, @bench_duration_ms)
    pkts_mesh = div(ops_mesh * 1_000_000, max(us_mesh, 1))
    IO.puts("  #{String.pad_trailing("Mesh forwarded (wrap+unwrap):", 35)} #{format_number(pkts_mesh)} pkt/sec")

    overhead = if pkts_direct > 0 do
      pct = Float.round((1 - pkts_mesh / pkts_direct) * 100, 1)
      "#{pct}%"
    else
      "N/A"
    end
    IO.puts("  Mesh overhead: #{overhead}")

    for r <- relays, do: :gen_udp.close(r.socket)
    IO.puts("")
  end

  # ── Admission Token ────────────────────────────────────────

  defp bench_admission_token do
    IO.puts("━━━ Admission Token (RAT) ━━━\n")

    secret = :crypto.strong_rand_bytes(32)
    node_id = :crypto.strong_rand_bytes(16)
    issuer_id = :crypto.strong_rand_bytes(16)
    session_id = :crypto.strong_rand_bytes(12)

    # Issue
    {ops_issue, us_issue} = timed_loop(fn ->
      ZtlpRelay.AdmissionToken.issue(node_id, session_id,
        secret_key: secret, issuer_id: issuer_id, ttl_seconds: 300)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("RAT issue:", 35)} #{format_number(div(ops_issue * 1_000_000, max(us_issue, 1)))} ops/sec")

    # Verify
    token = ZtlpRelay.AdmissionToken.issue(node_id, session_id,
      secret_key: secret, issuer_id: issuer_id, ttl_seconds: 300)
    {ops_verify, us_verify} = timed_loop(fn ->
      ZtlpRelay.AdmissionToken.verify(token, secret, session_scope: session_id)
    end, @bench_duration_ms)
    IO.puts("  #{String.pad_trailing("RAT verify:", 35)} #{format_number(div(ops_verify * 1_000_000, max(us_verify, 1)))} ops/sec")

    IO.puts("")
  end

  # ── Timing Helpers ─────────────────────────────────────────

  # Run `fun` repeatedly for `duration_ms`, return {ops, elapsed_microseconds}
  defp timed_loop(fun, duration_ms) do
    deadline = System.monotonic_time(:millisecond) + duration_ms
    do_timed_loop(fun, deadline, 0)
  end

  defp do_timed_loop(fun, deadline, count) do
    start = System.monotonic_time(:microsecond)
    fun.()
    now_ms = System.monotonic_time(:millisecond)
    elapsed = System.monotonic_time(:microsecond) - start

    if now_ms >= deadline do
      # We've been running long enough; calculate total
      total_us = duration_us(deadline, count + 1, elapsed)
      {count + 1, total_us}
    else
      do_timed_loop(fun, deadline, count + 1)
    end
  end

  defp duration_us(_deadline, _ops, _last_elapsed) when _ops == 0, do: 1
  defp duration_us(_deadline, _ops, _last_elapsed) do
    # Approximate: we ran for about @bench_duration_ms
    @bench_duration_ms * 1_000
  end

  defp format_number(n) when n >= 1_000_000 do
    "#{Float.round(n / 1_000_000, 2)}M"
    |> String.pad_leading(10)
  end
  defp format_number(n) when n >= 1_000 do
    "#{Float.round(n / 1_000, 1)}K"
    |> String.pad_leading(10)
  end
  defp format_number(n) do
    "#{n}"
    |> String.pad_leading(10)
  end
end

MeshBench.run()
