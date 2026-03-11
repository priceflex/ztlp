defmodule ZtlpRelay.Bench do
  @moduledoc """
  Performance benchmarks for new relay features:
  backpressure, component auth, mesh routing, and metrics.

  Run: cd relay && mix run -e "ZtlpRelay.Bench.run()"
  """

  # ── Benchmark Harness ──────────────────────────────────────────────

  defp measure(name, fun, iterations \\ 100_000) do
    # Warmup
    for _ <- 1..1_000, do: fun.()

    # Measure
    times =
      for _ <- 1..iterations do
        t0 = System.monotonic_time(:nanosecond)
        fun.()
        System.monotonic_time(:nanosecond) - t0
      end

    sorted = Enum.sort(times)
    total = Enum.sum(times)
    mean = total / iterations
    median = Enum.at(sorted, div(iterations, 2))
    p99 = Enum.at(sorted, trunc(iterations * 0.99))

    ops_sec = if mean > 0, do: trunc(1_000_000_000 / mean), else: 0

    %{name: name, mean: mean, median: median, p99: p99, ops_sec: ops_sec}
  end

  defp format_ns(ns) when ns >= 1_000_000, do: "#{Float.round(ns / 1_000_000, 1)} ms"
  defp format_ns(ns) when ns >= 1_000, do: "#{Float.round(ns / 1_000, 1)} µs"
  defp format_ns(ns), do: "#{round(ns)} ns"

  defp format_ops(ops) when ops >= 1_000_000, do: "#{Float.round(ops / 1_000_000, 2)}M ops/s"
  defp format_ops(ops) when ops >= 1_000, do: "#{Float.round(ops / 1_000, 1)}K ops/s"
  defp format_ops(ops), do: "#{ops} ops/s"

  defp print_result(%{name: name, mean: mean, median: median, p99: p99, ops_sec: ops_sec}) do
    IO.puts("  #{name}")
    IO.puts("    mean=#{format_ns(mean)}  median=#{format_ns(median)}  p99=#{format_ns(p99)}  throughput=#{format_ops(ops_sec)}")
  end

  defp print_table_row(%{name: name, mean: mean, median: median, p99: p99, ops_sec: ops_sec}) do
    IO.puts("| #{name} | #{format_ns(mean)} | #{format_ns(median)} | #{format_ns(p99)} | #{delimit(ops_sec)} ops/s |")
  end

  defp delimit(n) when is_integer(n) do
    n
    |> Integer.to_string()
    |> String.reverse()
    |> String.replace(~r/(\d{3})(?=\d)/, "\\1,")
    |> String.reverse()
  end
  defp delimit(n), do: delimit(trunc(n))

  # ── Setup helpers ──────────────────────────────────────────────────

  defp ensure_backpressure_table do
    # Backpressure uses an ETS table — ensure it exists
    case :ets.whereis(ZtlpRelay.Backpressure) do
      :undefined ->
        :ets.new(ZtlpRelay.Backpressure, [:named_table, :public, :set, read_concurrency: true])
        :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.0})
      _tid ->
        :ok
    end
  end

  defp ensure_component_auth_tables do
    # Ensure nonce table exists
    case :ets.whereis(:ztlp_relay_component_nonces) do
      :undefined ->
        :ets.new(:ztlp_relay_component_nonces, [:set, :public, :named_table])
      _tid -> :ok
    end

    # Ensure metrics table exists
    case :ets.whereis(:ztlp_relay_component_auth_metrics) do
      :undefined ->
        try do
          :ets.new(:ztlp_relay_component_auth_metrics, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  # ── Main entry point ───────────────────────────────────────────────

  def run do
    IO.puts("=" <> String.duplicate("=", 60))
    IO.puts("  ZTLP Relay — New Feature Benchmarks")
    IO.puts("=" <> String.duplicate("=", 60))

    ensure_backpressure_table()
    ensure_component_auth_tables()

    results = []

    # 1. Backpressure check overhead
    IO.puts("\n--- Backpressure ---")

    r1 = bench_backpressure_check_ok()
    r2 = bench_backpressure_check_soft()
    r3 = bench_backpressure_check_hard()
    r4 = bench_backpressure_update_load()

    results = results ++ [r1, r2, r3, r4]

    # 2. Component Auth
    IO.puts("\n--- Component Auth ---")

    r5 = bench_component_auth_generate_challenge()
    r6 = bench_component_auth_sign_challenge()
    r7 = bench_component_auth_verify_response()
    r8 = bench_component_auth_full_roundtrip()

    results = results ++ [r5, r6, r7, r8]

    # 3. Mesh routing (RoutePlanner)
    IO.puts("\n--- Mesh Routing ---")

    r9 = bench_route_plan_direct()
    r10 = bench_route_plan_via_transit()

    results = results ++ [r9, r10]

    # 4. Metrics collection overhead
    IO.puts("\n--- Metrics Collection ---")

    r11 = bench_backpressure_metrics()

    results = results ++ [r11]

    # Print markdown table
    IO.puts("\n\n--- Markdown Table ---")
    IO.puts("| Benchmark | Mean | Median | p99 | Throughput |")
    IO.puts("|-----------|------|--------|-----|------------|")
    Enum.each(results, &print_table_row/1)

    IO.puts("\n" <> String.duplicate("=", 61))
    IO.puts("  Relay new-feature benchmarks complete.")
    IO.puts(String.duplicate("=", 61))
  end

  # ── Backpressure Benchmarks ────────────────────────────────────────

  defp bench_backpressure_check_ok do
    # Set load below soft threshold (default 0.8)
    :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.3})
    Application.put_env(:ztlp_relay, :backpressure_soft_threshold, 0.8)
    Application.put_env(:ztlp_relay, :backpressure_hard_threshold, 0.95)

    result = measure("Backpressure check/0 — :ok (below soft)", fn ->
      ZtlpRelay.Backpressure.check()
    end)
    print_result(result)
    result
  end

  defp bench_backpressure_check_soft do
    :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.9})

    result = measure("Backpressure check/0 — :soft", fn ->
      ZtlpRelay.Backpressure.check()
    end)
    print_result(result)
    result
  end

  defp bench_backpressure_check_hard do
    :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.98})

    result = measure("Backpressure check/0 — :hard", fn ->
      ZtlpRelay.Backpressure.check()
    end)
    print_result(result)

    # Reset to normal
    :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.0})
    result
  end

  defp bench_backpressure_update_load do
    result = measure("Backpressure update_load/2", fn ->
      ZtlpRelay.Backpressure.update_load(500, 1000)
    end)
    print_result(result)
    result
  end

  # ── Component Auth Benchmarks ──────────────────────────────────────

  defp bench_component_auth_generate_challenge do
    result = measure("ComponentAuth generate_challenge/0", fn ->
      ZtlpRelay.ComponentAuth.generate_challenge()
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_component_auth_sign_challenge do
    {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    nonce = :crypto.strong_rand_bytes(16)

    result = measure("ComponentAuth sign_challenge/2", fn ->
      ZtlpRelay.ComponentAuth.sign_challenge(nonce, priv)
    end, 10_000)
    print_result(result)
    result
  end

  defp bench_component_auth_verify_response do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    nonce = :crypto.strong_rand_bytes(16)
    signature = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

    result = measure("ComponentAuth verify_response/4 (valid)", fn ->
      ZtlpRelay.ComponentAuth.verify_response(nonce, signature, pub,
        enabled: true, allowed_keys: [pub])
    end, 10_000)
    print_result(result)
    result
  end

  defp bench_component_auth_full_roundtrip do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    result = measure("ComponentAuth full roundtrip", fn ->
      # Generate challenge
      {challenge_bin, nonce} = ZtlpRelay.ComponentAuth.generate_challenge()

      # Parse challenge (other side)
      {:ok, ^nonce} = ZtlpRelay.ComponentAuth.parse_challenge(challenge_bin)

      # Sign and build response
      response_bin = ZtlpRelay.ComponentAuth.sign_challenge(nonce, priv)

      # Parse response
      {:ok, signature, peer_pubkey} = ZtlpRelay.ComponentAuth.parse_response(response_bin)

      # Verify
      ZtlpRelay.ComponentAuth.verify_response(nonce, signature, peer_pubkey,
        enabled: true, allowed_keys: [pub])
    end, 5_000)
    print_result(result)
    result
  end

  # ── Mesh Routing Benchmarks ────────────────────────────────────────

  defp bench_route_plan_direct do
    # Build a small relay registry for route planning
    source_id = :crypto.strong_rand_bytes(16)
    dest_id = :crypto.strong_rand_bytes(16)

    registry = [
      %{node_id: source_id, address: {{10, 0, 0, 1}, 23095}, role: :ingress},
      %{node_id: dest_id, address: {{10, 0, 0, 2}, 23095}, role: :service}
    ]

    result = measure("RoutePlanner plan/3 — direct (2 relays)", fn ->
      ZtlpRelay.RoutePlanner.plan(source_id, dest_id, registry)
    end)
    print_result(result)
    result
  end

  defp bench_route_plan_via_transit do
    source_id = :crypto.strong_rand_bytes(16)
    transit_id = :crypto.strong_rand_bytes(16)
    dest_id = :crypto.strong_rand_bytes(16)

    # Build 10-relay mesh with transits
    transit_relays = for i <- 1..8 do
      %{node_id: :crypto.strong_rand_bytes(16), address: {{10, 0, 1, i}, 23095}, role: :transit}
    end

    registry = [
      %{node_id: source_id, address: {{10, 0, 0, 1}, 23095}, role: :ingress},
      %{node_id: transit_id, address: {{10, 0, 1, 100}, 23095}, role: :transit},
      %{node_id: dest_id, address: {{10, 0, 0, 2}, 23095}, role: :service}
    ] ++ transit_relays

    result = measure("RoutePlanner plan/3 — via transit (10 relays)", fn ->
      ZtlpRelay.RoutePlanner.plan(source_id, dest_id, registry)
    end, 50_000)
    print_result(result)
    result
  end

  # ── Metrics Collection Benchmarks ──────────────────────────────────

  defp bench_backpressure_metrics do
    # Ensure there's some data to collect
    :ets.insert(ZtlpRelay.Backpressure, {:current_load, 0.5})
    :ets.insert(ZtlpRelay.Backpressure, {:rejections, 42})

    result = measure("Backpressure metrics/0 collection", fn ->
      ZtlpRelay.Backpressure.metrics()
    end)
    print_result(result)
    result
  end
end
