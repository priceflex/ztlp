defmodule ZtlpGateway.Bench do
  @moduledoc """
  Performance benchmarks for new gateway features:
  circuit breaker, component auth, NS identity resolution.

  Run: cd gateway && mix run -e "ZtlpGateway.Bench.run()"
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

  defp ensure_circuit_breaker_table do
    case :ets.whereis(ZtlpGateway.CircuitBreaker) do
      :undefined ->
        :ets.new(ZtlpGateway.CircuitBreaker, [
          :named_table, :public, :set,
          read_concurrency: true, write_concurrency: true
        ])
      _tid -> :ok
    end

    # Ensure metrics table
    case :ets.whereis(:ztlp_gateway_circuit_breaker_metrics) do
      :undefined ->
        try do
          :ets.new(:ztlp_gateway_circuit_breaker_metrics, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  # ── Main entry point ───────────────────────────────────────────────

  def run do
    IO.puts("=" <> String.duplicate("=", 60))
    IO.puts("  ZTLP Gateway — New Feature Benchmarks")
    IO.puts("=" <> String.duplicate("=", 60))

    ensure_circuit_breaker_table()

    # Enable circuit breaker for benchmarks
    Application.put_env(:ztlp_gateway, :circuit_breaker_enabled, true)
    Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
    Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 30_000)

    results = []

    # 1. Circuit Breaker
    IO.puts("\n--- Circuit Breaker ---")

    r1 = bench_cb_allow_unknown()
    r2 = bench_cb_allow_closed()
    r3 = bench_cb_allow_open()
    r4 = bench_cb_record_success()
    r5 = bench_cb_record_failure()
    r6 = bench_cb_state_transition()

    results = results ++ [r1, r2, r3, r4, r5, r6]

    # 2. Component Auth
    IO.puts("\n--- Component Auth ---")

    r7 = bench_gw_component_auth_parse_challenge()
    r8 = bench_gw_component_auth_sign_challenge()
    r9 = bench_gw_component_auth_full_roundtrip()

    results = results ++ [r7, r8, r9]

    # 3. NS Identity Resolution (cache hit vs miss)
    IO.puts("\n--- NS Identity Resolution ---")

    r10 = bench_identity_cache_hit()
    r11 = bench_identity_cache_miss_ets()

    results = results ++ [r10, r11]

    # Print markdown table
    IO.puts("\n\n--- Markdown Table ---")
    IO.puts("| Benchmark | Mean | Median | p99 | Throughput |")
    IO.puts("|-----------|------|--------|-----|------------|")
    Enum.each(results, &print_table_row/1)

    IO.puts("\n" <> String.duplicate("=", 61))
    IO.puts("  Gateway new-feature benchmarks complete.")
    IO.puts(String.duplicate("=", 61))
  end

  # ── Circuit Breaker Benchmarks ─────────────────────────────────────

  defp bench_cb_allow_unknown do
    # Unknown backend → returns true (fast path)
    ZtlpGateway.CircuitBreaker.reset()

    result = measure("CB allow?/1 — unknown backend (fast path)", fn ->
      ZtlpGateway.CircuitBreaker.allow?("bench-unknown-#{:rand.uniform(1000)}")
    end)
    print_result(result)
    result
  end

  defp bench_cb_allow_closed do
    ZtlpGateway.CircuitBreaker.reset()
    # Insert a closed-state entry
    :ets.insert(ZtlpGateway.CircuitBreaker, {"bench-closed", :closed, 0, 0, false})

    result = measure("CB allow?/1 — closed state (hot path)", fn ->
      ZtlpGateway.CircuitBreaker.allow?("bench-closed")
    end)
    print_result(result)
    result
  end

  defp bench_cb_allow_open do
    ZtlpGateway.CircuitBreaker.reset()
    now = System.monotonic_time(:millisecond)
    # Insert an open-state entry that's NOT expired (recent failure)
    :ets.insert(ZtlpGateway.CircuitBreaker, {"bench-open", :open, 5, now, false})

    result = measure("CB allow?/1 — open state (reject)", fn ->
      ZtlpGateway.CircuitBreaker.allow?("bench-open")
    end)
    print_result(result)
    result
  end

  defp bench_cb_record_success do
    ZtlpGateway.CircuitBreaker.reset()
    :ets.insert(ZtlpGateway.CircuitBreaker, {"bench-success", :closed, 2, 0, false})

    result = measure("CB record_success/1", fn ->
      ZtlpGateway.CircuitBreaker.record_success("bench-success")
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_cb_record_failure do
    ZtlpGateway.CircuitBreaker.reset()

    result = measure("CB record_failure/1 (no trip)", fn ->
      # Reset state each iteration to avoid tripping
      :ets.insert(ZtlpGateway.CircuitBreaker, {"bench-fail", :closed, 0, 0, false})
      ZtlpGateway.CircuitBreaker.record_failure("bench-fail")
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_cb_state_transition do
    Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 1)

    result = measure("CB state transition (closed→open→closed)", fn ->
      ZtlpGateway.CircuitBreaker.reset()
      :ets.insert(ZtlpGateway.CircuitBreaker, {"bench-transition", :closed, 0, 0, false})
      # Trip the breaker
      ZtlpGateway.CircuitBreaker.record_failure("bench-transition")
      # Reset via success (simulate half-open → closed)
      ZtlpGateway.CircuitBreaker.record_success("bench-transition")
    end, 10_000)
    print_result(result)

    # Restore default threshold
    Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
    result
  end

  # ── Component Auth Benchmarks ──────────────────────────────────────

  defp bench_gw_component_auth_parse_challenge do
    challenge = <<0xCA>> <> :crypto.strong_rand_bytes(16)

    result = measure("GW ComponentAuth parse_challenge/1", fn ->
      ZtlpGateway.ComponentAuth.parse_challenge(challenge)
    end)
    print_result(result)
    result
  end

  defp bench_gw_component_auth_sign_challenge do
    {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    nonce = :crypto.strong_rand_bytes(16)

    result = measure("GW ComponentAuth sign_challenge/2", fn ->
      ZtlpGateway.ComponentAuth.sign_challenge(nonce, priv)
    end, 10_000)
    print_result(result)
    result
  end

  defp bench_gw_component_auth_full_roundtrip do
    {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    result = measure("GW ComponentAuth full roundtrip", fn ->
      # Simulate: NS sends challenge, gateway responds
      nonce = :crypto.strong_rand_bytes(16)
      challenge_bin = <<0xCA, nonce::binary>>

      # Gateway parses challenge
      {:ok, ^nonce} = ZtlpGateway.ComponentAuth.parse_challenge(challenge_bin)

      # Gateway signs and responds
      response_bin = ZtlpGateway.ComponentAuth.sign_challenge(nonce, priv)

      # NS parses and verifies
      {:ok, sig, peer_pub} = ZtlpGateway.ComponentAuth.parse_response(response_bin)
      :crypto.verify(:eddsa, :none, nonce, sig, [peer_pub, :ed25519])
    end, 5_000)
    print_result(result)
    result
  end

  # ── Identity Resolution Benchmarks ─────────────────────────────────

  defp bench_identity_cache_hit do
    # Populate identity cache
    known_key = :crypto.strong_rand_bytes(32)
    ZtlpGateway.Identity.register(known_key, "node1.bench.ztlp")

    result = measure("Identity resolve/1 — cache hit", fn ->
      ZtlpGateway.Identity.resolve(known_key)
    end)
    print_result(result)
    result
  end

  defp bench_identity_cache_miss_ets do
    unknown_key = :crypto.strong_rand_bytes(32)

    result = measure("Identity cache miss (ETS lookup only)", fn ->
      :ets.lookup(:ztlp_gateway_identity_cache, unknown_key)
    end)
    print_result(result)
    result
  end
end
