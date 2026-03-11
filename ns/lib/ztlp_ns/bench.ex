defmodule ZtlpNs.Bench do
  @moduledoc """
  Performance benchmarks for new NS features:
  rate limiter, replication, anti-entropy, component auth.

  Run: cd ns && mix run -e "ZtlpNs.Bench.run()"
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

  defp ensure_rate_limiter_table do
    case :ets.whereis(ZtlpNs.RateLimiter) do
      :undefined ->
        :ets.new(ZtlpNs.RateLimiter, [
          :named_table, :public, :set,
          read_concurrency: true, write_concurrency: true
        ])
      _tid -> :ok
    end

    # Metrics table
    case :ets.whereis(:ztlp_ns_ratelimit_metrics) do
      :undefined ->
        try do
          :ets.new(:ztlp_ns_ratelimit_metrics, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  defp ensure_anti_entropy_metrics do
    case :ets.whereis(:ztlp_ns_antientropy_metrics) do
      :undefined ->
        try do
          :ets.new(:ztlp_ns_antientropy_metrics, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  defp ensure_component_auth_tables do
    # NS component auth nonce table
    case :ets.whereis(:ztlp_ns_component_nonces) do
      :undefined ->
        try do
          :ets.new(:ztlp_ns_component_nonces, [:set, :public, :named_table])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  # ── Main entry point ───────────────────────────────────────────────

  def run do
    IO.puts("=" <> String.duplicate("=", 60))
    IO.puts("  ZTLP-NS — New Feature Benchmarks")
    IO.puts("=" <> String.duplicate("=", 60))

    ensure_rate_limiter_table()
    ensure_anti_entropy_metrics()
    ensure_component_auth_tables()

    # Configure rate limiter
    Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
    Application.put_env(:ztlp_ns, :rate_limit_burst, 200)

    results = []

    # 1. Rate Limiter
    IO.puts("\n--- Rate Limiter ---")

    r1 = bench_rate_limiter_check_allowed()
    r2 = bench_rate_limiter_check_rejected()
    r3 = bench_rate_limiter_metrics()

    results = results ++ [r1, r2, r3]

    # 2. Anti-Entropy Hash Computation
    IO.puts("\n--- Anti-Entropy ---")

    r4 = bench_anti_entropy_leaf_hash()
    r5 = bench_anti_entropy_root_hash_small()
    r6 = bench_anti_entropy_root_hash_large()
    r7 = bench_anti_entropy_merge_records()

    results = results ++ [r4, r5, r6, r7]

    # 3. Replication overhead (local only — no cluster peers)
    IO.puts("\n--- Replication ---")

    r8 = bench_replication_no_peers()

    results = results ++ [r8]

    # 4. Component Auth
    IO.puts("\n--- Component Auth ---")

    r9 = bench_ns_component_auth_generate_challenge()
    r10 = bench_ns_component_auth_sign_challenge()
    r11 = bench_ns_component_auth_full_roundtrip()

    results = results ++ [r9, r10, r11]

    # 5. Cluster status
    IO.puts("\n--- Cluster ---")

    r12 = bench_cluster_status()

    results = results ++ [r12]

    # Print markdown table
    IO.puts("\n\n--- Markdown Table ---")
    IO.puts("| Benchmark | Mean | Median | p99 | Throughput |")
    IO.puts("|-----------|------|--------|-----|------------|")
    Enum.each(results, &print_table_row/1)

    IO.puts("\n" <> String.duplicate("=", 61))
    IO.puts("  NS new-feature benchmarks complete.")
    IO.puts(String.duplicate("=", 61))
  end

  # ── Rate Limiter Benchmarks ────────────────────────────────────────

  defp bench_rate_limiter_check_allowed do
    # Use different IPs to avoid bucket exhaustion
    counter = :counters.new(1, [])

    result = measure("RateLimiter check/1 — allowed (fresh bucket)", fn ->
      idx = :counters.get(counter, 1)
      :counters.add(counter, 1, 1)
      # Use unique IPs so each gets a fresh bucket
      ip = {10, rem(div(idx, 65536), 256), rem(div(idx, 256), 256), rem(idx, 256)}
      ZtlpNs.RateLimiter.check(ip)
    end)
    print_result(result)
    result
  end

  defp bench_rate_limiter_check_rejected do
    # Exhaust the bucket for one IP
    test_ip = {192, 168, 99, 1}
    :ets.insert(ZtlpNs.RateLimiter, {test_ip, 0.0, System.monotonic_time(:millisecond)})

    result = measure("RateLimiter check/1 — rate_limited (empty bucket)", fn ->
      # Keep bucket empty
      :ets.insert(ZtlpNs.RateLimiter, {test_ip, 0.0, System.monotonic_time(:millisecond)})
      ZtlpNs.RateLimiter.check(test_ip)
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_rate_limiter_metrics do
    result = measure("RateLimiter metrics/0", fn ->
      ZtlpNs.RateLimiter.metrics()
    end, 50_000)
    print_result(result)
    result
  end

  # ── Anti-Entropy Benchmarks ────────────────────────────────────────

  defp bench_anti_entropy_leaf_hash do
    # Direct BLAKE2s hash (the leaf_hash operation)
    name = "node1.bench.ztlp"
    type_byte = 1  # :key
    serial = 42

    result = measure("AntiEntropy leaf hash (BLAKE2s)", fn ->
      :crypto.hash(:blake2s, <<name::binary, type_byte::8, serial::unsigned-big-64>>)
    end)
    print_result(result)
    result
  end

  defp bench_anti_entropy_root_hash_small do
    # Compute root hash over a small store (10 records)
    # We'll use the Store.list() → hash pattern from AntiEntropy
    records = for i <- 1..10 do
      name = "node#{i}.ae-bench.ztlp"
      leaf = :crypto.hash(:blake2s, <<name::binary, 1::8, i::unsigned-big-64>>)
      {name, :key, leaf}
    end

    leaf_hashes = records
      |> Enum.sort_by(fn {name, type, _} -> {name, type} end)
      |> Enum.map(fn {_, _, leaf} -> leaf end)

    result = measure("AntiEntropy root hash (10 records)", fn ->
      :crypto.hash(:blake2s, IO.iodata_to_binary(leaf_hashes))
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_anti_entropy_root_hash_large do
    # Root hash over 1000 leaf hashes
    leaf_hashes = for i <- 1..1000 do
      name = "node#{i}.ae-large-bench.ztlp"
      :crypto.hash(:blake2s, <<name::binary, 1::8, i::unsigned-big-64>>)
    end

    result = measure("AntiEntropy root hash (1000 records)", fn ->
      :crypto.hash(:blake2s, IO.iodata_to_binary(leaf_hashes))
    end, 10_000)
    print_result(result)
    result
  end

  defp bench_anti_entropy_merge_records do
    # Simulate merge conflict resolution logic (without actual Store)
    # This measures the decision logic cost

    result = measure("AntiEntropy merge decision logic", fn ->
      # Simulate the checks done in merge_one:
      # Use :rand to avoid compile-time constant folding warnings
      # 1. Signature check (simulated — always valid in bench)
      sig_valid = :rand.uniform() < 2.0
      # 2. TTL check
      now = System.system_time(:second)
      created_at = now - 100
      ttl = 86400
      expired = ttl != 0 and now > created_at + ttl
      # 3. Serial comparison (remote wins most of the time)
      local_serial = 5
      remote_serial = 5 + :rand.uniform(5)
      stale = remote_serial <= local_serial

      cond do
        not sig_valid -> :rejected
        expired -> :skipped
        stale -> :skipped
        true -> :accepted
      end
    end)
    print_result(result)
    result
  end

  # ── Replication Benchmarks ─────────────────────────────────────────

  defp bench_replication_no_peers do
    # Replication with no peers (Node.list() == [])
    # Measures the overhead of the replication check itself

    # Ensure replication metrics table exists
    case :ets.whereis(:ztlp_ns_replication_metrics) do
      :undefined ->
        try do
          :ets.new(:ztlp_ns_replication_metrics, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end

    # Create a minimal record struct for testing
    record = %ZtlpNs.Record{
      name: "node1.repl-bench.ztlp",
      type: :key,
      data: %{node_id: "abc123", public_key: "def456", algorithm: "Ed25519"},
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: 1,
      signature: :crypto.strong_rand_bytes(64),
      signer_public_key: :crypto.strong_rand_bytes(32)
    }

    result = measure("Replication replicate/1 — no peers", fn ->
      ZtlpNs.Replication.replicate(record)
    end, 50_000)
    print_result(result)
    result
  end

  # ── Component Auth Benchmarks ──────────────────────────────────────

  defp bench_ns_component_auth_generate_challenge do
    result = measure("NS ComponentAuth generate_challenge/0", fn ->
      ZtlpNs.ComponentAuth.generate_challenge()
    end, 50_000)
    print_result(result)
    result
  end

  defp bench_ns_component_auth_sign_challenge do
    {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    nonce = :crypto.strong_rand_bytes(16)

    result = measure("NS ComponentAuth sign_challenge/2", fn ->
      ZtlpNs.ComponentAuth.sign_challenge(nonce, priv)
    end, 10_000)
    print_result(result)
    result
  end

  defp bench_ns_component_auth_full_roundtrip do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    result = measure("NS ComponentAuth full roundtrip", fn ->
      # NS generates challenge
      {challenge_bin, nonce} = ZtlpNs.ComponentAuth.generate_challenge()

      # Client parses and responds
      {:ok, ^nonce} = ZtlpNs.ComponentAuth.parse_challenge(challenge_bin)
      response_bin = ZtlpNs.ComponentAuth.sign_challenge(nonce, priv)

      # NS verifies
      {:ok, sig, peer_pub} = ZtlpNs.ComponentAuth.parse_response(response_bin)
      ZtlpNs.ComponentAuth.verify_response(nonce, sig, peer_pub,
        enabled: true, allowed_keys: [pub])
    end, 5_000)
    print_result(result)
    result
  end

  # ── Cluster Status Benchmarks ──────────────────────────────────────

  defp bench_cluster_status do
    result = measure("Cluster clustered?/0 (single node)", fn ->
      ZtlpNs.Cluster.clustered?()
    end, 50_000)
    print_result(result)
    result
  end
end
