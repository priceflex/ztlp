# ZTLP Gateway Throughput Benchmarks
# Run: cd gateway && mix run bench/bench_gateway.exs
#
# Benchmarks:
#   - Data packet decrypt throughput (varying payload sizes)
#   - Policy engine evaluation
#   - Identity resolution (cache hit vs miss)

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
IO.puts("  ZTLP Gateway Throughput Benchmarks")
IO.puts("=" <> String.duplicate("=", 60))

alias ZtlpGateway.{Crypto, PolicyEngine, Identity}

# ---------------------------------------------------------------------------
# Data Packet Decrypt (varying payload sizes)
# ---------------------------------------------------------------------------

IO.puts("\n--- Data Packet Decrypt Throughput ---")

key = :crypto.strong_rand_bytes(32)
nonce = :crypto.strong_rand_bytes(12)
aad = :crypto.strong_rand_bytes(42)  # Simulating full data header as AAD

for {label, size} <- [{"64B", 64}, {"1KB", 1024}, {"8KB", 8192}, {"64KB", 65536}] do
  plaintext = :crypto.strong_rand_bytes(size)
  {ct, tag} = Crypto.encrypt(key, nonce, plaintext, aad)

  Bench.run("Decrypt #{label} payload (ChaCha20-Poly1305)", fn ->
    Crypto.decrypt(key, nonce, ct, aad, tag)
  end, iterations: 10_000)
end

# ---------------------------------------------------------------------------
# Policy Engine Evaluation
# ---------------------------------------------------------------------------

IO.puts("\n--- Policy Engine Evaluation ---")

# Add rules with varying complexity
PolicyEngine.put_rule("public-web", :all)
PolicyEngine.put_rule("ssh-admin", ["admin.acme.ztlp", "ops.acme.ztlp"])
PolicyEngine.put_rule("db-internal", [
  "app1.acme.ztlp",
  "app2.acme.ztlp",
  "*.db-tier.acme.ztlp"
])

# Generate a large rule set
for i <- 1..50 do
  allowed = for j <- 1..10, do: "node#{j}.svc#{i}.ztlp"
  PolicyEngine.put_rule("service-#{i}", allowed)
end

Bench.run("PolicyEngine.authorize?/2 — :all rule (always allow)", fn ->
  PolicyEngine.authorize?("anyone.ztlp", "public-web")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — exact match (2 entries)", fn ->
  PolicyEngine.authorize?("admin.acme.ztlp", "ssh-admin")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — wildcard match", fn ->
  PolicyEngine.authorize?("replica3.db-tier.acme.ztlp", "db-internal")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — deny (no match)", fn ->
  PolicyEngine.authorize?("attacker.evil.ztlp", "ssh-admin")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — deny (no rule for service)", fn ->
  PolicyEngine.authorize?("anyone.ztlp", "nonexistent-service")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — large rule (10 patterns)", fn ->
  PolicyEngine.authorize?("node5.svc25.ztlp", "service-25")
end, iterations: 50_000)

Bench.run("PolicyEngine.authorize?/2 — large rule miss", fn ->
  PolicyEngine.authorize?("unknown.svc25.ztlp", "service-25")
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Identity Resolution
# ---------------------------------------------------------------------------

IO.puts("\n--- Identity Resolution ---")

# Populate identity cache
known_key = :crypto.strong_rand_bytes(32)
Identity.register(known_key, "node1.acme.ztlp")

for i <- 1..1000 do
  pk = :crypto.strong_rand_bytes(32)
  Identity.register(pk, "node#{i}.bench.ztlp")
end

Bench.run("Identity.resolve/1 — cache hit", fn ->
  Identity.resolve(known_key)
end, iterations: 50_000)

unknown_key = :crypto.strong_rand_bytes(32)

# Note: cache miss triggers NS lookup with network timeout — only test with
# low iteration count to avoid blocking. In production, NS responses are
# cached on first hit.
Bench.run("Identity.resolve/1 — cache miss (ETS miss, no NS)", fn ->
  # Directly check ETS to measure cache-miss path without NS timeout
  :ets.lookup(:ztlp_gateway_identity_cache, unknown_key)
end, iterations: 50_000)

Bench.run("Identity.resolve_or_hex/1 — cache hit", fn ->
  Identity.resolve_or_hex(known_key)
end, iterations: 50_000)

Bench.run("Identity.resolve_or_hex/1 — cache miss (hex fallback)", fn ->
  # Direct ETS + hex encode to avoid NS timeout
  case :ets.lookup(:ztlp_gateway_identity_cache, unknown_key) do
    [{_, id}] -> id
    [] -> "unknown:" <> Base.encode16(unknown_key, case: :lower)
  end
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Combined: Decrypt + Policy Check (steady-state data path)
# ---------------------------------------------------------------------------

IO.puts("\n--- Combined: Decrypt + Policy Check ---")

nonce2 = :crypto.strong_rand_bytes(12)
plaintext_1k = :crypto.strong_rand_bytes(1024)
{ct_1k, tag_1k} = Crypto.encrypt(key, nonce2, plaintext_1k, aad)

Bench.run("Decrypt 1KB + resolve identity (cached) + authorize", fn ->
  _decrypted = Crypto.decrypt(key, nonce2, ct_1k, aad, tag_1k)
  identity = case :ets.lookup(:ztlp_gateway_identity_cache, known_key) do
    [{_, id}] -> id
    [] -> "unknown"
  end
  PolicyEngine.authorize?(identity, "public-web")
end, iterations: 10_000)

IO.puts("\n" <> String.duplicate("=", 61))
IO.puts("  Gateway throughput benchmarks complete.")
IO.puts(String.duplicate("=", 61))
