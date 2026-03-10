# ZTLP Gateway Handshake & Crypto Benchmarks
# Run: cd gateway && mix run bench/bench_handshake.exs
#
# Benchmarks:
#   - Full Noise_XX 3-message handshake
#   - X25519 key generation & DH operations
#   - ChaCha20-Poly1305 encrypt/decrypt (varying payload sizes)
#   - HMAC-BLAKE2s and HKDF operations
#   - Ed25519 sign/verify

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
IO.puts("  ZTLP Gateway Handshake & Crypto Benchmarks")
IO.puts("=" <> String.duplicate("=", 60))

alias ZtlpGateway.{Crypto, Handshake}

# ---------------------------------------------------------------------------
# X25519 Key Operations
# ---------------------------------------------------------------------------

IO.puts("\n--- X25519 Key Operations ---")

Bench.run("Crypto.generate_keypair/0 (X25519)", fn ->
  Crypto.generate_keypair()
end, iterations: 10_000)

{pub_a, priv_a} = Crypto.generate_keypair()
{pub_b, priv_b} = Crypto.generate_keypair()

Bench.run("Crypto.dh/2 (X25519 shared secret)", fn ->
  Crypto.dh(pub_b, priv_a)
end, iterations: 10_000)

# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 AEAD
# ---------------------------------------------------------------------------

IO.puts("\n--- ChaCha20-Poly1305 AEAD ---")

key = :crypto.strong_rand_bytes(32)
nonce = :crypto.strong_rand_bytes(12)
aad = :crypto.strong_rand_bytes(32)

for {label, size} <- [{"64B", 64}, {"1KB", 1024}, {"8KB", 8192}, {"64KB", 65536}] do
  plaintext = :crypto.strong_rand_bytes(size)

  Bench.run("Crypto.encrypt/4 — #{label} payload", fn ->
    Crypto.encrypt(key, nonce, plaintext, aad)
  end, iterations: 10_000)

  {ct, tag} = Crypto.encrypt(key, nonce, plaintext, aad)

  Bench.run("Crypto.decrypt/5 — #{label} payload", fn ->
    Crypto.decrypt(key, nonce, ct, aad, tag)
  end, iterations: 10_000)
end

# ---------------------------------------------------------------------------
# BLAKE2s / HMAC-BLAKE2s / HKDF
# ---------------------------------------------------------------------------

IO.puts("\n--- BLAKE2s / HMAC / HKDF ---")

data_32 = :crypto.strong_rand_bytes(32)
data_256 = :crypto.strong_rand_bytes(256)

Bench.run("Crypto.hash/1 (BLAKE2s) — 32 bytes", fn ->
  Crypto.hash(data_32)
end, iterations: 50_000)

Bench.run("Crypto.hash/1 (BLAKE2s) — 256 bytes", fn ->
  Crypto.hash(data_256)
end, iterations: 50_000)

Bench.run("Crypto.hmac_blake2s/2 — 32 byte key + 32 byte data", fn ->
  Crypto.hmac_blake2s(data_32, data_32)
end, iterations: 50_000)

Bench.run("Crypto.hkdf_extract/2", fn ->
  Crypto.hkdf_extract(data_32, data_32)
end, iterations: 50_000)

Bench.run("Crypto.hkdf_expand/3 — 64 bytes output", fn ->
  Crypto.hkdf_expand(data_32, data_32, 64)
end, iterations: 50_000)

Bench.run("Crypto.hkdf_noise/2 — Noise chaining key update", fn ->
  Crypto.hkdf_noise(data_32, data_32)
end, iterations: 50_000)

Bench.run("Crypto.hkdf_noise_split/2 — Noise transport key split", fn ->
  Crypto.hkdf_noise_split(data_32, data_32)
end, iterations: 50_000)

# ---------------------------------------------------------------------------
# Ed25519 Sign / Verify
# ---------------------------------------------------------------------------

IO.puts("\n--- Ed25519 Sign / Verify ---")

{ed_pub, ed_priv} = Crypto.generate_identity_keypair()
message = :crypto.strong_rand_bytes(128)

Bench.run("Crypto.generate_identity_keypair/0 (Ed25519)", fn ->
  Crypto.generate_identity_keypair()
end, iterations: 5_000)

Bench.run("Crypto.sign/2 (Ed25519) — 128 byte message", fn ->
  Crypto.sign(message, ed_priv)
end, iterations: 5_000)

sig = Crypto.sign(message, ed_priv)

Bench.run("Crypto.verify/3 (Ed25519) — 128 byte message", fn ->
  Crypto.verify(message, sig, ed_pub)
end, iterations: 5_000)

# ---------------------------------------------------------------------------
# Full Noise_XX Handshake
# ---------------------------------------------------------------------------

IO.puts("\n--- Noise_XX Handshake (3-message round trip) ---")

{gw_pub, gw_priv} = Crypto.generate_keypair()

Bench.run("Full Noise_XX handshake (init + 3 msgs + split)", fn ->
  # Initiator setup
  {init_pub, init_priv} = Crypto.generate_keypair()
  init_state = Handshake.init_initiator(init_pub, init_priv)
  resp_state = Handshake.init_responder(gw_pub, gw_priv)

  # Message 1: → e
  {init_state, msg1} = Handshake.create_msg1(init_state)
  {resp_state, _} = Handshake.handle_msg1(resp_state, msg1)

  # Message 2: ← e, ee, s, es
  {resp_state, msg2} = Handshake.create_msg2(resp_state)
  {init_state, _} = Handshake.process_msg2(init_state, msg2)

  # Message 3: → s, se
  {init_state, msg3} = Handshake.create_msg3(init_state)
  {resp_state, _} = Handshake.handle_msg3(resp_state, msg3)

  # Split — derive transport keys
  {:ok, _init_keys} = Handshake.split(init_state)
  {:ok, _resp_keys} = Handshake.split(resp_state)
end, iterations: 2_000)

IO.puts("\n" <> String.duplicate("=", 61))
IO.puts("  Handshake & crypto benchmarks complete.")
IO.puts(String.duplicate("=", 61))
