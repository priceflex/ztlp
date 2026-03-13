defmodule ZtlpNs.RateLimiterTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.RateLimiter

  setup do
    # Set default config
    Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
    Application.put_env(:ztlp_ns, :rate_limit_burst, 200)

    # Start the RateLimiter GenServer if not already running (may be
    # started by the supervision tree in full-app test mode)
    case GenServer.whereis(RateLimiter) do
      nil ->
        {:ok, _pid} = RateLimiter.start_link()

      _pid ->
        # Already running (e.g., from supervision tree) — just reset state
        :ok
    end

    RateLimiter.reset()

    on_exit(fn ->
      Application.delete_env(:ztlp_ns, :rate_limit_queries_per_second)
      Application.delete_env(:ztlp_ns, :rate_limit_burst)
    end)

    :ok
  end

  describe "allows queries under limit" do
    test "first query from an IP is always allowed" do
      assert :ok = RateLimiter.check({192, 168, 1, 1})
    end

    test "multiple queries within burst are allowed" do
      ip = {10, 0, 0, 1}

      results = for _ <- 1..100 do
        RateLimiter.check(ip)
      end

      assert Enum.all?(results, fn r -> r == :ok end)
    end

    test "queries from IPv6 addresses work" do
      ip = {0, 0, 0, 0, 0, 0, 0, 1}
      assert :ok = RateLimiter.check(ip)
    end
  end

  describe "blocks queries over limit" do
    test "blocks after burst is exhausted" do
      ip = {10, 0, 0, 2}

      # Exhaust the burst (200 tokens)
      for _ <- 1..200 do
        RateLimiter.check(ip)
      end

      # Next query should be rate limited
      assert :rate_limited = RateLimiter.check(ip)
    end

    test "all queries blocked when bucket is empty" do
      ip = {10, 0, 0, 3}

      # Exhaust all tokens
      for _ <- 1..200 do
        RateLimiter.check(ip)
      end

      # Multiple subsequent queries should all be blocked
      results = for _ <- 1..10 do
        RateLimiter.check(ip)
      end

      assert Enum.all?(results, fn r -> r == :rate_limited end)
    end
  end

  describe "burst allowance" do
    test "allows burst_size queries in rapid succession" do
      Application.put_env(:ztlp_ns, :rate_limit_burst, 50)
      RateLimiter.reset()

      ip = {10, 0, 0, 10}

      results = for _ <- 1..50 do
        RateLimiter.check(ip)
      end

      assert Enum.all?(results, fn r -> r == :ok end)

      # 51st should be rate limited
      assert :rate_limited = RateLimiter.check(ip)
    end

    test "custom burst size of 10" do
      Application.put_env(:ztlp_ns, :rate_limit_burst, 10)
      RateLimiter.reset()

      ip = {10, 0, 0, 11}

      results = for _ <- 1..10 do
        RateLimiter.check(ip)
      end
      assert Enum.all?(results, fn r -> r == :ok end)

      assert :rate_limited = RateLimiter.check(ip)
    end
  end

  describe "different IPs are independent" do
    test "rate limiting one IP does not affect others" do
      ip_a = {192, 168, 1, 1}
      ip_b = {192, 168, 1, 2}

      # Exhaust IP A's bucket
      for _ <- 1..200 do
        RateLimiter.check(ip_a)
      end

      assert :rate_limited = RateLimiter.check(ip_a)

      # IP B should be unaffected
      assert :ok = RateLimiter.check(ip_b)
    end

    test "many IPs can each use their full burst" do
      Application.put_env(:ztlp_ns, :rate_limit_burst, 20)
      RateLimiter.reset()

      for i <- 1..10 do
        ip = {10, 0, 0, i}
        results = for _ <- 1..20 do
          RateLimiter.check(ip)
        end
        assert Enum.all?(results, fn r -> r == :ok end),
          "IP #{inspect(ip)} should allow all 20 queries"
      end
    end
  end

  describe "token replenishment over time" do
    test "tokens replenish after waiting" do
      # Use a low rate and small burst so we can exhaust tokens quickly
      # then verify replenishment with a controlled sleep
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
      Application.put_env(:ztlp_ns, :rate_limit_burst, 10)
      RateLimiter.reset()

      ip = {10, 0, 0, 20}

      # Exhaust all tokens
      for _ <- 1..10 do
        RateLimiter.check(ip)
      end

      # Keep calling until we're definitely rate limited
      # (drains any fractional tokens from timing)
      Enum.reduce_while(1..100, :ok, fn _, _ ->
        case RateLimiter.check(ip) do
          :rate_limited -> {:halt, :rate_limited}
          :ok -> {:cont, :ok}
        end
      end)

      # Confirm we're rate limited right now
      assert :rate_limited = RateLimiter.check(ip)

      # Wait 200ms — at 100 queries/sec, should replenish ~20 tokens (capped at burst=10)
      Process.sleep(200)

      # Should have tokens now
      assert :ok = RateLimiter.check(ip)
    end

    test "replenishment does not exceed burst" do
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 10_000)
      Application.put_env(:ztlp_ns, :rate_limit_burst, 20)
      RateLimiter.reset()

      ip = {10, 0, 0, 21}

      # Use some tokens
      for _ <- 1..10 do
        RateLimiter.check(ip)
      end

      # Wait a long time for max replenishment
      Process.sleep(200)

      # Should be capped at burst (20), so 20 queries should succeed
      results = for _ <- 1..20 do
        RateLimiter.check(ip)
      end
      assert Enum.all?(results, fn r -> r == :ok end)

      # 21st should be limited
      assert :rate_limited = RateLimiter.check(ip)
    end
  end

  describe "cleanup of stale entries" do
    test "tokens_for returns nil for unknown IPs" do
      assert nil == RateLimiter.tokens_for({99, 99, 99, 99})
    end

    test "reset clears all entries" do
      RateLimiter.check({10, 0, 0, 1})
      RateLimiter.check({10, 0, 0, 2})

      RateLimiter.reset()

      assert nil == RateLimiter.tokens_for({10, 0, 0, 1})
      assert nil == RateLimiter.tokens_for({10, 0, 0, 2})
    end

    test "cleanup message is handled without crashing" do
      # Send the cleanup message directly to the GenServer
      send(GenServer.whereis(RateLimiter), :cleanup)
      # Give it time to process
      Process.sleep(20)

      # GenServer should still be alive and functional
      assert :ok = RateLimiter.check({10, 0, 0, 1})
    end
  end

  describe "concurrent access" do
    test "handles concurrent queries from the same IP" do
      ip = {10, 0, 0, 50}

      tasks = for _ <- 1..100 do
        Task.async(fn -> RateLimiter.check(ip) end)
      end

      results = Enum.map(tasks, &Task.await/1)

      # All should succeed since burst (200) > 100
      assert Enum.all?(results, fn r -> r == :ok end)
    end

    test "handles concurrent queries from different IPs" do
      tasks = for i <- 1..50 do
        Task.async(fn ->
          ip = {10, 0, i, 1}
          RateLimiter.check(ip)
        end)
      end

      results = Enum.map(tasks, &Task.await/1)
      assert Enum.all?(results, fn r -> r == :ok end)
    end

    test "rate limiting works under concurrent load" do
      Application.put_env(:ztlp_ns, :rate_limit_burst, 10)
      RateLimiter.reset()

      ip = {10, 0, 0, 60}

      tasks = for _ <- 1..30 do
        Task.async(fn -> RateLimiter.check(ip) end)
      end

      results = Enum.map(tasks, &Task.await/1)

      ok_count = Enum.count(results, fn r -> r == :ok end)
      limited_count = Enum.count(results, fn r -> r == :rate_limited end)

      # Due to concurrency, exact counts may vary, but we should see some limited
      assert ok_count > 0
      assert limited_count > 0
      assert ok_count + limited_count == 30
    end
  end

  describe "configuration" do
    test "reads queries_per_second from app env" do
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 500)
      assert RateLimiter.queries_per_second() == 500
    end

    test "reads burst from app env" do
      Application.put_env(:ztlp_ns, :rate_limit_burst, 1000)
      assert RateLimiter.burst_size() == 1000
    end

    test "defaults when not configured" do
      Application.delete_env(:ztlp_ns, :rate_limit_queries_per_second)
      Application.delete_env(:ztlp_ns, :rate_limit_burst)

      assert RateLimiter.queries_per_second() == 100
      assert RateLimiter.burst_size() == 200
    end
  end
end
