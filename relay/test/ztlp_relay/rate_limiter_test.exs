defmodule ZtlpRelay.RateLimiterTest do
  use ExUnit.Case

  alias ZtlpRelay.RateLimiter

  @table :ztlp_rate_limiter_test

  setup do
    # Start a dedicated rate limiter for tests
    {:ok, pid} =
      RateLimiter.start_link(
        name: :"rate_limiter_test_#{:erlang.unique_integer([:positive])}",
        table: @table,
        cleanup_interval_ms: 60_000
      )

    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _ -> :ok
      end
    end)

    :ok
  end

  describe "check/4" do
    test "allows requests within the limit" do
      key = {:test, :basic}

      assert :ok = RateLimiter.check(key, 3, 60_000, table: @table)
      assert :ok = RateLimiter.check(key, 3, 60_000, table: @table)
      assert :ok = RateLimiter.check(key, 3, 60_000, table: @table)
    end

    test "rejects requests exceeding the limit" do
      key = {:test, :exceed}

      assert :ok = RateLimiter.check(key, 2, 60_000, table: @table)
      assert :ok = RateLimiter.check(key, 2, 60_000, table: @table)
      assert {:error, :rate_limited} = RateLimiter.check(key, 2, 60_000, table: @table)
    end

    test "allows requests after window expires" do
      key = {:test, :window_expiry}

      # Use a very short window
      assert :ok = RateLimiter.check(key, 1, 50, table: @table)
      assert {:error, :rate_limited} = RateLimiter.check(key, 1, 50, table: @table)

      # Wait for window to expire
      Process.sleep(60)

      assert :ok = RateLimiter.check(key, 1, 50, table: @table)
    end

    test "tracks different keys independently" do
      key_a = {:test, :key_a}
      key_b = {:test, :key_b}

      assert :ok = RateLimiter.check(key_a, 1, 60_000, table: @table)
      assert {:error, :rate_limited} = RateLimiter.check(key_a, 1, 60_000, table: @table)

      # key_b should still be allowed
      assert :ok = RateLimiter.check(key_b, 1, 60_000, table: @table)
    end

    test "works with IP address keys" do
      ip = {192, 168, 1, 1}

      assert :ok = RateLimiter.check(ip, 5, 60_000, table: @table)
      assert :ok = RateLimiter.check(ip, 5, 60_000, table: @table)
    end

    test "works with binary NodeID keys" do
      node_id = :crypto.strong_rand_bytes(16)

      assert :ok = RateLimiter.check(node_id, 3, 60_000, table: @table)
      assert :ok = RateLimiter.check(node_id, 3, 60_000, table: @table)
      assert :ok = RateLimiter.check(node_id, 3, 60_000, table: @table)
      assert {:error, :rate_limited} = RateLimiter.check(node_id, 3, 60_000, table: @table)
    end

    test "handles concurrent access" do
      key = {:test, :concurrent}
      limit = 100

      tasks =
        for _ <- 1..200 do
          Task.async(fn ->
            RateLimiter.check(key, limit, 60_000, table: @table)
          end)
        end

      results = Task.await_many(tasks)
      ok_count = Enum.count(results, &(&1 == :ok))
      limited_count = Enum.count(results, &(&1 == {:error, :rate_limited}))

      # At least `limit` should succeed (could be slightly more due to race conditions)
      assert ok_count >= limit
      assert ok_count + limited_count == 200
    end
  end

  describe "reset/2" do
    test "resets counter for a key" do
      key = {:test, :reset}

      assert :ok = RateLimiter.check(key, 1, 60_000, table: @table)
      assert {:error, :rate_limited} = RateLimiter.check(key, 1, 60_000, table: @table)

      RateLimiter.reset(key, table: @table)

      assert :ok = RateLimiter.check(key, 1, 60_000, table: @table)
    end
  end

  describe "reset_all/1" do
    test "resets all counters" do
      key_a = {:test, :reset_all_a}
      key_b = {:test, :reset_all_b}

      RateLimiter.check(key_a, 1, 60_000, table: @table)
      RateLimiter.check(key_b, 1, 60_000, table: @table)

      RateLimiter.reset_all(table: @table)

      assert :ok = RateLimiter.check(key_a, 1, 60_000, table: @table)
      assert :ok = RateLimiter.check(key_b, 1, 60_000, table: @table)
    end
  end
end
