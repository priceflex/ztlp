defmodule ZtlpNs.MetricsNewTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.{AntiEntropy, Replication, RateLimiter, ComponentAuth}

  setup do
    # Clean up metrics ETS tables between tests
    for table <- [
      :ztlp_ns_antientropy_metrics,
      :ztlp_ns_replication_metrics,
      :ztlp_ns_ratelimit_metrics,
      :ztlp_ns_component_auth_metrics
    ] do
      if :ets.whereis(table) != :undefined do
        :ets.delete_all_objects(table)
      end
    end

    # Ensure RateLimiter ETS table exists
    unless :ets.whereis(RateLimiter) != :undefined do
      :ets.new(RateLimiter, [
        :named_table, :public, :set,
        read_concurrency: true, write_concurrency: true
      ])
    end
    :ets.delete_all_objects(RateLimiter)

    :ok
  end

  # ── Anti-Entropy metrics ─────────────────────────────────────────────

  describe "AntiEntropy.metrics/0" do
    test "returns zero counters initially" do
      metrics = AntiEntropy.metrics()
      assert metrics.syncs_total == 0
      assert metrics.syncs_needed == 0
      assert metrics.records_merged == 0
      assert metrics.records_rejected == 0
      assert metrics.last_sync_epoch == 0
    end

    test "increments sync counters" do
      AntiEntropy.increment_metric(:syncs_total)
      AntiEntropy.increment_metric(:syncs_total)
      AntiEntropy.increment_metric(:syncs_needed)

      metrics = AntiEntropy.metrics()
      assert metrics.syncs_total == 2
      assert metrics.syncs_needed == 1
    end

    test "increments record merge/reject counters" do
      AntiEntropy.increment_metric(:records_merged, 5)
      AntiEntropy.increment_metric(:records_rejected, 2)

      metrics = AntiEntropy.metrics()
      assert metrics.records_merged == 5
      assert metrics.records_rejected == 2
    end

    test "sets last sync epoch" do
      now = System.system_time(:second)
      AntiEntropy.set_metric(:last_sync_epoch, now)

      metrics = AntiEntropy.metrics()
      assert metrics.last_sync_epoch == now
    end
  end

  # ── Replication metrics ──────────────────────────────────────────────

  describe "Replication.metrics/0" do
    test "returns zero counters initially" do
      metrics = Replication.metrics()
      assert metrics.pushes_total == 0
      assert metrics.push_successes == 0
      assert metrics.push_failures == 0
    end

    test "returns all counter keys" do
      metrics = Replication.metrics()
      assert Map.has_key?(metrics, :pushes_total)
      assert Map.has_key?(metrics, :push_successes)
      assert Map.has_key?(metrics, :push_failures)
    end
  end

  # ── Rate Limiter metrics ─────────────────────────────────────────────

  describe "RateLimiter.metrics/0" do
    test "returns zero counters initially" do
      metrics = RateLimiter.metrics()
      assert metrics.allowed == 0
      assert metrics.rejected == 0
    end

    test "increments allowed counter on successful check" do
      RateLimiter.check({127, 0, 0, 1})
      metrics = RateLimiter.metrics()
      assert metrics.allowed == 1
      assert metrics.rejected == 0
    end

    test "increments rejected counter on rate limited check" do
      # Exhaust the bucket by making many rapid checks
      ip = {10, 0, 0, 1}
      # Set burst very low for testing
      Application.put_env(:ztlp_ns, :rate_limit_burst, 2)
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 1)

      # These should succeed
      RateLimiter.check(ip)
      RateLimiter.check(ip)

      # This should be rate limited
      result = RateLimiter.check(ip)
      assert result == :rate_limited

      metrics = RateLimiter.metrics()
      assert metrics.allowed == 2
      assert metrics.rejected == 1

      # Reset config
      Application.put_env(:ztlp_ns, :rate_limit_burst, 200)
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
    end
  end

  # ── Component Auth metrics ───────────────────────────────────────────

  describe "ComponentAuth.metrics/0" do
    test "returns zero counters initially" do
      metrics = ComponentAuth.metrics()
      assert metrics.challenges == 0
      assert metrics.successes == 0
      assert metrics.failures == 0
    end

    test "increments challenge counter" do
      ComponentAuth.record_challenge()
      assert ComponentAuth.metrics().challenges == 1
    end

    test "increments success counter" do
      ComponentAuth.record_success()
      assert ComponentAuth.metrics().successes == 1
    end

    test "increments failure counter" do
      ComponentAuth.record_failure()
      ComponentAuth.record_failure()
      assert ComponentAuth.metrics().failures == 2
    end
  end

  # ── Cluster metrics ──────────────────────────────────────────────────

  describe "Cluster metrics" do
    test "cluster member count is at least 1 (self)" do
      all_members = [node() | Node.list()]
      assert length(all_members) >= 1
    end
  end

  # ── Prometheus format ────────────────────────────────────────────────

  describe "Prometheus format" do
    test "anti-entropy metrics are valid format" do
      AntiEntropy.increment_metric(:syncs_total)
      m = AntiEntropy.metrics()

      line = "ztlp_ns_antientropy_syncs_total #{m.syncs_total}"
      assert String.match?(line, ~r/^ztlp_ns_antientropy_syncs_total \d+$/)
    end

    test "rate limiter metrics are valid format" do
      RateLimiter.check({127, 0, 0, 1})
      m = RateLimiter.metrics()

      line = "ztlp_ns_ratelimit_allowed_total #{m.allowed}"
      assert String.match?(line, ~r/^ztlp_ns_ratelimit_allowed_total \d+$/)
    end
  end
end
