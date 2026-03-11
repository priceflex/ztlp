defmodule ZtlpRelay.MetricsNewTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.{Backpressure, ComponentAuth}

  setup do
    # Ensure the Backpressure ETS table exists
    unless :ets.whereis(Backpressure) != :undefined do
      :ets.new(Backpressure, [:named_table, :public, :set, read_concurrency: true])
      :ets.insert(Backpressure, {:current_load, 0.0})
    end

    # Clean up metrics state between tests
    if :ets.whereis(:ztlp_relay_component_auth_metrics) != :undefined do
      :ets.delete_all_objects(:ztlp_relay_component_auth_metrics)
    end

    # Reset backpressure rejections
    if :ets.whereis(Backpressure) != :undefined do
      :ets.insert(Backpressure, {:rejections, 0})
      :ets.insert(Backpressure, {:current_load, 0.0})
    end

    :ok
  end

  # ── Backpressure metrics ─────────────────────────────────────────────

  describe "Backpressure.metrics/0" do
    test "returns default metrics with zero state" do
      metrics = Backpressure.metrics()
      assert metrics.state == :ok
      assert metrics.load_ratio == 0.0
      assert metrics.rejections == 0
    end

    test "reflects load changes" do
      Backpressure.update_load(50, 100)
      metrics = Backpressure.metrics()
      assert metrics.load_ratio == 0.5
      assert metrics.state == :ok
    end

    test "reflects soft backpressure state" do
      # Default soft threshold is 0.8
      Backpressure.update_load(85, 100)
      metrics = Backpressure.metrics()
      assert metrics.state == :soft
      assert metrics.load_ratio == 0.85
    end

    test "reflects hard backpressure state" do
      # Default hard threshold is 0.95
      Backpressure.update_load(96, 100)
      metrics = Backpressure.metrics()
      assert metrics.state == :hard
      assert metrics.load_ratio == 0.96
    end

    test "tracks rejections" do
      Backpressure.record_rejection()
      Backpressure.record_rejection()
      Backpressure.record_rejection()
      metrics = Backpressure.metrics()
      assert metrics.rejections == 3
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
      ComponentAuth.record_challenge()
      metrics = ComponentAuth.metrics()
      assert metrics.challenges == 2
    end

    test "increments success counter" do
      ComponentAuth.record_success()
      metrics = ComponentAuth.metrics()
      assert metrics.successes == 1
    end

    test "increments failure counter" do
      ComponentAuth.record_failure()
      ComponentAuth.record_failure()
      metrics = ComponentAuth.metrics()
      assert metrics.failures == 2
    end

    test "tracks all counters independently" do
      ComponentAuth.record_challenge()
      ComponentAuth.record_challenge()
      ComponentAuth.record_challenge()
      ComponentAuth.record_success()
      ComponentAuth.record_success()
      ComponentAuth.record_failure()

      metrics = ComponentAuth.metrics()
      assert metrics.challenges == 3
      assert metrics.successes == 2
      assert metrics.failures == 1
    end
  end

  # ── Prometheus format validation ─────────────────────────────────────

  describe "Prometheus format" do
    test "backpressure metrics appear in valid format" do
      Backpressure.update_load(50, 100)
      Backpressure.record_rejection()

      metrics = Backpressure.metrics()
      state_val = case metrics.state do
        :ok -> 0
        :soft -> 1
        :hard -> 2
      end

      # Verify we can construct valid Prometheus text
      line = "ztlp_relay_backpressure_state #{state_val}"
      assert String.match?(line, ~r/^ztlp_relay_backpressure_state \d+$/)

      line = "ztlp_relay_backpressure_load_ratio #{Float.round(metrics.load_ratio, 4)}"
      assert String.match?(line, ~r/^ztlp_relay_backpressure_load_ratio \d+\.\d+$/)

      line = "ztlp_relay_backpressure_rejections_total #{metrics.rejections}"
      assert String.match?(line, ~r/^ztlp_relay_backpressure_rejections_total \d+$/)
    end

    test "component auth metrics appear in valid format" do
      ComponentAuth.record_challenge()
      ComponentAuth.record_success()

      metrics = ComponentAuth.metrics()

      line = "ztlp_relay_component_auth_challenges_total #{metrics.challenges}"
      assert String.match?(line, ~r/^ztlp_relay_component_auth_challenges_total \d+$/)

      line = "ztlp_relay_component_auth_successes_total #{metrics.successes}"
      assert String.match?(line, ~r/^ztlp_relay_component_auth_successes_total \d+$/)

      line = "ztlp_relay_component_auth_failures_total #{metrics.failures}"
      assert String.match?(line, ~r/^ztlp_relay_component_auth_failures_total \d+$/)
    end
  end
end
