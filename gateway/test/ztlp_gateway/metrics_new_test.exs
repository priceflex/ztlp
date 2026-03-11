defmodule ZtlpGateway.MetricsNewTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.{CircuitBreaker, ComponentAuth}

  setup do
    # Ensure circuit breaker ETS table exists
    unless :ets.whereis(CircuitBreaker) != :undefined do
      :ets.new(CircuitBreaker, [
        :named_table, :public, :set,
        read_concurrency: true, write_concurrency: true
      ])
    end

    # Clean up state
    :ets.delete_all_objects(CircuitBreaker)

    if :ets.whereis(:ztlp_gateway_circuit_breaker_metrics) != :undefined do
      :ets.delete_all_objects(:ztlp_gateway_circuit_breaker_metrics)
    end

    if :ets.whereis(:ztlp_gateway_component_auth_metrics) != :undefined do
      :ets.delete_all_objects(:ztlp_gateway_component_auth_metrics)
    end

    :ok
  end

  # ── Circuit Breaker metrics ──────────────────────────────────────────

  describe "CircuitBreaker.metrics/0" do
    test "returns empty list when no backends exist" do
      assert CircuitBreaker.metrics() == []
    end

    test "returns per-backend metrics after activity" do
      CircuitBreaker.record_success("web")
      CircuitBreaker.record_success("api")

      metrics = CircuitBreaker.metrics()
      assert length(metrics) == 2

      web = Enum.find(metrics, &(&1.backend == "web"))
      assert web.state == :closed
      assert web.successes == 1
      assert web.failures == 0
      assert web.trips == 0
    end

    test "tracks failures per backend" do
      CircuitBreaker.record_failure("web")
      CircuitBreaker.record_failure("web")

      metrics = CircuitBreaker.metrics()
      web = Enum.find(metrics, &(&1.backend == "web"))
      assert web.failures == 2
    end

    test "tracks circuit breaker state transitions" do
      # Set threshold to 2 for easier testing
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 2)

      CircuitBreaker.record_failure("web")
      metrics_before = CircuitBreaker.metrics()
      web_before = Enum.find(metrics_before, &(&1.backend == "web"))
      assert web_before.state == :closed
      assert web_before.trips == 0

      CircuitBreaker.record_failure("web")
      metrics_after = CircuitBreaker.metrics()
      web_after = Enum.find(metrics_after, &(&1.backend == "web"))
      assert web_after.state == :open
      assert web_after.trips == 1

      # Cleanup
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
    end

    test "trips counter increments on each new open transition" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 1)

      # First trip
      CircuitBreaker.record_failure("web")
      m1 = Enum.find(CircuitBreaker.metrics(), &(&1.backend == "web"))
      assert m1.trips == 1

      # Reset to closed
      CircuitBreaker.record_success("web")
      m2 = Enum.find(CircuitBreaker.metrics(), &(&1.backend == "web"))
      assert m2.state == :closed

      # Second trip
      CircuitBreaker.record_failure("web")
      m3 = Enum.find(CircuitBreaker.metrics(), &(&1.backend == "web"))
      assert m3.trips == 2

      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
    end

    test "reports metrics for multiple backends independently" do
      CircuitBreaker.record_success("web")
      CircuitBreaker.record_failure("api")
      CircuitBreaker.record_failure("api")

      metrics = CircuitBreaker.metrics()
      web = Enum.find(metrics, &(&1.backend == "web"))
      api = Enum.find(metrics, &(&1.backend == "api"))

      assert web.successes == 1
      assert web.failures == 0
      assert api.successes == 0
      assert api.failures == 2
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
      assert ComponentAuth.metrics().challenges == 2
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

    test "tracks all counters independently" do
      ComponentAuth.record_challenge()
      ComponentAuth.record_challenge()
      ComponentAuth.record_success()
      ComponentAuth.record_failure()

      m = ComponentAuth.metrics()
      assert m.challenges == 2
      assert m.successes == 1
      assert m.failures == 1
    end
  end

  # ── Prometheus format ────────────────────────────────────────────────

  describe "Prometheus format" do
    test "circuit breaker metrics use valid label syntax" do
      CircuitBreaker.record_success("web")

      metrics = CircuitBreaker.metrics()
      web = Enum.find(metrics, &(&1.backend == "web"))

      state_val = case web.state do
        :closed -> 0
        :open -> 1
        :half_open -> 2
      end

      line = "ztlp_gateway_circuit_breaker_state{backend=\"web\"} #{state_val}"
      assert String.match?(line, ~r/^ztlp_gateway_circuit_breaker_state\{backend="web"\} \d+$/)
    end
  end
end
