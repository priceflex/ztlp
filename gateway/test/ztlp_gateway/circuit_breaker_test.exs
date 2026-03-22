defmodule ZtlpGateway.CircuitBreakerTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.CircuitBreaker

  setup do
    # Trap exits so linked GenServer crashes don't kill the test process
    Process.flag(:trap_exit, true)

    # Start the CircuitBreaker GenServer for each test
    case GenServer.whereis(CircuitBreaker) do
      nil -> :ok
      pid ->
        GenServer.stop(pid)
        Process.sleep(10)
    end

    # Set default config
    Application.put_env(:ztlp_gateway, :circuit_breaker_enabled, true)
    Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
    Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 30_000)

    {:ok, _pid} = CircuitBreaker.start_link()

    on_exit(fn ->
      try do
        case GenServer.whereis(CircuitBreaker) do
          nil -> :ok
          p when is_pid(p) -> GenServer.stop(p)
          _ -> :ok
        end
      catch
        :exit, _ -> :ok
      end
      Application.delete_env(:ztlp_gateway, :circuit_breaker_enabled)
      Application.delete_env(:ztlp_gateway, :circuit_breaker_failure_threshold)
      Application.delete_env(:ztlp_gateway, :circuit_breaker_cooldown_ms)
    end)

    :ok
  end

  describe "closed state" do
    test "allows requests for unknown backends" do
      assert CircuitBreaker.allow?("backend-1") == true
    end

    test "allows requests after recording successes" do
      CircuitBreaker.record_success("backend-1")
      assert CircuitBreaker.allow?("backend-1") == true
    end

    test "allows requests with some failures below threshold" do
      for _ <- 1..4 do
        CircuitBreaker.record_failure("backend-1")
      end
      assert CircuitBreaker.allow?("backend-1") == true
    end

    test "state is :closed with recorded failures below threshold" do
      CircuitBreaker.record_failure("backend-1")
      CircuitBreaker.record_failure("backend-1")
      assert {:closed, 2} = CircuitBreaker.get_state("backend-1")
    end
  end

  describe "tripping open" do
    test "trips open after N consecutive failures (default 5)" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert {:open, 5} = CircuitBreaker.get_state("backend-1")
      assert CircuitBreaker.allow?("backend-1") == false
    end

    test "trips open after custom threshold" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 3)

      for _ <- 1..3 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert {:open, 3} = CircuitBreaker.get_state("backend-1")
      assert CircuitBreaker.allow?("backend-1") == false
    end

    test "success resets failure counter" do
      CircuitBreaker.record_failure("backend-1")
      CircuitBreaker.record_failure("backend-1")
      CircuitBreaker.record_failure("backend-1")
      CircuitBreaker.record_success("backend-1")

      assert {:closed, 0} = CircuitBreaker.get_state("backend-1")

      # Need full 5 failures again to trip
      for _ <- 1..4 do
        CircuitBreaker.record_failure("backend-1")
      end
      assert CircuitBreaker.allow?("backend-1") == true
    end
  end

  describe "open state" do
    test "rejects requests immediately" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert CircuitBreaker.allow?("backend-1") == false
      assert CircuitBreaker.allow?("backend-1") == false
      assert CircuitBreaker.allow?("backend-1") == false
    end

    test "accumulates additional failures" do
      for _ <- 1..7 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert {:open, 7} = CircuitBreaker.get_state("backend-1")
    end
  end

  describe "half-open state (cooldown)" do
    test "transitions to half-open after cooldown expires" do
      # Use a very short cooldown for testing
      Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 50)

      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert CircuitBreaker.allow?("backend-1") == false

      # Wait for cooldown
      Process.sleep(60)

      # Should now allow one probe request
      assert CircuitBreaker.allow?("backend-1") == true
      assert {:half_open, 5} = CircuitBreaker.get_state("backend-1")
    end

    test "does not transition before cooldown expires" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 5_000)

      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      # Immediately after tripping — should still be blocked
      assert CircuitBreaker.allow?("backend-1") == false
    end
  end

  describe "successful recovery (half_open → closed)" do
    test "closes circuit when half-open probe succeeds" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 50)

      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      Process.sleep(60)

      # Probe request goes through
      assert CircuitBreaker.allow?("backend-1") == true

      # Record success — circuit should close
      CircuitBreaker.record_success("backend-1")
      assert {:closed, 0} = CircuitBreaker.get_state("backend-1")

      # All subsequent requests should be allowed
      assert CircuitBreaker.allow?("backend-1") == true
      assert CircuitBreaker.allow?("backend-1") == true
    end
  end

  describe "failed recovery (half_open → open)" do
    test "re-opens circuit when half-open probe fails" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 50)

      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end

      Process.sleep(60)

      # Probe request goes through
      assert CircuitBreaker.allow?("backend-1") == true

      # Record failure — circuit should re-open
      CircuitBreaker.record_failure("backend-1")
      assert {:open, 6} = CircuitBreaker.get_state("backend-1")
      assert CircuitBreaker.allow?("backend-1") == false
    end
  end

  describe "multiple independent backends" do
    test "backends have independent circuit states" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-a")
      end

      # backend-a should be open
      assert CircuitBreaker.allow?("backend-a") == false

      # backend-b should be unaffected
      assert CircuitBreaker.allow?("backend-b") == true
      assert CircuitBreaker.get_state("backend-b") == :unknown
    end

    test "success on one backend doesn't affect another" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-a")
        CircuitBreaker.record_failure("backend-b")
      end

      CircuitBreaker.record_success("backend-a")

      assert {:closed, 0} = CircuitBreaker.get_state("backend-a")
      assert {:open, 5} = CircuitBreaker.get_state("backend-b")
    end

    test "three backends with different states" do
      # backend-1: closed (healthy)
      CircuitBreaker.record_success("backend-1")

      # backend-2: open (failing)
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-2")
      end

      # backend-3: some failures but not tripped
      for _ <- 1..3 do
        CircuitBreaker.record_failure("backend-3")
      end

      assert CircuitBreaker.allow?("backend-1") == true
      assert CircuitBreaker.allow?("backend-2") == false
      assert CircuitBreaker.allow?("backend-3") == true

      assert {:closed, 0} = CircuitBreaker.get_state("backend-1")
      assert {:open, 5} = CircuitBreaker.get_state("backend-2")
      assert {:closed, 3} = CircuitBreaker.get_state("backend-3")
    end
  end

  describe "concurrent access" do
    test "handles concurrent allow? calls" do
      tasks = for _ <- 1..100 do
        Task.async(fn -> CircuitBreaker.allow?("backend-1") end)
      end

      results = Enum.map(tasks, &Task.await/1)
      assert Enum.all?(results, fn r -> r == true end)
    end

    test "handles concurrent failure recording" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 50)

      tasks = for _ <- 1..100 do
        Task.async(fn -> CircuitBreaker.record_failure("backend-1") end)
      end

      Enum.each(tasks, &Task.await/1)

      # Allow ETS state to settle after concurrent writes
      Process.sleep(50)

      {state, failures} = CircuitBreaker.get_state("backend-1")
      # Due to races, the exact count might vary, but should be around 100
      # and the state should be open (since 100 >= 50)
      assert state == :open
      assert failures > 0
    end
  end

  describe "reset/0" do
    test "clears all circuit breaker state" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end
      CircuitBreaker.record_success("backend-2")

      CircuitBreaker.reset()

      assert CircuitBreaker.get_state("backend-1") == :unknown
      assert CircuitBreaker.get_state("backend-2") == :unknown
    end

    test "allows requests after reset" do
      for _ <- 1..5 do
        CircuitBreaker.record_failure("backend-1")
      end
      assert CircuitBreaker.allow?("backend-1") == false

      CircuitBreaker.reset()
      assert CircuitBreaker.allow?("backend-1") == true
    end
  end

  describe "disabled circuit breaker" do
    test "always allows requests when disabled" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_enabled, false)

      for _ <- 1..10 do
        CircuitBreaker.record_failure("backend-1")
      end

      assert CircuitBreaker.allow?("backend-1") == true
    end
  end

  describe "edge cases" do
    test "threshold of 1 trips on first failure" do
      Application.put_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 1)

      CircuitBreaker.record_failure("backend-1")
      assert {:open, 1} = CircuitBreaker.get_state("backend-1")
      assert CircuitBreaker.allow?("backend-1") == false
    end

    test "get_state returns :unknown for never-seen backends" do
      assert CircuitBreaker.get_state("nonexistent") == :unknown
    end
  end
end
