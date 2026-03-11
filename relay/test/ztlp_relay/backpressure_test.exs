defmodule ZtlpRelay.BackpressureTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.Backpressure

  setup do
    # Start the Backpressure GenServer for each test
    # Stop it if already running (from a prior test or the application)
    case GenServer.whereis(Backpressure) do
      nil -> :ok
      pid ->
        GenServer.stop(pid)
        # Wait for ETS table to be cleaned up
        Process.sleep(10)
    end

    {:ok, _pid} = Backpressure.start_link()
    on_exit(fn ->
      case GenServer.whereis(Backpressure) do
        nil -> :ok
        p when is_pid(p) -> if Process.alive?(p), do: GenServer.stop(p)
        _ -> :ok
      end
    end)
    :ok
  end

  describe "check/0" do
    test "returns :ok when load is zero" do
      assert :ok = Backpressure.check()
    end

    test "returns :ok when load is below soft threshold" do
      Backpressure.update_load(500, 10_000)  # 5% load
      assert :ok = Backpressure.check()
    end

    test "returns :ok at 79% load (just below default soft threshold)" do
      Backpressure.update_load(7900, 10_000)
      assert :ok = Backpressure.check()
    end

    test "returns {:backpressure, :soft} at exactly 80% load" do
      Backpressure.update_load(8000, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()
    end

    test "returns {:backpressure, :soft} at 90% load" do
      Backpressure.update_load(9000, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()
    end

    test "returns {:backpressure, :soft} at 94% load (just below hard threshold)" do
      Backpressure.update_load(9400, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()
    end

    test "returns {:backpressure, :hard} at exactly 95% load" do
      Backpressure.update_load(9500, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()
    end

    test "returns {:backpressure, :hard} at 100% load" do
      Backpressure.update_load(10_000, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()
    end

    test "returns {:backpressure, :hard} when overloaded (>100%)" do
      Backpressure.update_load(12_000, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()
    end
  end

  describe "recovery" do
    test "recovers from hard backpressure when load drops" do
      Backpressure.update_load(9800, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()

      # Load drops below soft threshold
      Backpressure.update_load(5000, 10_000)
      assert :ok = Backpressure.check()
    end

    test "recovers from soft backpressure when load drops" do
      Backpressure.update_load(8500, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()

      Backpressure.update_load(3000, 10_000)
      assert :ok = Backpressure.check()
    end

    test "transitions from hard to soft when load decreases" do
      Backpressure.update_load(9700, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()

      Backpressure.update_load(8500, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()
    end
  end

  describe "custom thresholds from config" do
    setup do
      # Save original values
      old_soft = Application.get_env(:ztlp_relay, :backpressure_soft_threshold)
      old_hard = Application.get_env(:ztlp_relay, :backpressure_hard_threshold)

      on_exit(fn ->
        if old_soft, do: Application.put_env(:ztlp_relay, :backpressure_soft_threshold, old_soft),
                     else: Application.delete_env(:ztlp_relay, :backpressure_soft_threshold)
        if old_hard, do: Application.put_env(:ztlp_relay, :backpressure_hard_threshold, old_hard),
                     else: Application.delete_env(:ztlp_relay, :backpressure_hard_threshold)
      end)

      :ok
    end

    test "respects custom soft threshold of 0.5" do
      Application.put_env(:ztlp_relay, :backpressure_soft_threshold, 0.5)
      Application.put_env(:ztlp_relay, :backpressure_hard_threshold, 0.9)

      # 40% — below custom soft
      Backpressure.update_load(4000, 10_000)
      assert :ok = Backpressure.check()

      # 50% — at custom soft
      Backpressure.update_load(5000, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()

      # 90% — at custom hard
      Backpressure.update_load(9000, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()
    end

    test "respects custom hard threshold of 0.7" do
      Application.put_env(:ztlp_relay, :backpressure_soft_threshold, 0.6)
      Application.put_env(:ztlp_relay, :backpressure_hard_threshold, 0.7)

      Backpressure.update_load(6500, 10_000)
      assert {:backpressure, :soft} = Backpressure.check()

      Backpressure.update_load(7000, 10_000)
      assert {:backpressure, :hard} = Backpressure.check()
    end

    test "thresholds/0 returns configured values" do
      Application.put_env(:ztlp_relay, :backpressure_soft_threshold, 0.6)
      Application.put_env(:ztlp_relay, :backpressure_hard_threshold, 0.85)

      assert {0.6, 0.85} = Backpressure.thresholds()
    end
  end

  describe "update_load/2" do
    test "updates the current load ratio" do
      Backpressure.update_load(2500, 10_000)
      assert_in_delta Backpressure.current_load(), 0.25, 0.001
    end

    test "handles small max_sessions values" do
      Backpressure.update_load(8, 10)
      assert_in_delta Backpressure.current_load(), 0.8, 0.001
    end

    test "handles zero active sessions" do
      Backpressure.update_load(0, 10_000)
      assert_in_delta Backpressure.current_load(), 0.0, 0.001
    end
  end

  describe "concurrent access" do
    test "handles multiple processes calling check/0 simultaneously" do
      Backpressure.update_load(8500, 10_000)  # soft backpressure

      tasks = for _ <- 1..100 do
        Task.async(fn -> Backpressure.check() end)
      end

      results = Enum.map(tasks, &Task.await/1)

      # All should get the same answer — soft backpressure
      assert Enum.all?(results, fn r -> r == {:backpressure, :soft} end)
    end

    test "handles concurrent updates and reads" do
      tasks =
        for i <- 1..50 do
          Task.async(fn ->
            Backpressure.update_load(i * 200, 10_000)
            Backpressure.check()
          end)
        end

      results = Enum.map(tasks, &Task.await/1)

      # All results should be valid return values
      assert Enum.all?(results, fn
        :ok -> true
        {:backpressure, :soft} -> true
        {:backpressure, :hard} -> true
      end)
    end
  end
end
