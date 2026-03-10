defmodule ZtlpRelay.PathScoreTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.PathScore

  describe "compute/1" do
    test "perfect relay — zero loss and zero load" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0})
      assert_in_delta score, 50.0, 0.001
    end

    test "loss rate heavily penalizes score" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 0.1, load_factor: 0.0})
      # 50 * (1 + 0.1*10) * (1 + 0) = 50 * 2.0 = 100
      assert_in_delta score, 100.0, 0.001
    end

    test "load factor moderately penalizes score" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.5})
      # 50 * (1 + 0) * (1 + 0.5*2) = 50 * 2.0 = 100
      assert_in_delta score, 100.0, 0.001
    end

    test "both loss and load compound" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 0.1, load_factor: 0.5})
      # 50 * (1 + 1.0) * (1 + 1.0) = 50 * 2.0 * 2.0 = 200
      assert_in_delta score, 200.0, 0.001
    end

    test "maximum loss rate" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 1.0, load_factor: 0.0})
      # 50 * (1 + 10) * 1 = 550
      assert_in_delta score, 550.0, 0.001
    end

    test "maximum load factor" do
      score = PathScore.compute(%{rtt_ms: 50, loss_rate: 0.0, load_factor: 1.0})
      # 50 * 1 * (1 + 2) = 150
      assert_in_delta score, 150.0, 0.001
    end

    test "zero RTT results in zero score" do
      score = PathScore.compute(%{rtt_ms: 0, loss_rate: 0.5, load_factor: 0.5})
      assert_in_delta score, 0.0, 0.001
    end

    test "high RTT dominates" do
      score = PathScore.compute(%{rtt_ms: 500, loss_rate: 0.0, load_factor: 0.0})
      assert_in_delta score, 500.0, 0.001
    end
  end

  describe "select_best/2" do
    test "selects the relay with lowest score" do
      candidates = [
        %{node_id: "relay-a", address: {{10, 0, 0, 1}, 23095}},
        %{node_id: "relay-b", address: {{10, 0, 0, 2}, 23095}},
        %{node_id: "relay-c", address: {{10, 0, 0, 3}, 23095}}
      ]

      scores = %{
        "relay-a" => %{rtt_ms: 100, loss_rate: 0.0, load_factor: 0.0},
        "relay-b" => %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0},
        "relay-c" => %{rtt_ms: 200, loss_rate: 0.0, load_factor: 0.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == "relay-b"
    end

    test "lower RTT with some loss beats higher RTT" do
      candidates = [
        %{node_id: "relay-a", address: {{10, 0, 0, 1}, 23095}},
        %{node_id: "relay-b", address: {{10, 0, 0, 2}, 23095}}
      ]

      scores = %{
        # 30 * (1 + 0.01*10) * 1 = 30 * 1.1 = 33
        "relay-a" => %{rtt_ms: 30, loss_rate: 0.01, load_factor: 0.0},
        # 100 * 1 * 1 = 100
        "relay-b" => %{rtt_ms: 100, loss_rate: 0.0, load_factor: 0.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == "relay-a"
    end

    test "returns error for empty candidates" do
      assert :error = PathScore.select_best([], %{})
    end

    test "skips candidates without scores" do
      candidates = [
        %{node_id: "relay-a", address: {{10, 0, 0, 1}, 23095}},
        %{node_id: "relay-b", address: {{10, 0, 0, 2}, 23095}}
      ]

      # Only relay-b has scores
      scores = %{
        "relay-b" => %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == "relay-b"
    end

    test "returns error when no candidates have scores" do
      candidates = [
        %{node_id: "relay-a", address: {{10, 0, 0, 1}, 23095}}
      ]

      assert :error = PathScore.select_best(candidates, %{})
    end

    test "handles equal scores — returns first encountered" do
      candidates = [
        %{node_id: "relay-a", address: {{10, 0, 0, 1}, 23095}},
        %{node_id: "relay-b", address: {{10, 0, 0, 2}, 23095}}
      ]

      scores = %{
        "relay-a" => %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0},
        "relay-b" => %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0}
      }

      assert {:ok, _best} = PathScore.select_best(candidates, scores)
      # Just needs to return one of them, doesn't matter which
    end
  end

  describe "update_rtt/3" do
    test "exponential moving average" do
      # Current RTT = 100, new sample = 50, alpha = 0.3
      # Result = 0.3 * 50 + 0.7 * 100 = 15 + 70 = 85
      assert_in_delta PathScore.update_rtt(100, 50), 85.0, 0.001
    end

    test "converges toward new value" do
      rtt = 100.0
      # Apply 50ms sample 10 times
      rtt = Enum.reduce(1..10, rtt, fn _, acc -> PathScore.update_rtt(acc, 50.0) end)
      # Should be close to 50 after many iterations
      assert_in_delta rtt, 50.0, 5.0
    end

    test "custom alpha" do
      # alpha = 1.0 means new value replaces old entirely
      assert_in_delta PathScore.update_rtt(100, 50, 1.0), 50.0, 0.001
    end
  end

  describe "compute_load_factor/2" do
    test "zero load" do
      assert_in_delta PathScore.compute_load_factor(0, 1000), 0.0, 0.001
    end

    test "half load" do
      assert_in_delta PathScore.compute_load_factor(500, 1000), 0.5, 0.001
    end

    test "full load" do
      assert_in_delta PathScore.compute_load_factor(1000, 1000), 1.0, 0.001
    end

    test "over capacity is capped at 1.0" do
      assert_in_delta PathScore.compute_load_factor(2000, 1000), 1.0, 0.001
    end

    test "zero max capacity returns 1.0" do
      assert_in_delta PathScore.compute_load_factor(100, 0), 1.0, 0.001
    end
  end
end
