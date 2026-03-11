defmodule ZtlpRelay.PathScoreProbingTest do
  use ExUnit.Case, async: false
  alias ZtlpRelay.{PathScore, RelayRegistry}

  setup do
    try do
      :ets.new(:ztlp_relay_health, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])
    rescue
      ArgumentError -> :ok
    end

    try do
      :ets.delete_all_objects(:ztlp_relay_health)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  describe "PathScore.compute_jitter/1" do
    test "returns 0.0 for empty list" do
      assert PathScore.compute_jitter([]) == 0.0
    end

    test "returns 0.0 for single sample" do
      assert PathScore.compute_jitter([50.0]) == 0.0
    end

    test "returns 0.0 for identical samples" do
      assert PathScore.compute_jitter([100.0, 100.0, 100.0, 100.0]) == 0.0
    end

    test "computes correct jitter for known values" do
      assert PathScore.compute_jitter([40.0, 60.0]) == 10.0
    end

    test "higher variance yields higher jitter" do
      stable = [50.0, 51.0, 49.0, 50.0, 50.5]
      unstable = [10.0, 90.0, 20.0, 80.0, 50.0]
      assert PathScore.compute_jitter(unstable) > PathScore.compute_jitter(stable)
    end
  end

  describe "PathScore.compute/1 with jitter" do
    test "zero jitter matches old formula" do
      metrics = %{rtt_ms: 50, loss_rate: 0.1, load_factor: 0.5, jitter_ms: 0.0}
      assert PathScore.compute(metrics) == 200.0
    end

    test "jitter increases score" do
      base = %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 0.0}
      jittery = %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 50.0}
      assert PathScore.compute(jittery) > PathScore.compute(base)
    end

    test "100ms jitter adds 100% penalty" do
      metrics = %{rtt_ms: 100, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 100.0}
      assert PathScore.compute(metrics) == 200.0
    end

    test "backward compatible without jitter_ms key" do
      metrics = %{rtt_ms: 50, loss_rate: 0.0, load_factor: 0.0}
      assert PathScore.compute(metrics) == 50.0
    end
  end

  describe "RelayRegistry.classify_health/3" do
    test "healthy: low loss and low RTT" do
      assert RelayRegistry.classify_health(0.01, 100.0, 0) == :healthy
    end

    test "degraded: moderate loss" do
      assert RelayRegistry.classify_health(0.10, 100.0, 0) == :degraded
    end

    test "degraded: high RTT" do
      assert RelayRegistry.classify_health(0.02, 800.0, 0) == :degraded
    end

    test "unreachable: high loss" do
      assert RelayRegistry.classify_health(0.30, 100.0, 0) == :unreachable
    end

    test "unreachable: 3+ missed sweeps" do
      assert RelayRegistry.classify_health(0.0, 100.0, 3) == :unreachable
    end

    test "unreachable: very high RTT" do
      assert RelayRegistry.classify_health(0.06, 2500.0, 0) == :unreachable
    end
  end

  describe "health state transitions" do
    test "starts healthy by default" do
      node_id = :crypto.strong_rand_bytes(16)
      assert RelayRegistry.get_health(node_id) == :healthy
    end

    test "healthy to degraded on moderate loss" do
      node_id = :crypto.strong_rand_bytes(16)

      result =
        RelayRegistry.update_health(node_id,
          loss_rate: 0.15,
          rtt_ms: 100.0,
          missed_sweeps: 0,
          pong_received: true
        )

      assert result == :degraded
      assert RelayRegistry.get_health(node_id) == :degraded
    end

    test "healthy to unreachable on high loss" do
      node_id = :crypto.strong_rand_bytes(16)

      result =
        RelayRegistry.update_health(node_id,
          loss_rate: 0.30,
          rtt_ms: 100.0,
          missed_sweeps: 0,
          pong_received: true
        )

      assert result == :unreachable
    end

    test "degraded to healthy requires 3 good pings" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.update_health(node_id,
        loss_rate: 0.10,
        rtt_ms: 100.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded

      RelayRegistry.update_health(node_id,
        loss_rate: 0.01,
        rtt_ms: 50.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded

      RelayRegistry.update_health(node_id,
        loss_rate: 0.01,
        rtt_ms: 50.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded

      result =
        RelayRegistry.update_health(node_id,
          loss_rate: 0.01,
          rtt_ms: 50.0,
          missed_sweeps: 0,
          pong_received: true
        )

      assert result == :healthy
    end

    test "unreachable to degraded on pong" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.update_health(node_id,
        loss_rate: 0.30,
        rtt_ms: 100.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :unreachable

      result =
        RelayRegistry.update_health(node_id,
          loss_rate: 0.10,
          rtt_ms: 100.0,
          missed_sweeps: 0,
          pong_received: true
        )

      assert result == :degraded
    end

    test "unreachable stays unreachable without pong" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.update_health(node_id,
        loss_rate: 0.30,
        rtt_ms: 100.0,
        missed_sweeps: 0,
        pong_received: true
      )

      result =
        RelayRegistry.update_health(node_id,
          loss_rate: 0.10,
          rtt_ms: 100.0,
          missed_sweeps: 3,
          pong_received: false
        )

      assert result == :unreachable
    end

    test "good streak resets on bad ping" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.update_health(node_id,
        loss_rate: 0.10,
        rtt_ms: 100.0,
        missed_sweeps: 0,
        pong_received: true
      )

      RelayRegistry.update_health(node_id,
        loss_rate: 0.01,
        rtt_ms: 50.0,
        missed_sweeps: 0,
        pong_received: true
      )

      RelayRegistry.update_health(node_id,
        loss_rate: 0.01,
        rtt_ms: 50.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded

      RelayRegistry.update_health(node_id,
        loss_rate: 0.10,
        rtt_ms: 600.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded

      for _ <- 1..3 do
        RelayRegistry.update_health(node_id,
          loss_rate: 0.01,
          rtt_ms: 50.0,
          missed_sweeps: 0,
          pong_received: true
        )
      end

      assert RelayRegistry.get_health(node_id) == :healthy
    end
  end

  describe "remove_health/1" do
    test "removes health tracking" do
      node_id = :crypto.strong_rand_bytes(16)

      RelayRegistry.update_health(node_id,
        loss_rate: 0.15,
        rtt_ms: 100.0,
        missed_sweeps: 0,
        pong_received: true
      )

      assert RelayRegistry.get_health(node_id) == :degraded
      RelayRegistry.remove_health(node_id)
      assert RelayRegistry.get_health(node_id) == :healthy
    end
  end

  describe "sequence number correlation" do
    alias ZtlpRelay.InterRelay

    test "ping encodes seq and pong echoes it" do
      node_id = :crypto.strong_rand_bytes(16)
      ping = InterRelay.encode_ping(node_id, 42)
      {:ok, {:relay_ping, _, _, payload}} = InterRelay.decode(ping)
      assert payload.seq == 42

      metrics = %{active_sessions: 10, max_sessions: 1000, uptime_seconds: 3600}
      pong = InterRelay.encode_pong(node_id, metrics, payload.seq)
      {:ok, {:relay_pong, _, _, pong_payload}} = InterRelay.decode(pong)
      assert pong_payload.echo_seq == 42
    end

    test "different pings have different seqs" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, {:relay_ping, _, _, p1}} = InterRelay.decode(InterRelay.encode_ping(node_id, 1))
      {:ok, {:relay_ping, _, _, p2}} = InterRelay.decode(InterRelay.encode_ping(node_id, 2))
      assert p1.seq == 1
      assert p2.seq == 2
    end
  end

  describe "PathScore.select_best with jitter" do
    test "prefers relay with lower jitter" do
      candidates = [%{node_id: "relay-1"}, %{node_id: "relay-2"}]

      scores = %{
        "relay-1" => %{rtt_ms: 50.0, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 100.0},
        "relay-2" => %{rtt_ms: 50.0, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 5.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == "relay-2"
    end

    test "high jitter can override lower RTT" do
      candidates = [%{node_id: "fast-jittery"}, %{node_id: "slow-stable"}]

      scores = %{
        "fast-jittery" => %{rtt_ms: 30.0, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 200.0},
        "slow-stable" => %{rtt_ms: 50.0, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 0.0}
      }

      assert {:ok, best} = PathScore.select_best(candidates, scores)
      assert best.node_id == "slow-stable"
    end
  end
end
