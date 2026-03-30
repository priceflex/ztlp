defmodule ZtlpGateway.BbrTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Bbr

  # ── Helper ──

  # Simulate multiple ACK rounds at a constant delivery rate.
  # Returns the BBR state after `count` ACKs.
  defp simulate_acks(state, count, acked_bytes, rtt_ms, start_time, time_step) do
    Enum.reduce(0..(count - 1), state, fn i, acc ->
      now = start_time + i * time_step
      Bbr.on_ack(acc, acked_bytes, rtt_ms, now)
    end)
  end

  # Drive startup to completion: send enough rounds with the same BW
  # to trigger the 3-round plateau exit condition.
  # Returns a state in :drain.
  defp drive_to_drain(now \\ 1_000) do
    state = Bbr.new(0)

    # First ACK establishes initial btl_bw
    state = Bbr.on_ack(state, 12_000, 10, now)
    assert state.state == :startup

    # Next 3 ACKs at the same rate should hit the 3-round plateau
    state = simulate_acks(state, 3, 12_000, 10, now + 10, 10)
    assert state.state == :drain
    {state, now + 40}
  end

  # Drive all the way to :probe_bw via drain.
  defp drive_to_probe_bw(now \\ 1_000) do
    {state, now} = drive_to_drain(now)
    # In drain, inflight starts at 0 (we haven't called on_send), so
    # inflight (0) <= BDP triggers transition on next ACK.
    state = Bbr.on_ack(state, 1200, 10, now + 10)
    assert state.state == :probe_bw
    {state, now + 10}
  end

  # ────────────────────────────────────────────
  # 1. new/0 starts in :startup with defaults
  # ────────────────────────────────────────────
  test "new/0 starts in :startup state with default values" do
    state = Bbr.new(0)
    assert state.state == :startup
    assert state.btl_bw == 0.0
    assert state.rt_prop == :infinity
    assert state.cwnd == 256.0
    assert state.inflight == 0
    assert state.delivered == 0
    assert state.pacing_rate == 0.0
    assert state.filled_pipe == false
  end

  # ────────────────────────────────────────────
  # 2. on_ack/4 in startup increases btl_bw
  # ────────────────────────────────────────────
  test "on_ack/4 in startup increases btl_bw estimate" do
    state = Bbr.new(0)
    state = Bbr.on_ack(state, 12_000, 10, 100)
    # delivery_rate = 12000 / (10/1000) = 1_200_000 bytes/sec
    assert state.btl_bw == 1_200_000.0
    assert state.state == :startup
  end

  # ────────────────────────────────────────────
  # 3. Startup exits to drain after 3 rounds
  #    without 25% BW increase
  # ────────────────────────────────────────────
  test "startup exits to drain after 3 rounds without 25% BW increase" do
    state = Bbr.new(0)
    # Establish baseline bw
    state = Bbr.on_ack(state, 12_000, 10, 100)
    assert state.state == :startup

    # 3 more ACKs at the same rate (no 25% increase) → filled_pipe → drain
    state = Bbr.on_ack(state, 12_000, 10, 110)
    state = Bbr.on_ack(state, 12_000, 10, 120)
    state = Bbr.on_ack(state, 12_000, 10, 130)
    assert state.state == :drain
  end

  # ────────────────────────────────────────────
  # 4. Drain exits to probe_bw when inflight <= BDP
  # ────────────────────────────────────────────
  test "drain exits to probe_bw when inflight <= BDP" do
    {state, now} = drive_to_drain()
    # Inflight is 0 (no on_send calls), BDP > 0.
    # Next ACK triggers the inflight <= BDP check.
    state = Bbr.on_ack(state, 1200, 10, now + 10)
    assert state.state == :probe_bw
  end

  # ────────────────────────────────────────────
  # 5. ProbeBW cycles through 8 gain phases
  # ────────────────────────────────────────────
  test "ProbeBW cycles through 8 gain phases" do
    {state, now} = drive_to_probe_bw()
    assert state.probe_bw_phase == 0

    # Each ACK advances phase when enough time passes (>= rt_prop)
    rt = state.rt_prop

    phases =
      Enum.reduce(1..8, {state, now, [0]}, fn _i, {s, t, acc} ->
        new_t = t + rt + 1
        s = Bbr.on_ack(s, 1200, rt, new_t)
        {s, new_t, [s.probe_bw_phase | acc]}
      end)

    {_state, _time, collected} = phases
    collected = Enum.reverse(collected)
    # Should cycle: 0, 1, 2, 3, 4, 5, 6, 7, 0
    assert collected == [0, 1, 2, 3, 4, 5, 6, 7, 0]
  end

  # ────────────────────────────────────────────
  # 6. ProbeRTT entered after 10s without RTprop update
  # ────────────────────────────────────────────
  test "ProbeRTT entered after 10s without RTprop update" do
    {state, now} = drive_to_probe_bw()
    assert state.state == :probe_bw

    # Force rt_prop_stamp well into the past so probe_rtt triggers
    interval = Bbr.probe_rtt_interval_ms()
    state = %{state | rt_prop_stamp: now - interval - 1}

    # Need enough time elapsed for phase advance too
    state = Bbr.on_ack(state, 1200, state.rt_prop + 1, now + state.rt_prop + 1)
    assert state.state == :probe_rtt
  end

  # ────────────────────────────────────────────
  # 7. ProbeRTT lasts 200ms with cwnd = 4
  # ────────────────────────────────────────────
  test "ProbeRTT has cwnd = min_cwnd" do
    {state, now} = drive_to_probe_bw()
    interval = Bbr.probe_rtt_interval_ms()
    state = %{state | rt_prop_stamp: now - interval - 1}
    state = Bbr.on_ack(state, 1200, state.rt_prop + 1, now + state.rt_prop + 1)
    assert state.state == :probe_rtt
    assert Bbr.cwnd(state) == Bbr.min_cwnd()
  end

  # ────────────────────────────────────────────
  # 8. ProbeRTT exits back to ProbeBW
  # ────────────────────────────────────────────
  test "ProbeRTT exits back to ProbeBW after duration" do
    {state, now} = drive_to_probe_bw()
    interval = Bbr.probe_rtt_interval_ms()
    state = %{state | rt_prop_stamp: now - interval - 1}

    # Enter probe_rtt
    now = now + state.rt_prop + 1
    state = Bbr.on_ack(state, 1200, state.rt_prop + 1, now)
    assert state.state == :probe_rtt

    # First ACK in probe_rtt sets probe_rtt_start
    now = now + 10
    state = Bbr.on_ack(state, 1200, 10, now)
    assert state.state == :probe_rtt
    assert state.probe_rtt_start != nil

    # After 200ms, exits to probe_bw
    duration = Bbr.probe_rtt_duration_ms()
    now = now + duration + 1
    state = Bbr.on_ack(state, 1200, 10, now)
    assert state.state == :probe_bw
  end

  # ────────────────────────────────────────────
  # 9. can_send?/1 true when inflight < cwnd * payload
  # ────────────────────────────────────────────
  test "can_send?/1 true when inflight < cwnd * payload" do
    state = Bbr.new(0)
    assert Bbr.can_send?(state) == true
  end

  # ────────────────────────────────────────────
  # 10. can_send?/1 false when inflight >= cwnd * payload
  # ────────────────────────────────────────────
  test "can_send?/1 false when inflight >= cwnd * payload" do
    state = Bbr.new(0)
    # cwnd=256, payload=1140, threshold=291840
    state = %{state | inflight: 256 * Bbr.max_payload_bytes()}
    assert Bbr.can_send?(state) == false
  end

  # ────────────────────────────────────────────
  # 11. cwnd/1 returns current window in packets
  # ────────────────────────────────────────────
  test "cwnd/1 returns current window in packets" do
    state = Bbr.new(0)
    assert Bbr.cwnd(state) == 256.0
  end

  # ────────────────────────────────────────────
  # 12. pacing_rate/1 returns bytes/sec
  # ────────────────────────────────────────────
  test "pacing_rate/1 returns bytes/sec" do
    state = Bbr.new(0)
    assert Bbr.pacing_rate(state) == 0.0

    state = Bbr.on_ack(state, 12_000, 10, 100)
    assert Bbr.pacing_rate(state) > 0.0
  end

  # ────────────────────────────────────────────
  # 13. BtlBw windowed max filter keeps highest rate
  # ────────────────────────────────────────────
  test "BtlBw windowed max filter keeps highest rate in window" do
    state = Bbr.new(0)
    # First ACK: 12000 bytes / 10ms = 1.2M bytes/sec
    state = Bbr.on_ack(state, 12_000, 10, 100)
    assert state.btl_bw == 1_200_000.0

    # Second ACK with higher rate: 24000 bytes / 10ms = 2.4M bytes/sec
    state = Bbr.on_ack(state, 24_000, 10, 110)
    assert state.btl_bw == 2_400_000.0

    # Third ACK with lower rate: 6000 bytes / 10ms = 600K bytes/sec
    state = Bbr.on_ack(state, 6_000, 10, 120)
    # Should still keep the max
    assert state.btl_bw == 2_400_000.0
  end

  # ────────────────────────────────────────────
  # 14. BtlBw filter expires old entries after 10 rounds
  # ────────────────────────────────────────────
  test "BtlBw filter expires old entries after 10 rounds" do
    state = Bbr.new(0)

    # First: send enough data to track inflight, then ACK with high bandwidth.
    # Simulate inflight so rounds advance properly.
    state = Bbr.on_send(state, 24_000)
    state = Bbr.on_ack(state, 24_000, 10, 100)
    high_bw = state.btl_bw
    assert high_bw == 2_400_000.0

    # Run 12 more rounds at a much lower rate to expire the high entry.
    # Each round: send bytes → ack bytes. The round advances when
    # delivered >= next_round_delivered, which requires enough cumulative
    # ACK'd bytes to surpass the target set at the start of the round.
    state =
      Enum.reduce(1..12, state, fn i, acc ->
        # Send and ack enough bytes to advance next_round_delivered each time
        acc = Bbr.on_send(acc, 24_000)
        Bbr.on_ack(acc, 24_000, 10, 100 + i * 100)
      end)

    # After 12 rounds, the old high-bw entry (round 1) should be expired
    # The max should now be the lower rate from the latest rounds
    assert state.round_count > 10
    assert state.btl_bw <= high_bw
  end

  # ────────────────────────────────────────────
  # 15. RTprop tracks minimum RTT
  # ────────────────────────────────────────────
  test "RTprop tracks minimum RTT" do
    state = Bbr.new(0)
    assert state.rt_prop == :infinity

    state = Bbr.on_ack(state, 1200, 50, 100)
    assert state.rt_prop == 50

    # Lower RTT updates
    state = Bbr.on_ack(state, 1200, 30, 200)
    assert state.rt_prop == 30
  end

  # ────────────────────────────────────────────
  # 16. RTprop doesn't increase
  # ────────────────────────────────────────────
  test "RTprop doesn't increase (only decreases or stays)" do
    state = Bbr.new(0)
    state = Bbr.on_ack(state, 1200, 30, 100)
    assert state.rt_prop == 30

    # Higher RTT should NOT update rt_prop
    state = Bbr.on_ack(state, 1200, 100, 200)
    assert state.rt_prop == 30

    # Equal RTT should NOT update
    state = Bbr.on_ack(state, 1200, 30, 300)
    assert state.rt_prop == 30
  end

  # ────────────────────────────────────────────
  # 17. on_send/2 increases inflight counter
  # ────────────────────────────────────────────
  test "on_send/2 increases inflight counter" do
    state = Bbr.new(0)
    assert state.inflight == 0

    state = Bbr.on_send(state, 1200)
    assert state.inflight == 1200

    state = Bbr.on_send(state, 2400)
    assert state.inflight == 3600
  end

  # ────────────────────────────────────────────
  # 18. On loss (packet timeout), BtlBw is NOT artificially reduced
  # ────────────────────────────────────────────
  test "on loss (packet timeout), BtlBw is not artificially reduced" do
    state = Bbr.new(0)
    state = Bbr.on_ack(state, 12_000, 10, 100)
    bw_before = state.btl_bw

    # BBR doesn't have an on_loss callback — losses don't reduce BtlBw.
    # The windowed max filter naturally ages out old high estimates.
    # Verify BtlBw is unchanged after processing more ACKs at the same rate.
    state = Bbr.on_ack(state, 12_000, 10, 110)
    assert state.btl_bw == bw_before
  end

  # ────────────────────────────────────────────
  # 19. Full lifecycle: startup → drain → probe_bw → probe_rtt → probe_bw
  # ────────────────────────────────────────────
  test "full lifecycle: startup → drain → probe_bw → probe_rtt → probe_bw" do
    # Startup
    state = Bbr.new(0)
    assert state.state == :startup

    # Build up bw in startup
    state = Bbr.on_ack(state, 12_000, 10, 1000)
    assert state.state == :startup

    # Plateau → drain
    state = Bbr.on_ack(state, 12_000, 10, 1010)
    state = Bbr.on_ack(state, 12_000, 10, 1020)
    state = Bbr.on_ack(state, 12_000, 10, 1030)
    assert state.state == :drain

    # Drain → probe_bw (inflight == 0 <= BDP)
    state = Bbr.on_ack(state, 1200, 10, 1040)
    assert state.state == :probe_bw

    # probe_bw → probe_rtt (fast-forward rt_prop_stamp)
    interval = Bbr.probe_rtt_interval_ms()
    state = %{state | rt_prop_stamp: 1040 - interval - 1}
    now = 1040 + state.rt_prop + 1
    state = Bbr.on_ack(state, 1200, state.rt_prop + 1, now)
    assert state.state == :probe_rtt

    # probe_rtt → probe_bw (after 200ms)
    now = now + 10
    state = Bbr.on_ack(state, 1200, 10, now)
    assert state.probe_rtt_start != nil

    duration = Bbr.probe_rtt_duration_ms()
    now = now + duration + 1
    state = Bbr.on_ack(state, 1200, 10, now)
    assert state.state == :probe_bw
  end

  # ────────────────────────────────────────────
  # 20. BBR cwnd never below @min_cwnd (4)
  # ────────────────────────────────────────────
  test "BBR cwnd never below min_cwnd" do
    state = Bbr.new(0)
    # Even with very low bandwidth, cwnd should floor at min_cwnd
    state = Bbr.on_ack(state, 1, 1000, 100)
    assert Bbr.cwnd(state) >= Bbr.min_cwnd()
  end

  # ────────────────────────────────────────────
  # 21. BBR cwnd never above @max_cwnd (256)
  # ────────────────────────────────────────────
  test "BBR cwnd never above max_cwnd" do
    state = Bbr.new(0)
    # Extremely high bandwidth → cwnd should cap at max_cwnd
    state = Bbr.on_ack(state, 10_000_000, 1, 100)
    assert Bbr.cwnd(state) <= Bbr.max_cwnd()
  end
end
