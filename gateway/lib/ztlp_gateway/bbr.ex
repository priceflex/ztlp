defmodule ZtlpGateway.Bbr do
  @moduledoc """
  BBR-inspired congestion control for ZTLP gateway.

  Estimates bottleneck bandwidth (BtlBw) and minimum RTT (RTprop)
  to compute the optimal pacing rate and cwnd.

  Simplified BBR v1 with 4 states:
  - Startup: exponential growth to find BtlBw (gain = 2.885)
  - Drain: reduce inflight to BDP (gain = 1/2.885)
  - ProbeBW: steady state with periodic bandwidth probing
  - ProbeRTT: periodic RTT measurement (every 10s, reduce cwnd to 4 for 200ms)
  """

  @startup_gain 2.885
  @drain_gain 0.347
  @probe_bw_gains [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
  @probe_rtt_interval_ms 10_000
  @probe_rtt_duration_ms 200
  @min_cwnd 4
  @max_cwnd 256
  @max_payload_bytes 1200

  defstruct state: :startup,
            btl_bw: 0.0,
            bw_filter: [],
            bw_filter_len: 10,
            rt_prop: :infinity,
            rt_prop_stamp: 0,
            pacing_rate: 0.0,
            cwnd: 64,
            filled_pipe: false,
            full_bw: 0.0,
            full_bw_count: 0,
            probe_bw_phase: 0,
            cycle_stamp: 0,
            probe_rtt_start: nil,
            probe_rtt_done: false,
            delivered: 0,
            delivered_time: 0,
            send_elapsed: 0,
            ack_elapsed: 0,
            round_count: 0,
            next_round_delivered: 0,
            round_start: false,
            inflight: 0

  @doc "Create new BBR state."
  def new do
    now = System.monotonic_time(:millisecond)

    %__MODULE__{
      delivered_time: now,
      rt_prop_stamp: now,
      cycle_stamp: now
    }
  end

  @doc "Create new BBR state with an explicit timestamp (for testing)."
  def new(now_ms) do
    %__MODULE__{
      delivered_time: now_ms,
      rt_prop_stamp: now_ms,
      cycle_stamp: now_ms
    }
  end

  @doc "Called on each ACK. Returns updated state."
  def on_ack(state, acked_bytes, rtt_ms, now_ms) do
    state
    |> update_round(acked_bytes)
    |> update_btl_bw(acked_bytes, rtt_ms, now_ms)
    |> update_rt_prop(rtt_ms, now_ms)
    |> update_inflight(-acked_bytes)
    |> check_state_transitions(now_ms)
    |> set_pacing_rate()
    |> set_cwnd()
  end

  @doc "Called on each send. Returns updated state."
  def on_send(state, sent_bytes) do
    update_inflight(state, sent_bytes)
  end

  @doc "Release bytes from inflight without triggering bandwidth estimation (for dropped/SACK'd packets)."
  def release_bytes(state, bytes) do
    update_inflight(state, -bytes)
  end

  @doc "Get current pacing rate in bytes/sec."
  def pacing_rate(%__MODULE__{pacing_rate: rate}), do: rate

  @doc "Get current cwnd in packets."
  def cwnd(%__MODULE__{cwnd: cwnd}), do: cwnd

  @doc "Can we send? inflight < cwnd * max_payload."
  def can_send?(%__MODULE__{inflight: inflight, cwnd: cwnd}) do
    inflight < cwnd * @max_payload_bytes
  end

  @doc "Return the min_cwnd constant."
  def min_cwnd, do: @min_cwnd

  @doc "Return the max_cwnd constant."
  def max_cwnd, do: @max_cwnd

  @doc "Return the max_payload_bytes constant."
  def max_payload_bytes, do: @max_payload_bytes

  @doc "Return the probe_rtt_interval_ms constant."
  def probe_rtt_interval_ms, do: @probe_rtt_interval_ms

  @doc "Return the probe_rtt_duration_ms constant."
  def probe_rtt_duration_ms, do: @probe_rtt_duration_ms

  ## Internal

  defp update_round(state, acked_bytes) do
    delivered = state.delivered + acked_bytes
    round_start = delivered >= state.next_round_delivered

    if round_start do
      # New round detected: set the next round target to the current
      # delivery count plus estimated bytes in flight. This ensures the
      # next round lasts approximately one RTT.
      next_target = delivered + max(state.inflight, acked_bytes)
      %{state |
        delivered: delivered,
        round_start: true,
        round_count: state.round_count + 1,
        next_round_delivered: next_target
      }
    else
      %{state |
        delivered: delivered,
        round_start: false
      }
    end
  end

  defp update_btl_bw(state, acked_bytes, rtt_ms, now_ms) when rtt_ms > 0 do
    delivery_rate = acked_bytes / (rtt_ms / 1000.0)

    bw_filter =
      [{delivery_rate, state.round_count} | state.bw_filter]
      |> Enum.filter(fn {_rate, round} ->
        state.round_count - round < state.bw_filter_len
      end)
      |> Enum.sort_by(fn {rate, _} -> rate end, :desc)
      |> Enum.take(state.bw_filter_len)

    btl_bw =
      case bw_filter do
        [{max_rate, _} | _] -> max_rate
        [] -> state.btl_bw
      end

    state = check_filled_pipe(state, btl_bw)

    %{state | btl_bw: btl_bw, bw_filter: bw_filter, delivered_time: now_ms}
  end

  defp update_btl_bw(state, _acked_bytes, _rtt_ms, _now_ms), do: state

  defp update_rt_prop(state, rtt_ms, now_ms) when rtt_ms > 0 do
    if rtt_ms < state.rt_prop or state.rt_prop == :infinity do
      %{state | rt_prop: rtt_ms, rt_prop_stamp: now_ms}
    else
      state
    end
  end

  defp update_rt_prop(state, _rtt_ms, _now_ms), do: state

  defp update_inflight(state, delta) do
    %{state | inflight: max(0, state.inflight + delta)}
  end

  defp check_filled_pipe(%{state: :startup} = state, btl_bw) do
    if btl_bw >= state.full_bw * 1.25 do
      %{state | full_bw: btl_bw, full_bw_count: 0}
    else
      count = state.full_bw_count + 1

      if count >= 3 do
        %{state | filled_pipe: true, full_bw_count: count}
      else
        %{state | full_bw_count: count}
      end
    end
  end

  defp check_filled_pipe(state, _btl_bw), do: state

  defp check_state_transitions(state, now_ms) do
    case state.state do
      :startup ->
        if state.filled_pipe do
          %{state | state: :drain}
        else
          state
        end

      :drain ->
        bdp = bdp(state)

        if state.inflight <= bdp do
          %{state | state: :probe_bw, cycle_stamp: now_ms, probe_bw_phase: 0}
        else
          state
        end

      :probe_bw ->
        state = maybe_advance_probe_bw_phase(state, now_ms)
        maybe_enter_probe_rtt(state, now_ms)

      :probe_rtt ->
        cond do
          state.probe_rtt_start != nil and
              now_ms - state.probe_rtt_start >= @probe_rtt_duration_ms ->
            %{state |
              state: :probe_bw,
              probe_rtt_start: nil,
              rt_prop_stamp: now_ms,
              cycle_stamp: now_ms,
              probe_bw_phase: 0
            }

          state.probe_rtt_start == nil ->
            %{state | probe_rtt_start: now_ms}

          true ->
            state
        end
    end
  end

  defp maybe_advance_probe_bw_phase(state, now_ms) do
    rt = if state.rt_prop == :infinity, do: 100, else: state.rt_prop

    if now_ms - state.cycle_stamp >= rt do
      phase = rem(state.probe_bw_phase + 1, length(@probe_bw_gains))
      %{state | probe_bw_phase: phase, cycle_stamp: now_ms}
    else
      state
    end
  end

  defp maybe_enter_probe_rtt(state, now_ms) do
    if now_ms - state.rt_prop_stamp >= @probe_rtt_interval_ms do
      %{state | state: :probe_rtt, probe_rtt_start: nil, probe_rtt_done: false}
    else
      state
    end
  end

  defp set_pacing_rate(state) do
    gain = pacing_gain(state)
    rate = state.btl_bw * gain
    %{state | pacing_rate: rate}
  end

  defp set_cwnd(state) do
    bdp = bdp(state)
    cwnd_gain = cwnd_gain(state)
    target_cwnd = trunc(bdp * cwnd_gain / @max_payload_bytes) + 1

    cwnd =
      case state.state do
        :probe_rtt -> @min_cwnd
        _ -> min(max(target_cwnd, @min_cwnd), @max_cwnd)
      end

    %{state | cwnd: cwnd}
  end

  defp bdp(state) do
    rt = if state.rt_prop == :infinity, do: 100.0, else: state.rt_prop / 1.0
    state.btl_bw * (rt / 1000.0)
  end

  defp pacing_gain(%{state: :startup}), do: @startup_gain
  defp pacing_gain(%{state: :drain}), do: @drain_gain

  defp pacing_gain(%{state: :probe_bw, probe_bw_phase: phase}) do
    Enum.at(@probe_bw_gains, phase, 1.0)
  end

  defp pacing_gain(%{state: :probe_rtt}), do: 1.0

  defp cwnd_gain(%{state: :startup}), do: @startup_gain
  defp cwnd_gain(_), do: 2.0
end
