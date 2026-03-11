defmodule ZtlpRelay.StatsReporter do
  @moduledoc """
  Periodically logs a stats summary at info level.

  Runs every 60 seconds (configurable) and emits a structured
  stats_summary event with current pipeline counters, session count,
  and mesh health.

  ## Configuration

  - `:stats_report_interval_ms` — Report interval (default: 60_000ms)
  - `ZTLP_RELAY_STATS_INTERVAL_MS` — Environment variable override
  """

  use GenServer

  require Logger

  @default_interval_ms 60_000

  # ── Client API ─────────────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    interval = report_interval()
    # Store start time for uptime calculation
    :persistent_term.put({__MODULE__, :start_time}, System.monotonic_time(:second))
    schedule_report(interval)
    {:ok, %{interval: interval}}
  end

  @impl true
  def handle_info(:report, state) do
    report_stats()
    schedule_report(state.interval)
    {:noreply, state}
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp schedule_report(interval) do
    Process.send_after(self(), :report, interval)
  end

  defp report_interval do
    case System.get_env("ZTLP_RELAY_STATS_INTERVAL_MS") do
      nil -> Application.get_env(:ztlp_relay, :stats_report_interval_ms, @default_interval_ms)
      ms -> String.to_integer(ms)
    end
  end

  defp report_stats do
    stats = ZtlpRelay.Stats.get_stats()
    uptime = System.monotonic_time(:second) - :persistent_term.get({__MODULE__, :start_time}, 0)

    # Count active sessions
    sessions = case :ets.info(:ztlp_sessions, :size) do
      :undefined -> 0
      n when is_integer(n) -> n
    end

    Logger.info(
      "[stats] sessions=#{sessions} " <>
      "passed=#{stats.passed} " <>
      "dropped_l1=#{stats.layer1_drops} " <>
      "dropped_l2=#{stats.layer2_drops} " <>
      "dropped_l3=#{stats.layer3_drops} " <>
      "forwarded=#{stats.forwarded} " <>
      "uptime=#{uptime}s"
    )
  end
end
