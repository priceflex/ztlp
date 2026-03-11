defmodule ZtlpGateway.StatsReporter do
  @moduledoc """
  Periodically logs gateway stats at info level (every 60s).
  """

  use GenServer
  require Logger

  @default_interval_ms 60_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    interval = report_interval()
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

  defp schedule_report(interval), do: Process.send_after(self(), :report, interval)

  defp report_interval do
    case System.get_env("ZTLP_GATEWAY_STATS_INTERVAL_MS") do
      nil -> Application.get_env(:ztlp_gateway, :stats_report_interval_ms, @default_interval_ms)
      ms -> String.to_integer(ms)
    end
  end

  defp report_stats do
    stats = ZtlpGateway.Stats.snapshot()
    uptime = System.monotonic_time(:second) - :persistent_term.get({__MODULE__, :start_time}, 0)

    Logger.info(
      "[stats] sessions=#{stats.active_sessions} " <>
      "bytes_in=#{stats.bytes_in} bytes_out=#{stats.bytes_out} " <>
      "handshakes_ok=#{stats.handshakes_ok} handshakes_fail=#{stats.handshakes_fail} " <>
      "policy_denials=#{stats.policy_denials} " <>
      "uptime=#{uptime}s"
    )
  end
end
