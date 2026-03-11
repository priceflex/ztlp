defmodule ZtlpRelay.SignalHandler do
  @moduledoc """
  Handles POSIX signals for graceful operations.

  - `SIGUSR1` → Start drain mode (for systemd ExecReload)
  - `SIGUSR2` → Log current status to info (diagnostics)

  Uses `:os.set_signal/2` available in OTP 24+.
  """

  use GenServer

  require Logger

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Trap SIGUSR1 and SIGUSR2
    try do
      :os.set_signal(:sigusr1, :handle)
      :os.set_signal(:sigusr2, :handle)
      Logger.debug("[signal] Signal handler registered (SIGUSR1=drain, SIGUSR2=status)")
    rescue
      _ -> Logger.debug("[signal] Signal trapping not available on this platform")
    catch
      _, _ -> Logger.debug("[signal] Signal trapping not available on this platform")
    end

    {:ok, %{}}
  end

  @impl true
  def handle_info({:signal, :sigusr1}, state) do
    Logger.info("[signal] SIGUSR1 received — starting drain mode")

    case ZtlpRelay.Drain.start_drain() do
      :ok -> Logger.info("[signal] Drain mode activated")
      {:error, :already_draining} -> Logger.info("[signal] Already draining")
    end

    {:noreply, state}
  end

  def handle_info({:signal, :sigusr2}, state) do
    Logger.info("[signal] SIGUSR2 received — dumping status")
    log_status()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp log_status do
    stats = ZtlpRelay.Stats.get_stats()
    {drain_state, drain_info} = ZtlpRelay.Drain.status()

    Logger.info(
      "[status] drain=#{drain_state} " <>
      "sessions=#{drain_info.active_sessions} " <>
      "passed=#{stats.passed} " <>
      "dropped_l1=#{stats.layer1_drops} " <>
      "dropped_l2=#{stats.layer2_drops} " <>
      "dropped_l3=#{stats.layer3_drops}"
    )
  end
end
