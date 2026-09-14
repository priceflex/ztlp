defmodule ZtlpRelay.SignalHandler do
  @moduledoc """
  Handles POSIX signals for graceful operations.

  - `SIGUSR1` → Start drain mode (for systemd ExecReload)
  - `SIGUSR2` → Log current status to info (diagnostics)

  ## How signal delivery works (OTP 24+)

  `:os.set_signal(sig, :handle)` only tells the emulator to forward `sig`
  as an event to the `:erl_signal_server` gen_event. It does NOT deliver a
  message to any particular process. By default the only handler installed
  there is OTP's `:erl_signal_handler`, whose behaviour is:

    * `sigusr1` → `erlang:halt("Received SIGUSR1")`  (kills the node!)
    * `sigquit` → `erlang:halt()`
    * `sigterm` → `init:stop()`
    * anything else → ignored

  So this module installs its own gen_event handler
  (`ZtlpRelay.SignalHandler.EventHandler`) in place of the default one. It
  forwards `sigusr1`/`sigusr2` to this GenServer as `{:signal, sig}` and
  preserves the default `sigterm`/`sigquit` semantics so systemd stop still
  works.
  """

  use GenServer

  require Logger

  defmodule EventHandler do
    @moduledoc false
    # gen_event handler installed on :erl_signal_server. Forwards the
    # signals we own to the SignalHandler GenServer and keeps OTP's default
    # behaviour for the rest.
    @behaviour :gen_event

    @impl true
    def init(pid) when is_pid(pid), do: {:ok, pid}
    # swap_handler/3 calls init({NewArgs, TermResultOfOldHandler}).
    def init({pid, _old_handler_term}) when is_pid(pid), do: {:ok, pid}

    @impl true
    def handle_event(sig, pid) when sig in [:sigusr1, :sigusr2] do
      send(pid, {:signal, sig})
      {:ok, pid}
    end

    def handle_event(:sigterm, pid) do
      Logger.info("[signal] SIGTERM received - shutting down")
      :ok = :init.stop()
      {:ok, pid}
    end

    def handle_event(:sigquit, pid) do
      :erlang.halt()
      {:ok, pid}
    end

    def handle_event(_other, pid), do: {:ok, pid}

    @impl true
    def handle_call(_req, pid), do: {:ok, :ok, pid}

    @impl true
    def handle_info(_msg, pid), do: {:ok, pid}

    @impl true
    def terminate(_reason, _pid), do: :ok

    @impl true
    def code_change(_old, pid, _extra), do: {:ok, pid}
  end

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    install_event_handler()

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

  # Replace OTP's default erl_signal_handler (which halts on SIGUSR1) with
  # ours. If the default is not installed (minimal mode, or a previous
  # incarnation of this process already swapped it), just add ours. Any
  # stale handler from a previous incarnation is removed first so exactly
  # one EventHandler is ever installed.
  defp install_event_handler do
    server = :erl_signal_server

    if Process.whereis(server) do
      handlers = :gen_event.which_handlers(server)

      Enum.each(handlers, fn
        EventHandler -> :gen_event.delete_handler(server, EventHandler, :stale)
        _ -> :ok
      end)

      if :erl_signal_handler in handlers do
        :gen_event.swap_handler(server, {:erl_signal_handler, :swap}, {EventHandler, self()})
      else
        :gen_event.add_handler(server, EventHandler, self())
      end
    end
  rescue
    e -> Logger.warning("[signal] Could not install signal event handler: #{inspect(e)}")
  catch
    kind, reason ->
      Logger.warning("[signal] Could not install signal event handler: #{inspect({kind, reason})}")
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
