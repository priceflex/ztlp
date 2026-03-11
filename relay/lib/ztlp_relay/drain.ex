defmodule ZtlpRelay.Drain do
  @moduledoc """
  Manages graceful relay shutdown / upgrade.

  ## Drain Lifecycle

  1. **Normal** — accepting new sessions, forwarding traffic
  2. **Draining** — rejecting new sessions, existing sessions continue
  3. **Drained** — all sessions closed (or timeout hit), safe to stop

  ## Triggering Drain

  - `ZtlpRelay.Drain.start_drain/1` — programmatic
  - `SIGUSR1` signal — from systemd ExecReload
  - Admin API: `POST /admin/drain` on the metrics HTTP server

  ## Mesh Integration

  When drain starts in mesh mode:
  1. Broadcasts DRAIN message to mesh peers
  2. Peers stop routing new sessions to this relay
  3. Existing forwarded sessions continue until natural close
  4. On cancel, broadcasts DRAIN_CANCEL to restore routing

  ## Hot-Path Performance

  The `draining?/0` check uses `:persistent_term` for zero-cost reads
  in the UDP listener hot path. No GenServer call required.
  """

  use GenServer

  require Logger

  @persistent_key {__MODULE__, :draining}
  @default_timeout_ms 300_000

  # ── Types ──────────────────────────────────────────────────────────

  @type state :: :normal | :draining | :drained
  @type status :: {state(), map()}

  # ── Client API ─────────────────────────────────────────────────────

  @doc "Start the Drain manager."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Begin draining. New sessions will be rejected.
  Existing sessions continue until they close or the timeout expires.

  Options:
  - `timeout_ms` — max time to wait for sessions (default: 300_000 = 5min)
  """
  @spec start_drain(keyword()) :: :ok | {:error, :already_draining}
  def start_drain(opts \\ []) do
    GenServer.call(__MODULE__, {:start_drain, opts})
  end

  @doc "Cancel an in-progress drain, returning to normal operation."
  @spec cancel_drain() :: :ok | {:error, :not_draining}
  def cancel_drain do
    GenServer.call(__MODULE__, :cancel_drain)
  end

  @doc "Get drain status."
  @spec status() :: status()
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Fast check for use in the UDP listener hot path.
  Uses `:persistent_term` — effectively free.
  """
  @spec draining?() :: boolean()
  def draining? do
    :persistent_term.get(@persistent_key, false)
  end

  @doc "Notify the drain manager that a session closed."
  @spec session_closed() :: :ok
  def session_closed do
    # Only send if draining (avoid GenServer overhead in normal operation)
    if draining?() do
      GenServer.cast(__MODULE__, :session_closed)
    end
    :ok
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :persistent_term.put(@persistent_key, false)

    {:ok, %{
      state: :normal,
      drain_started_at: nil,
      timeout_at: nil,
      timeout_ref: nil
    }}
  end

  @impl true
  def handle_call({:start_drain, opts}, _from, %{state: :normal} = state) do
    timeout_ms = Keyword.get(opts, :timeout_ms, @default_timeout_ms)
    now = System.system_time(:millisecond)

    # Set draining flag (persistent_term for hot-path reads)
    :persistent_term.put(@persistent_key, true)

    # Schedule drain timeout
    timeout_ref = Process.send_after(self(), :drain_timeout, timeout_ms)

    Logger.info("[drain] Drain mode started, timeout in #{div(timeout_ms, 1000)}s")

    # Broadcast to mesh if enabled
    broadcast_drain(timeout_ms)

    # Check if already drained (no active sessions)
    new_state = %{state |
      state: :draining,
      drain_started_at: now,
      timeout_at: now + timeout_ms,
      timeout_ref: timeout_ref
    }

    new_state = maybe_complete_drain(new_state)

    {:reply, :ok, new_state}
  end

  def handle_call({:start_drain, _opts}, _from, state) do
    {:reply, {:error, :already_draining}, state}
  end

  def handle_call(:cancel_drain, _from, %{state: s} = state) when s in [:draining, :drained] do
    Logger.info("[drain] Drain cancelled, returning to normal")

    :persistent_term.put(@persistent_key, false)

    if state.timeout_ref, do: Process.cancel_timer(state.timeout_ref)

    broadcast_drain_cancel()

    {:reply, :ok, %{state |
      state: :normal,
      drain_started_at: nil,
      timeout_at: nil,
      timeout_ref: nil
    }}
  end

  def handle_call(:cancel_drain, _from, state) do
    {:reply, {:error, :not_draining}, state}
  end

  def handle_call(:status, _from, state) do
    sessions = active_session_count()
    status = {state.state, %{
      active_sessions: sessions,
      drain_started_at: state.drain_started_at,
      timeout_at: state.timeout_at
    }}
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:session_closed, %{state: :draining} = state) do
    {:noreply, maybe_complete_drain(state)}
  end

  def handle_cast(:session_closed, state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(:drain_timeout, %{state: :draining} = state) do
    remaining = active_session_count()
    Logger.warn("[drain] Drain timeout reached, #{remaining} sessions still active — force closing")

    :persistent_term.put(@persistent_key, false)

    {:noreply, %{state |
      state: :drained,
      timeout_ref: nil
    }}
  end

  def handle_info(:drain_timeout, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, _state) do
    :persistent_term.put(@persistent_key, false)
    :ok
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp maybe_complete_drain(%{state: :draining} = state) do
    if active_session_count() == 0 do
      Logger.info("[drain] All sessions closed, drain complete")
      :persistent_term.put(@persistent_key, false)
      if state.timeout_ref, do: Process.cancel_timer(state.timeout_ref)

      %{state |
        state: :drained,
        timeout_ref: nil
      }
    else
      state
    end
  end

  defp active_session_count do
    case :ets.info(:ztlp_sessions, :size) do
      :undefined -> 0
      n when is_integer(n) -> n
    end
  rescue
    _ -> 0
  catch
    _, _ -> 0
  end

  defp broadcast_drain(_timeout_ms) do
    if ZtlpRelay.Config.mesh_enabled?() do
      # MeshManager handles broadcasting to peers
      try do
        ZtlpRelay.MeshManager.broadcast_drain()
      rescue
        _ -> :ok
      catch
        _, _ -> :ok
      end
    end
  end

  defp broadcast_drain_cancel do
    if ZtlpRelay.Config.mesh_enabled?() do
      try do
        ZtlpRelay.MeshManager.broadcast_drain_cancel()
      rescue
        _ -> :ok
      catch
        _, _ -> :ok
      end
    end
  end
end
