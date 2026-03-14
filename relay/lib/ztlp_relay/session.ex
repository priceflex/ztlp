defmodule ZtlpRelay.Session do
  @moduledoc """
  GenServer for an active relay session with state machine.

  Session lifecycle:
  - HALF_OPEN: only peer_a is known (waiting for peer_b's HELLO)
  - ESTABLISHED: both peers known, bidirectional forwarding active
  - CLOSED: session torn down

  Each session tracks:
  - `session_id` — 12-byte SessionID
  - `peer_a` — {ip, port} of peer A
  - `peer_b` — {ip, port} of peer B (nil when HALF_OPEN)
  - `status` — :half_open | :established | :closed
  - `created_at` — monotonic creation time
  - `packet_count` — total packets forwarded through this session
  - `last_activity` — monotonic time of last packet

  Timeout behavior:
  - HALF_OPEN sessions expire after `half_open_timeout_ms` (default 30s)
  - ESTABLISHED sessions expire after `timeout_ms` (default 5min) of inactivity

  The session monitors for inactivity timeout and unregisters itself
  from the registry on expiry or close.
  """

  use GenServer

  require Logger

  @default_half_open_timeout_ms 30_000

  @type peer_addr :: {:inet.ip_address(), :inet.port_number()} | nil
  @type session_status :: :half_open | :established | :closed

  @type state :: %{
          session_id: binary(),
          peer_a: peer_addr(),
          peer_b: peer_addr(),
          status: session_status(),
          created_at: integer(),
          packet_count: non_neg_integer(),
          last_activity: integer(),
          timeout_ms: non_neg_integer(),
          half_open_timeout_ms: non_neg_integer(),
          timer_ref: reference() | nil
        }

  # Client API

  @doc """
  Start a session GenServer.

  Options:
    - `:session_id` — required, 12-byte binary
    - `:peer_a` — required, {ip, port}
    - `:peer_b` — optional, {ip, port} (nil for half-open sessions)
    - `:timeout_ms` — optional, defaults to configured session_timeout_ms
    - `:half_open_timeout_ms` — optional, defaults to 30_000
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Notify the session that a packet was forwarded.

  Increments the packet counter and resets the inactivity timer.
  """
  @spec forward(pid()) :: :ok
  def forward(pid) do
    GenServer.cast(pid, :forward)
  end

  @doc """
  Set peer_b, transitioning from HALF_OPEN to ESTABLISHED.

  Returns :ok if successful, {:error, reason} if the session is not half-open.
  """
  @spec set_peer_b(pid(), peer_addr()) :: :ok | {:error, atom()}
  def set_peer_b(pid, peer_b) do
    GenServer.call(pid, {:set_peer_b, peer_b})
  end

  @doc """
  Close the session.
  """
  @spec close(pid()) :: :ok
  def close(pid) do
    GenServer.cast(pid, :close)
  end

  @doc """
  Get the current session state (for inspection/testing).
  """
  @spec get_state(pid()) :: state()
  def get_state(pid) do
    GenServer.call(pid, :get_state)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    session_id = Keyword.fetch!(opts, :session_id)
    peer_a = Keyword.fetch!(opts, :peer_a)
    peer_b = Keyword.get(opts, :peer_b, nil)
    timeout_ms = Keyword.get(opts, :timeout_ms, ZtlpRelay.Config.session_timeout_ms())

    half_open_timeout_ms =
      Keyword.get(opts, :half_open_timeout_ms, @default_half_open_timeout_ms)

    now = System.monotonic_time(:millisecond)

    # Determine initial status and timeout
    {status, initial_timeout} =
      if peer_b != nil and peer_b != {{0, 0, 0, 0}, 0} do
        {:established, timeout_ms}
      else
        {:half_open, half_open_timeout_ms}
      end

    timer_ref = schedule_timeout(initial_timeout)

    state = %{
      session_id: session_id,
      peer_a: peer_a,
      peer_b: if(status == :half_open, do: nil, else: peer_b),
      status: status,
      created_at: now,
      packet_count: 0,
      last_activity: now,
      timeout_ms: timeout_ms,
      half_open_timeout_ms: half_open_timeout_ms,
      timer_ref: timer_ref
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:forward, state) do
    now = System.monotonic_time(:millisecond)

    # Cancel old timer, schedule new one (only reset for established sessions)
    cancel_timer(state.timer_ref)

    timer_ref =
      case state.status do
        :established -> schedule_timeout(state.timeout_ms)
        :half_open -> schedule_timeout(state.half_open_timeout_ms)
        _ -> nil
      end

    {:noreply,
     %{state | packet_count: state.packet_count + 1, last_activity: now, timer_ref: timer_ref}}
  end

  def handle_cast(:close, state) do
    cleanup(%{state | status: :closed})
    {:stop, :normal, %{state | status: :closed}}
  end

  @impl true
  def handle_call({:set_peer_b, peer_b}, _from, %{status: :half_open} = state) do
    cancel_timer(state.timer_ref)
    timer_ref = schedule_timeout(state.timeout_ms)

    new_state = %{
      state
      | peer_b: peer_b,
        status: :established,
        timer_ref: timer_ref,
        last_activity: System.monotonic_time(:millisecond)
    }

    # Update the registry with the new peer_b
    ZtlpRelay.SessionRegistry.update_peer_b(state.session_id, peer_b)

    Logger.debug(
      "Session #{Base.encode16(state.session_id)} transitioned HALF_OPEN → ESTABLISHED"
    )

    {:reply, :ok, new_state}
  end

  def handle_call({:set_peer_b, _peer_b}, _from, state) do
    {:reply, {:error, :not_half_open}, state}
  end

  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:session_timeout, %{status: :half_open} = state) do
    Logger.debug(
      "Session #{Base.encode16(state.session_id)} half-open timeout expired"
    )

    cleanup(%{state | status: :closed})
    {:stop, :normal, %{state | status: :closed}}
  end

  def handle_info(:session_timeout, state) do
    Logger.debug("Session #{Base.encode16(state.session_id)} timed out after inactivity")
    cleanup(%{state | status: :closed})
    {:stop, :normal, %{state | status: :closed}}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    cleanup(state)
    :ok
  end

  # Internal helpers

  defp schedule_timeout(timeout_ms) do
    Process.send_after(self(), :session_timeout, timeout_ms)
  end

  defp cancel_timer(nil), do: :ok
  defp cancel_timer(ref), do: Process.cancel_timer(ref)

  defp cleanup(state) do
    ZtlpRelay.SessionRegistry.unregister_session(state.session_id)
  end
end
