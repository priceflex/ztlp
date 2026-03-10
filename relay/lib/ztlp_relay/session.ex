defmodule ZtlpRelay.Session do
  @moduledoc """
  GenServer for an active relay session.

  Each session tracks:
  - `session_id` — 12-byte SessionID
  - `peer_a` — {ip, port} of peer A
  - `peer_b` — {ip, port} of peer B
  - `created_at` — monotonic creation time
  - `packet_count` — total packets forwarded through this session
  - `last_activity` — monotonic time of last packet

  The session monitors for inactivity timeout and unregisters itself
  from the registry on expiry or close.
  """

  use GenServer

  require Logger

  @type peer_addr :: {:inet.ip_address(), :inet.port_number()}

  @type state :: %{
    session_id: binary(),
    peer_a: peer_addr(),
    peer_b: peer_addr(),
    created_at: integer(),
    packet_count: non_neg_integer(),
    last_activity: integer(),
    timeout_ms: non_neg_integer(),
    timer_ref: reference() | nil
  }

  # Client API

  @doc """
  Start a session GenServer.

  Options:
    - `:session_id` — required, 12-byte binary
    - `:peer_a` — required, {ip, port}
    - `:peer_b` — required, {ip, port}
    - `:timeout_ms` — optional, defaults to configured session_timeout_ms
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
    peer_b = Keyword.fetch!(opts, :peer_b)
    timeout_ms = Keyword.get(opts, :timeout_ms, ZtlpRelay.Config.session_timeout_ms())

    now = System.monotonic_time(:millisecond)
    timer_ref = schedule_timeout(timeout_ms)

    state = %{
      session_id: session_id,
      peer_a: peer_a,
      peer_b: peer_b,
      created_at: now,
      packet_count: 0,
      last_activity: now,
      timeout_ms: timeout_ms,
      timer_ref: timer_ref
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:forward, state) do
    now = System.monotonic_time(:millisecond)

    # Cancel old timer, schedule new one
    cancel_timer(state.timer_ref)
    timer_ref = schedule_timeout(state.timeout_ms)

    {:noreply, %{state |
      packet_count: state.packet_count + 1,
      last_activity: now,
      timer_ref: timer_ref
    }}
  end

  def handle_cast(:close, state) do
    cleanup(state)
    {:stop, :normal, state}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:session_timeout, state) do
    Logger.debug("Session #{inspect(state.session_id)} timed out after inactivity")
    cleanup(state)
    {:stop, :normal, state}
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
