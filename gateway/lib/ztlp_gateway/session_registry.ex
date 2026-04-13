defmodule ZtlpGateway.SessionRegistry do
  @moduledoc """
  ETS-based session registry for the ZTLP Gateway.

  Maps SessionID (12 bytes / 96-bit) → Session pid. Provides O(1) lookup
  for the admission pipeline's Layer 2 (SessionID check).

  ## Concurrency

  The ETS table uses `read_concurrency: true` since reads vastly
  outnumber writes (every incoming packet triggers a lookup, but
  sessions are created/destroyed infrequently).

  Process monitors are used to automatically clean up sessions
  that crash or terminate unexpectedly.
  """

  use GenServer

  @table :ztlp_gateway_sessions
  @addr_table :ztlp_gateway_session_addrs

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the session registry."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a session. Maps session_id → pid.

  The registry monitors the pid so that if the session process dies,
  the entry is automatically removed.

  Accepts an optional `client_addr` ({ip, port}) to enable address-based
  lookup for session deduplication.
  """
  @spec register(binary(), pid()) :: :ok | {:error, :already_registered}
  def register(session_id, pid) when byte_size(session_id) == 12 do
    GenServer.call(__MODULE__, {:register, session_id, pid, nil})
  end

  @spec register(binary(), pid(), {tuple(), non_neg_integer()} | nil) :: :ok | {:error, :already_registered}
  def register(session_id, pid, client_addr) when byte_size(session_id) == 12 do
    GenServer.call(__MODULE__, {:register, session_id, pid, client_addr})
  end

  @doc """
  Look up a session by its SessionID.

  Returns `{:ok, pid}` if found, `:error` if not registered.
  This is called on every incoming packet — must be fast.
  """
  @spec lookup(binary()) :: {:ok, pid()} | :error
  def lookup(session_id) when byte_size(session_id) == 12 do
    case :ets.lookup(@table, session_id) do
      [{^session_id, pid}] -> {:ok, pid}
      [] -> :error
    end
  end

  @doc """
  Look up a session by client address ({ip, port}).

  Returns `{:ok, {session_id, pid}}` if found, `:error` if not.
  Used for session deduplication when a new HELLO arrives from a
  client that already has an active session.
  """
  @spec lookup_by_addr({tuple(), non_neg_integer()}) :: {:ok, {binary(), pid()}} | :error
  def lookup_by_addr(addr) do
    case :ets.lookup(@addr_table, addr) do
      [{^addr, session_id, pid}] -> {:ok, {session_id, pid}}
      [] -> :error
    end
  end

  @doc """
  Unregister a session (called during clean shutdown).

  This deletes the addr mapping only if it still points at the same pid/session pair,
  which prevents late cleanup from an old session from erasing a newer replacement
  session that already claimed the same client_addr.
  """
  @spec unregister(binary(), pid() | nil) :: :ok
  def unregister(session_id, pid \\ nil) when byte_size(session_id) == 12 do
    :ets.delete(@table, session_id)

    if pid do
      case :ets.match_object(@addr_table, {:_, session_id, pid}) do
        [{addr, ^session_id, ^pid}] -> :ets.delete(@addr_table, addr)
        _ -> :ok
      end
    else
      # Fallback for legacy callers when we do not know the owner pid.
      :ets.match_delete(@addr_table, {:_, session_id, :_})
    end

    :ok
  end

  @doc "Count of active registered sessions."
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table, :size)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@addr_table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, %{monitors: %{}}}
  end

  @impl true
  def handle_call({:register, session_id, pid, client_addr}, _from, state) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, _existing}] ->
        {:reply, {:error, :already_registered}, state}

      [] ->
        :ets.insert(@table, {session_id, pid})
        if client_addr do
          :ets.insert(@addr_table, {client_addr, session_id, pid})
        end
        ref = Process.monitor(pid)
        monitors = Map.put(state.monitors, ref, session_id)
        {:reply, :ok, %{state | monitors: monitors}}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, monitors} ->
        {:noreply, %{state | monitors: monitors}}

      {session_id, monitors} ->
        unregister(session_id, pid)
        {:noreply, %{state | monitors: monitors}}
    end
  end
end
