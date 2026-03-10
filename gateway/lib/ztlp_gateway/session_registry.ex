defmodule ZtlpGateway.SessionRegistry do
  @moduledoc """
  ETS-based session registry for the ZTLP Gateway.

  Maps SessionID (16 bytes) → Session pid. Provides O(1) lookup
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
  """
  @spec register(binary(), pid()) :: :ok | {:error, :already_registered}
  def register(session_id, pid) when byte_size(session_id) == 16 do
    GenServer.call(__MODULE__, {:register, session_id, pid})
  end

  @doc """
  Look up a session by its SessionID.

  Returns `{:ok, pid}` if found, `:error` if not registered.
  This is called on every incoming packet — must be fast.
  """
  @spec lookup(binary()) :: {:ok, pid()} | :error
  def lookup(session_id) when byte_size(session_id) == 16 do
    case :ets.lookup(@table, session_id) do
      [{^session_id, pid}] -> {:ok, pid}
      [] -> :error
    end
  end

  @doc """
  Unregister a session (called during clean shutdown).
  """
  @spec unregister(binary()) :: :ok
  def unregister(session_id) when byte_size(session_id) == 16 do
    :ets.delete(@table, session_id)
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
    :ets.new(@table, [:named_table, :set, :public,
                       read_concurrency: true])
    {:ok, %{monitors: %{}}}
  end

  @impl true
  def handle_call({:register, session_id, pid}, _from, state) do
    case :ets.lookup(@table, session_id) do
      [{^session_id, _existing}] ->
        {:reply, {:error, :already_registered}, state}

      [] ->
        :ets.insert(@table, {session_id, pid})
        ref = Process.monitor(pid)
        monitors = Map.put(state.monitors, ref, session_id)
        {:reply, :ok, %{state | monitors: monitors}}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, monitors} ->
        {:noreply, %{state | monitors: monitors}}

      {session_id, monitors} ->
        :ets.delete(@table, session_id)
        {:noreply, %{state | monitors: monitors}}
    end
  end
end
