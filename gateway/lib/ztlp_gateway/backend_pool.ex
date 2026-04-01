defmodule ZtlpGateway.BackendPool do
  @moduledoc """
  Connection pool for backend TCP connections.

  Maintains a pool of idle TCP connections per `{host, port}` backend.
  When a new mux stream needs a backend connection, it checks the pool
  first. When a stream closes, the connection is returned to the pool
  if still alive.

  ## How it works

  Idle sockets are stored in an ETS table with `{:active, false}` so no
  messages are delivered while pooled. On checkout, a `BackendPool.Conn`
  process wraps the socket (or a new connection is opened), and the pid
  is returned to the caller.

  On checkin, the caller passes the Conn pid. The pool extracts the raw
  socket, parks it idle, and stops the Conn process.

  ## Configuration

  - `ZTLP_GATEWAY_POOL_SIZE`: max idle connections per backend (default 8)
  - `ZTLP_GATEWAY_POOL_IDLE_TIMEOUT`: idle connection timeout in ms (default 60000)
  """

  use GenServer

  require Logger

  @sweep_interval_ms 30_000

  # ETS table name
  @table :ztlp_gateway_backend_pool

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the BackendPool GenServer."
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Check out a backend connection for the given `{host, port}`.

  Returns `{:ok, pid}` where `pid` is a `BackendPool.Conn` process that
  forwards data between the session and the backend. Returns
  `{:error, reason}` if the pool is empty and a new connection fails.

  The returned pid supports `Backend.send_data/2` and `Backend.close/1`
  compatible APIs (GenServer.call `{:send, data}` and GenServer.cast `:close`).

  ## Parameters
  - `host` — backend IP tuple, e.g. `{127, 0, 0, 1}`
  - `port` — backend TCP port
  - `owner` — pid to receive `{:backend_data, ...}` messages
  - `stream_id` — optional mux stream identifier
  - `timeout` — connection timeout in ms (default 5000)
  """
  @spec checkout(tuple(), non_neg_integer(), pid(), non_neg_integer() | nil, non_neg_integer()) ::
          {:ok, pid()} | {:error, term()}
  def checkout(host, port, owner, stream_id \\ nil, timeout \\ 5_000) do
    GenServer.call(__MODULE__, {:checkout, host, port, owner, stream_id, timeout}, timeout + 1_000)
  end

  @doc """
  Return a connection to the pool.

  Extracts the raw TCP socket from the `BackendPool.Conn` process, parks
  it idle in the pool, and stops the Conn process. If the socket is dead
  or the pool is full, the socket is closed.
  """
  @spec checkin(pid()) :: :ok
  def checkin(pid) do
    GenServer.cast(__MODULE__, {:checkin, pid})
  end

  @doc """
  Close a pooled connection permanently (do not return to pool).
  """
  @spec close(pid()) :: :ok
  def close(pid) do
    if Process.alive?(pid) do
      ZtlpGateway.BackendPool.Conn.stop(pid)
    end
  end

  @doc """
  Pool stats: idle/active counts, pool hits/misses.
  """
  @spec status() :: map()
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Return the number of idle connections for a given backend.
  Mainly useful for testing.
  """
  @spec idle_count(tuple(), non_neg_integer()) :: non_neg_integer()
  def idle_count(host, port) do
    GenServer.call(__MODULE__, {:idle_count, host, port})
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS table for idle connections
    # Schema: {{host, port}, socket, checked_in_at_mono}
    table = :ets.new(@table, [:bag, :named_table, :private])

    state = %{
      table: table,
      # %{monitor_ref => {pid, {host, port}}} — track active Conn processes
      active_monitors: %{},
      # Metrics
      pool_hits: 0,
      pool_misses: 0,
      total_checkouts: 0,
      total_checkins: 0
    }

    # Schedule periodic sweep
    Process.send_after(self(), :sweep_idle, @sweep_interval_ms)

    {:ok, state}
  end

  @impl true
  def handle_call({:checkout, host, port, owner, stream_id, timeout}, _from, state) do
    key = {host, port}

    case take_healthy_connection(key) do
      {:ok, socket} ->
        # Pool hit — reuse idle socket
        case start_conn(socket, owner, stream_id, key) do
          {:ok, pid} ->
            ref = Process.monitor(pid)
            active = Map.put(state.active_monitors, ref, {pid, key})
            state = %{state |
              active_monitors: active,
              pool_hits: state.pool_hits + 1,
              total_checkouts: state.total_checkouts + 1
            }
            {:reply, {:ok, pid}, state}

          {:error, _reason} ->
            # Conn process failed to start — socket might be bad, close it
            :gen_tcp.close(socket)
            # Fall through to create a new connection
            checkout_new(host, port, owner, stream_id, timeout, state)
        end

      :empty ->
        # Pool miss — create new connection
        checkout_new(host, port, owner, stream_id, timeout, state)
    end
  end

  def handle_call({:idle_count, host, port}, _from, state) do
    count = length(:ets.lookup(@table, {host, port}))
    {:reply, count, state}
  end

  def handle_call(:status, _from, state) do
    # Count idle connections across all backends
    all_idle = :ets.tab2list(@table)
    idle_by_backend =
      all_idle
      |> Enum.group_by(fn {key, _socket, _ts} -> key end)
      |> Enum.map(fn {key, entries} -> {key, length(entries)} end)
      |> Map.new()

    total_idle = length(all_idle)
    total_active = map_size(state.active_monitors)

    status = %{
      total_connections: total_idle + total_active,
      idle: total_idle,
      active: total_active,
      idle_by_backend: idle_by_backend,
      pool_hits: state.pool_hits,
      pool_misses: state.pool_misses,
      total_checkouts: state.total_checkouts,
      total_checkins: state.total_checkins
    }

    {:reply, status, state}
  end

  @impl true
  def handle_cast({:checkin, pid}, state) do
    if Process.alive?(pid) do
      # Extract socket from the Conn process and return to pool.
      # The Conn process transfers socket ownership to us (pool GenServer).
      case ZtlpGateway.BackendPool.Conn.detach(pid, self()) do
        {:ok, socket, key} ->
          return_socket_to_pool(socket, key, state)

        {:error, _reason} ->
          {:noreply, state}
      end
    else
      {:noreply, state}
    end
  end

  def handle_cast({:close_idle, host, port}, state) do
    key = {host, port}
    entries = :ets.lookup(@table, key)

    Enum.each(entries, fn {_key, socket, _ts} ->
      :gen_tcp.close(socket)
    end)

    :ets.delete(@table, key)
    Logger.debug("[BackendPool] Closed #{length(entries)} idle connections for #{inspect(key)}")
    {:noreply, state}
  end

  # Conn process died — remove from active monitors
  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    active = Map.delete(state.active_monitors, ref)
    {:noreply, %{state | active_monitors: active}}
  end

  # Periodic sweep to close idle connections past the timeout
  def handle_info(:sweep_idle, state) do
    timeout = ZtlpGateway.Config.pool_idle_timeout()
    now = System.monotonic_time(:millisecond)
    cutoff = now - timeout

    all_entries = :ets.tab2list(@table)
    expired =
      Enum.filter(all_entries, fn {_key, _socket, checked_in_at} ->
        checked_in_at < cutoff
      end)

    Enum.each(expired, fn {_key, socket, _ts} = entry ->
      :gen_tcp.close(socket)
      :ets.delete_object(@table, entry)
    end)

    if length(expired) > 0 do
      Logger.debug("[BackendPool] Sweep: closed #{length(expired)} idle connections")
    end

    # Reschedule
    Process.send_after(self(), :sweep_idle, @sweep_interval_ms)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  # Start a Conn process wrapping a socket.
  # The BackendPool GenServer owns the socket, so it must transfer ownership.
  defp start_conn(socket, owner, stream_id, key) do
    case ZtlpGateway.BackendPool.Conn.start_link(owner, stream_id, key) do
      {:ok, pid} ->
        case :gen_tcp.controlling_process(socket, pid) do
          :ok ->
            ZtlpGateway.BackendPool.Conn.activate(pid, socket)
            {:ok, pid}

          {:error, reason} ->
            GenServer.stop(pid, :normal)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp checkout_new(host, port, owner, stream_id, timeout, state) do
    # Open a new TCP connection (the pool GenServer owns the socket initially)
    case :gen_tcp.connect(host, port, [:binary, active: false, packet: :raw], timeout) do
      {:ok, socket} ->
        key = {host, port}
        case start_conn(socket, owner, stream_id, key) do
          {:ok, pid} ->
            ref = Process.monitor(pid)
            active = Map.put(state.active_monitors, ref, {pid, key})
            state = %{state |
              active_monitors: active,
              pool_misses: state.pool_misses + 1,
              total_checkouts: state.total_checkouts + 1
            }
            {:reply, {:ok, pid}, state}

          {:error, reason} ->
            :gen_tcp.close(socket)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        state = %{state | pool_misses: state.pool_misses + 1}
        {:reply, {:error, reason}, state}
    end
  end

  defp return_socket_to_pool(socket, {_host, _port} = key, state) do
    # Verify socket is still alive
    case :inet.peername(socket) do
      {:ok, _} ->
        pool_size = ZtlpGateway.Config.pool_size()
        current_count = length(:ets.lookup(@table, key))

        if current_count < pool_size do
          now = System.monotonic_time(:millisecond)
          :ets.insert(@table, {key, socket, now})
          Logger.debug("[BackendPool] Checked in socket for #{inspect(key)}, pool size: #{current_count + 1}")
        else
          # Pool full — close the socket
          :gen_tcp.close(socket)
          Logger.debug("[BackendPool] Pool full for #{inspect(key)} (#{current_count}/#{pool_size}), closed socket")
        end

      {:error, _} ->
        # Socket is dead, just close it
        :gen_tcp.close(socket)
    end

    {:noreply, %{state | total_checkins: state.total_checkins + 1}}
  end

  # Try to find a healthy connection from the pool for the given key.
  # Performs health check: try a zero-byte recv — if the peer has closed,
  # we'll get {:error, :closed}. Discard stale connections and try next.
  defp take_healthy_connection(key) do
    case :ets.lookup(@table, key) do
      [] ->
        :empty

      entries ->
        # Sort by checked_in_at descending (prefer most recently used — warm)
        sorted = Enum.sort_by(entries, fn {_k, _s, ts} -> ts end, :desc)
        find_healthy(sorted)
    end
  end

  defp find_healthy([]), do: :empty

  defp find_healthy([{_key, socket, _ts} = entry | rest]) do
    # Remove this entry from ETS first
    :ets.delete_object(@table, entry)

    # Health check: try a non-blocking recv to detect closed connections.
    # For a healthy idle socket, recv returns {:error, :timeout} (nothing to read).
    # For a closed socket, it returns {:error, :closed} or {:error, :einval}.
    case :gen_tcp.recv(socket, 0, 0) do
      {:error, :timeout} ->
        # Socket is healthy (nothing to read, which is expected for idle)
        {:ok, socket}

      {:ok, _data} ->
        # Unexpected data on idle socket — backend sent something.
        # Close and try next.
        :gen_tcp.close(socket)
        find_healthy(rest)

      {:error, _reason} ->
        # Socket is dead — close and try next
        :gen_tcp.close(socket)
        find_healthy(rest)
    end
  end
end

defmodule ZtlpGateway.BackendPool.Conn do
  @moduledoc """
  Lightweight connection wrapper for pooled backend TCP sockets.

  Similar to `ZtlpGateway.Backend` but designed for pool integration:
  - Supports `detach/1` to extract the raw socket without closing it
  - Tracks the backend `{host, port}` key for pool return
  - Compatible with `Backend.send_data/2` and `Backend.close/1` APIs
    (GenServer.call `{:send, data}` and GenServer.cast `:close`)

  ## Lifecycle

  1. Pool starts Conn with `start_link(owner, stream_id, key)`
  2. Pool transfers socket ownership and calls `activate(pid, socket)`
  3. Conn sets `{:active, true}` and begins forwarding data
  4. On checkin, pool calls `detach(pid)` to reclaim socket
  5. On close, Conn closes the socket and stops
  """

  use GenServer

  require Logger

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc """
  Start a Conn process. The socket will be provided via `activate/2`
  after the pool transfers ownership.
  """
  @spec start_link(pid(), non_neg_integer() | nil, {tuple(), non_neg_integer()}) :: GenServer.on_start()
  def start_link(owner, stream_id, backend_key) do
    GenServer.start_link(__MODULE__, {owner, stream_id, backend_key})
  end

  @doc """
  Provide the TCP socket to this Conn process. Called by the pool after
  transferring socket ownership via `:gen_tcp.controlling_process/2`.
  """
  @spec activate(pid(), :gen_tcp.socket()) :: :ok
  def activate(pid, socket) do
    GenServer.cast(pid, {:activate, socket})
  end

  @doc """
  Extract the raw TCP socket and stop this process without closing
  the socket. Transfers socket ownership to `new_owner` (must be called
  while Conn is alive). Returns `{:ok, socket, backend_key}` or `{:error, reason}`.

  The socket is returned with `{:active, false}`.
  """
  @spec detach(pid(), pid()) :: {:ok, :gen_tcp.socket(), {tuple(), non_neg_integer()}} | {:error, term()}
  def detach(pid, new_owner) do
    GenServer.call(pid, {:detach, new_owner}, 5_000)
  catch
    :exit, _ -> {:error, :noproc}
  end

  @doc "Stop the Conn process and close the socket."
  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.cast(pid, :close)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init({owner, stream_id, backend_key}) do
    Process.monitor(owner)
    {:ok, %{socket: nil, owner: owner, stream_id: stream_id, backend_key: backend_key, paused: false}}
  end

  @impl true
  def handle_cast({:activate, socket}, state) do
    :inet.setopts(socket, [{:active, :once}])
    {:noreply, %{state | socket: socket, paused: false}}
  end

  # Backpressure: Session tells us to pause/resume reading
  def handle_cast(:pause_read, state) do
    {:noreply, %{state | paused: true}}
  end

  def handle_cast(:resume_read, %{socket: socket, paused: _} = state) when socket != nil do
    :inet.setopts(socket, [{:active, :once}])
    {:noreply, %{state | paused: false}}
  end

  def handle_cast(:resume_read, state) do
    {:noreply, %{state | paused: false}}
  end

  def handle_cast(:close, %{socket: socket} = state) when socket != nil do
    :gen_tcp.close(socket)
    {:stop, :normal, %{state | socket: nil}}
  end

  def handle_cast(:close, state) do
    {:stop, :normal, state}
  end

  @impl true
  def handle_call({:send, _data}, _from, %{socket: nil} = state) do
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:send, data}, _from, %{socket: socket} = state) do
    case :gen_tcp.send(socket, data) do
      :ok -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:detach, _new_owner}, _from, %{socket: nil} = state) do
    {:stop, :normal, {:error, :no_socket}, state}
  end

  def handle_call({:detach, new_owner}, _from, %{socket: socket, backend_key: key} = state) do
    # Set socket to passive and transfer ownership to the pool GenServer.
    # This must happen while Conn (the current owner) is still alive.
    :inet.setopts(socket, [{:active, false}])
    case :gen_tcp.controlling_process(socket, new_owner) do
      :ok ->
        {:stop, :normal, {:ok, socket, key}, %{state | socket: nil}}
      {:error, reason} ->
        {:stop, :normal, {:error, reason}, state}
    end
  end

  # TCP data from the backend → forward to the session owner
  # Uses active: :once for backpressure. Re-arms immediately unless paused.
  @impl true
  def handle_info({:tcp, socket, data}, %{owner: owner, stream_id: nil, paused: paused} = state) do
    send(owner, {:backend_data, data})
    unless paused, do: :inet.setopts(socket, [{:active, :once}])
    {:noreply, state}
  end

  def handle_info({:tcp, socket, data}, %{owner: owner, stream_id: stream_id, paused: paused} = state) do
    send(owner, {:backend_data, stream_id, data})
    unless paused, do: :inet.setopts(socket, [{:active, :once}])
    {:noreply, state}
  end

  # TCP connection closed by the backend
  def handle_info({:tcp_closed, _socket}, %{owner: owner, stream_id: nil} = state) do
    send(owner, :backend_closed)
    {:stop, :normal, %{state | socket: nil}}
  end

  def handle_info({:tcp_closed, _socket}, %{owner: owner, stream_id: stream_id} = state) do
    send(owner, {:backend_closed, stream_id})
    {:stop, :normal, %{state | socket: nil}}
  end

  # TCP error
  def handle_info({:tcp_error, _socket, reason}, %{owner: owner, stream_id: nil} = state) do
    Logger.error("[BackendPool.Conn] TCP error: #{inspect(reason)}")
    send(owner, {:backend_error, reason})
    {:stop, {:tcp_error, reason}, %{state | socket: nil}}
  end

  def handle_info({:tcp_error, _socket, reason}, %{owner: owner, stream_id: stream_id} = state) do
    Logger.error("[BackendPool.Conn] TCP error on stream #{stream_id}: #{inspect(reason)}")
    send(owner, {:backend_error, stream_id, reason})
    {:stop, {:tcp_error, reason}, %{state | socket: nil}}
  end

  # Owner (Session) died — close the socket and stop
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, %{socket: socket} = state) when socket != nil do
    :gen_tcp.close(socket)
    {:stop, :normal, %{state | socket: nil}}
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, state) do
    {:stop, :normal, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %{socket: socket}) when socket != nil do
    :gen_tcp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok
end
