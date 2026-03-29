defmodule ZtlpGateway.Backend do
  @moduledoc """
  TCP backend connection manager for the ZTLP Gateway.

  Each `Backend` process manages a TCP connection to a single backend
  service. When the Session process decrypts a ZTLP payload, it sends
  the plaintext here, and this process forwards it over TCP to the
  actual service.

  Responses from the backend are sent back to the owning Session
  process as `{:backend_data, data}` messages.

  ## Connection Lifecycle

  1. Session starts a Backend with `{host, port}`
  2. Backend opens a TCP connection (`:gen_tcp.connect/3`)
  3. Incoming data from Session → forwarded to TCP socket
  4. Incoming data from TCP socket → sent back to Session
  5. TCP close or error → Backend notifies Session and terminates

  ## Active Mode

  The TCP socket uses `{:active, true}` so data arrives as messages
  to the GenServer. This is appropriate for the prototype; production
  would use flow control with `{:active, :once}`.
  """

  use GenServer

  require Logger

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc """
  Start a backend connection.

  ## Parameters
  - `host` — IP tuple, e.g. `{127, 0, 0, 1}`
  - `port` — TCP port number
  - `owner` — pid of the Session process that will receive responses
  """
  @spec start_link({tuple(), non_neg_integer(), pid()} | {tuple(), non_neg_integer(), pid(), non_neg_integer()}) :: GenServer.on_start()
  def start_link({host, port, owner}) do
    GenServer.start_link(__MODULE__, {host, port, owner, nil})
  end

  def start_link({host, port, owner, stream_id}) do
    GenServer.start_link(__MODULE__, {host, port, owner, stream_id})
  end

  @doc """
  Start a backend connection using an existing (pooled) TCP socket.

  The socket should have `{:active, false}`. This process takes ownership,
  sets it to `{:active, true}`, and begins forwarding data.

  ## Parameters
  - `socket` — an existing `:gen_tcp` socket
  - `owner` — pid of the Session process that will receive responses
  - `stream_id` — optional stream ID for multiplexed mode
  """
  @spec start_link_with_socket(:gen_tcp.socket(), pid(), non_neg_integer() | nil) :: GenServer.on_start()
  def start_link_with_socket(socket, owner, stream_id \\ nil) do
    GenServer.start_link(__MODULE__, {:adopt, socket, owner, stream_id})
  end

  @doc """
  Extract the raw TCP socket from a Backend process and stop it without
  closing the socket. Used to return connections to the pool.

  Returns `{:ok, socket}` on success, `{:error, reason}` if the backend
  is already dead or the socket is closed.
  """
  @spec detach_socket(pid()) :: {:ok, :gen_tcp.socket()} | {:error, term()}
  def detach_socket(pid) do
    GenServer.call(pid, :detach_socket)
  catch
    :exit, _ -> {:error, :noproc}
  end

  @doc """
  Send data to the backend service over TCP.

  Returns `:ok` on success, `{:error, reason}` if the socket is closed.
  """
  @spec send_data(pid(), binary()) :: :ok | {:error, term()}
  def send_data(pid, data) do
    GenServer.call(pid, {:send, data})
  end

  @doc "Close the backend connection."
  @spec close(pid()) :: :ok
  def close(pid) do
    GenServer.cast(pid, :close)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init({host, port, owner, stream_id}) do
    # Connect to the backend. 5-second timeout for the TCP handshake.
    case :gen_tcp.connect(host, port, [:binary, active: true, packet: :raw], 5_000) do
      {:ok, socket} ->
        # Monitor the owner (Session process) — if it dies, we clean up
        Process.monitor(owner)
        {:ok, %{socket: socket, owner: owner, stream_id: stream_id}}

      {:error, reason} ->
        {:stop, {:connect_failed, reason}}
    end
  end

  @impl true
  def handle_call({:send, data}, _from, %{socket: socket} = state) do
    case :gen_tcp.send(socket, data) do
      :ok ->
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast(:close, %{socket: socket} = state) do
    :gen_tcp.close(socket)
    {:stop, :normal, state}
  end

  # TCP data from the backend → forward to the Session process
  # Include stream_id when available (multiplexed mode)
  @impl true
  def handle_info({:tcp, _socket, data}, %{owner: owner, stream_id: nil} = state) do
    send(owner, {:backend_data, data})
    {:noreply, state}
  end

  def handle_info({:tcp, _socket, data}, %{owner: owner, stream_id: stream_id} = state) do
    send(owner, {:backend_data, stream_id, data})
    {:noreply, state}
  end

  # TCP connection closed by the backend
  def handle_info({:tcp_closed, _socket}, %{owner: owner, stream_id: nil} = state) do
    send(owner, :backend_closed)
    {:stop, :normal, state}
  end

  def handle_info({:tcp_closed, _socket}, %{owner: owner, stream_id: stream_id} = state) do
    send(owner, {:backend_closed, stream_id})
    {:stop, :normal, state}
  end

  # TCP error
  def handle_info({:tcp_error, _socket, reason}, %{owner: owner, stream_id: nil} = state) do
    Logger.error("[Backend] TCP error: #{inspect(reason)}")
    send(owner, {:backend_error, reason})
    {:stop, {:tcp_error, reason}, state}
  end

  def handle_info({:tcp_error, _socket, reason}, %{owner: owner, stream_id: stream_id} = state) do
    Logger.error("[Backend] TCP error on stream #{stream_id}: #{inspect(reason)}")
    send(owner, {:backend_error, stream_id, reason})
    {:stop, {:tcp_error, reason}, state}
  end

  # Owner (Session) died — close the TCP socket and stop
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, %{socket: socket} = state) do
    :gen_tcp.close(socket)
    {:stop, :normal, state}
  end
end
