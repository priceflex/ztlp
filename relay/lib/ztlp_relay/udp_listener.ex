defmodule ZtlpRelay.UdpListener do
  @moduledoc """
  GenServer wrapping `:gen_udp` in active mode.

  Binds to the configured ZTLP port (default 23095 = 0x5A37) and processes
  incoming UDP packets through the admission pipeline.

  On packet receipt:
  1. Run through the three-layer pipeline
  2. If pass: look up session, forward to other peer via `:gen_udp.send`
  3. If handshake (HELLO/HELLO_ACK): handled for future session creation

  For relay forwarding: receive from peer A, send to peer B (same socket).
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{Pipeline, SessionRegistry, Stats, Session}

  @type state :: %{
    socket: :gen_udp.socket() | nil,
    port: non_neg_integer()
  }

  # Client API

  @doc """
  Start the UDP listener.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the actual port the listener is bound to (useful when port 0 is configured).
  """
  @spec get_port() :: non_neg_integer()
  def get_port do
    GenServer.call(__MODULE__, :get_port)
  end

  @doc """
  Get the underlying socket (for testing).
  """
  @spec get_socket() :: :gen_udp.socket()
  def get_socket do
    GenServer.call(__MODULE__, :get_socket)
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    port = ZtlpRelay.Config.listen_port()
    address = ZtlpRelay.Config.listen_address()

    case :gen_udp.open(port, [:binary, {:active, true}, {:ip, address}]) do
      {:ok, socket} ->
        {:ok, actual_port} = :inet.port(socket)
        Logger.info("ZTLP Relay listening on #{format_addr(address)}:#{actual_port}")
        {:ok, %{socket: socket, port: actual_port}}

      {:error, reason} ->
        Logger.error("Failed to open UDP port #{port}: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
  end

  def handle_call(:get_socket, _from, state) do
    {:reply, state.socket, state}
  end

  @impl true
  def handle_info({:udp, _socket, src_ip, src_port, data}, state) do
    sender = {src_ip, src_port}
    handle_packet(data, sender, state)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %{socket: socket}) when socket != nil do
    :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # Internal packet handling

  defp handle_packet(data, sender, state) do
    # Run through the admission pipeline (Layer 3 skipped in relay mode — no keys)
    case Pipeline.process(data, nil) do
      {:pass, parsed} ->
        handle_admitted_packet(parsed, data, sender, state)

      {:drop, layer, reason} ->
        Logger.debug("Dropped packet from #{inspect(sender)} at layer #{layer}: #{reason}")
        :ok
    end
  end

  defp handle_admitted_packet(%{type: :handshake, msg_type: :hello} = _parsed, _data, sender, _state) do
    # HELLO: store pending session (simplified for prototype)
    Logger.debug("Received HELLO from #{inspect(sender)}")
    :ok
  end

  defp handle_admitted_packet(%{type: :handshake, msg_type: :hello_ack} = _parsed, _data, sender, _state) do
    # HELLO_ACK: session establishment (simplified for prototype)
    Logger.debug("Received HELLO_ACK from #{inspect(sender)}")
    :ok
  end

  defp handle_admitted_packet(parsed, data, sender, state) do
    # Data or other control packets — forward to the other peer
    session_id = parsed.session_id

    case SessionRegistry.lookup_peer(session_id, sender) do
      {:ok, {dest_ip, dest_port}} ->
        :gen_udp.send(state.socket, dest_ip, dest_port, data)
        Stats.increment(:forwarded)

        # Notify session GenServer of activity
        case SessionRegistry.lookup_session(session_id) do
          {:ok, {_a, _b, pid}} when is_pid(pid) ->
            Session.forward(pid)

          _ ->
            :ok
        end

      :error ->
        Logger.debug("No peer found for session #{inspect(session_id)} from #{inspect(sender)}")
        :ok
    end
  end

  defp format_addr({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_addr(addr), do: inspect(addr)
end
