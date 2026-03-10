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

  # Process a raw UDP packet through the admission pipeline.
  # The relay passes `nil` for session_key, which means Layer 3
  # (HeaderAuthTag AEAD verification) is skipped — the relay has
  # no access to session keys.  This is the core zero-trust property:
  # the relay can route packets but never read or forge them.
  defp handle_packet(data, sender, state) do
    case Pipeline.process(data, nil) do
      {:pass, parsed} ->
        handle_admitted_packet(parsed, data, sender, state)

      {:drop, layer, reason} ->
        Logger.debug("Dropped packet from #{inspect(sender)} at layer #{layer}: #{reason}")
        :ok
    end
  end

  # HELLO packets — first message of a new handshake.
  # In production, the relay would begin tracking this as a pending
  # session and wait for the HELLO_ACK from the responder.  For the
  # prototype, we just log it — sessions are pre-registered externally.
  defp handle_admitted_packet(%{type: :handshake, msg_type: :hello} = _parsed, _data, sender, _state) do
    Logger.debug("Received HELLO from #{inspect(sender)}")
    :ok
  end

  # HELLO_ACK packets — second message, completing the relay's view
  # of the session.  In production, this would pair the two peers
  # and register the session in the SessionRegistry.
  defp handle_admitted_packet(%{type: :handshake, msg_type: :hello_ack} = _parsed, _data, sender, _state) do
    Logger.debug("Received HELLO_ACK from #{inspect(sender)}")
    :ok
  end

  # All other packets (data, rekey, close, ping/pong, non-HELLO handshake).
  # The relay's core job: look up the SessionID in the registry to find the
  # OTHER peer's address, then forward the raw packet unchanged.  The relay
  # never decrypts, modifies, or inspects the payload — it's an opaque
  # forwarder keyed on SessionID.
  defp handle_admitted_packet(parsed, data, sender, state) do
    session_id = parsed.session_id

    case SessionRegistry.lookup_peer(session_id, sender) do
      {:ok, {dest_ip, dest_port}} ->
        # Forward the raw packet to the other peer — unchanged, byte-for-byte
        :gen_udp.send(state.socket, dest_ip, dest_port, data)
        Stats.increment(:forwarded)

        # Notify the session GenServer so it can reset its inactivity timer.
        # If the session has no associated GenServer (pid=nil), skip silently.
        case SessionRegistry.lookup_session(session_id) do
          {:ok, {_a, _b, pid}} when is_pid(pid) ->
            Session.forward(pid)

          _ ->
            :ok
        end

      :error ->
        # This can happen if a peer's address changed (NAT rebind) or
        # the sender is an unknown third party.  Drop silently.
        Logger.debug("No peer found for session #{inspect(session_id)} from #{inspect(sender)}")
        :ok
    end
  end

  defp format_addr({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_addr(addr), do: inspect(addr)
end
