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

  In mesh mode (ZTLP_RELAY_MESH=true):
  - Packets for unknown sessions are routed via the hash ring
  - If this relay owns the session: handle normally
  - If another relay owns it: forward via InterRelay
  - RELAY_FORWARD messages are unwrapped and processed as inner packets
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{Pipeline, SessionRegistry, Stats, Session, Config, InterRelay, MeshManager}

  @type state :: %{
    socket: :gen_udp.socket() | nil,
    port: non_neg_integer(),
    mesh_enabled: boolean()
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
    port = Config.listen_port()
    address = Config.listen_address()
    mesh_enabled = Config.mesh_enabled?()

    case :gen_udp.open(port, [:binary, {:active, true}, {:ip, address}]) do
      {:ok, socket} ->
        {:ok, actual_port} = :inet.port(socket)
        Logger.info("ZTLP Relay listening on #{format_addr(address)}:#{actual_port}")

        if mesh_enabled do
          Logger.info("ZTLP Relay mesh mode enabled")
        end

        {:ok, %{socket: socket, port: actual_port, mesh_enabled: mesh_enabled}}

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
        # In mesh mode, check if this is a RELAY_FORWARD message
        # (which won't pass the ZTLP magic check since it uses inter-relay protocol)
        if state.mesh_enabled and InterRelay.inter_relay_message?(data) do
          handle_inter_relay_packet(data, sender, state)
        else
          Logger.debug("Dropped packet from #{inspect(sender)} at layer #{layer}: #{reason}")
          :ok
        end
    end
  end

  # Handle inter-relay protocol messages received on the client port.
  # These are decoded and dispatched — RELAY_FORWARD messages have their
  # inner packet unwrapped and re-processed through the pipeline.
  defp handle_inter_relay_packet(data, sender, state) do
    case InterRelay.handle_message(data, sender) do
      {:ok, {:relay_forward, _sender_node_id, _ts, %{inner_packet: inner}}} ->
        # Re-process the inner packet through the normal pipeline
        handle_packet(inner, sender, state)

      {:ok, _other} ->
        # Other inter-relay messages go to MeshManager
        MeshManager.handle_inter_relay(data, sender)

      {:error, reason} ->
        Logger.debug("Failed to decode inter-relay message from #{inspect(sender)}: #{reason}")
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
        # Session not found locally — try mesh routing if enabled
        if state.mesh_enabled do
          mesh_route_packet(session_id, data, sender, state)
        else
          Logger.debug("No peer found for session #{inspect(session_id)} from #{inspect(sender)}")
          :ok
        end
    end
  end

  # Mesh routing: hash the SessionID to find which relay owns it,
  # then forward via InterRelay if it's not us.
  defp mesh_route_packet(session_id, data, sender, state) do
    case MeshManager.route(session_id) do
      {:local, :self} ->
        # We own this session but don't have it registered — drop
        Logger.debug("Mesh: session #{inspect(session_id)} maps to us but not found, from #{inspect(sender)}")
        :ok

      {:ok, relay} ->
        # Forward to the owning relay
        node_id = MeshManager.node_id()
        forward_data = InterRelay.forward_packet(data, node_id)
        {dest_ip, dest_port} = relay.address
        :gen_udp.send(state.socket, dest_ip, dest_port, forward_data)
        Logger.debug("Mesh: forwarded packet for session #{inspect(session_id)} to relay #{inspect(relay.node_id)}")
        :ok

      :error ->
        Logger.debug("Mesh: no relay found for session #{inspect(session_id)}")
        :ok
    end
  end

  defp format_addr({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_addr(addr), do: inspect(addr)
end
