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

  alias ZtlpRelay.{
    Pipeline,
    SessionRegistry,
    Stats,
    Session,
    Config,
    InterRelay,
    MeshManager,
    GatewayForwarder,
    Packet
  }

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

    # Debug: log all packets from known gateway IPs
    if src_ip == {54, 149, 48, 6} do
      Logger.info("[UdpListener] Packet from gateway #{inspect(sender)} len=#{byte_size(data)} first=#{if byte_size(data) > 0, do: :binary.at(data, 0), else: :empty}")
    end

    # Check for GATEWAY_REGISTER packet before the pipeline
    case data do
      <<0x5A, 0x37, 0x0A, rest::binary>> ->
        handle_gateway_register(rest, sender)

      _ ->
        handle_packet(data, sender, state)
    end

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

  # ---------------------------------------------------------------------------
  # Gateway dynamic registration
  # ---------------------------------------------------------------------------

  # Handle a GATEWAY_REGISTER packet (magic + 0x0A already stripped).
  # Format after magic+type: [16 node_id][16 service_name][4 TTL][8 timestamp][32 HMAC]
  defp handle_gateway_register(
         <<node_id::binary-size(16), service_raw::binary-size(16), ttl::32,
           timestamp::64, hmac::binary-size(32)>>,
         sender
       ) do
    service_name = service_raw |> :binary.bin_to_list() |> Enum.take_while(&(&1 != 0)) |> to_string()

    # Verify HMAC if a shared secret is configured
    case Config.registration_secret() do
      nil ->
        # Dev mode — accept without verification
        Logger.debug("[UdpListener] Accepting unverified GATEWAY_REGISTER from #{inspect(sender)}")
        do_register_gateway(sender, node_id, service_name, ttl)

      secret ->
        # Build the message that was signed: type + node_id + service + ttl + timestamp
        signed_data = <<0x0A, node_id::binary, service_raw::binary, ttl::32, timestamp::64>>
        expected_hmac = :crypto.mac(:hmac, :sha256, secret, signed_data)

        if secure_compare(expected_hmac, hmac) do
          # Verify timestamp is within 5 minutes
          now = System.system_time(:second)

          if abs(now - timestamp) <= 300 do
            do_register_gateway(sender, node_id, service_name, ttl)
          else
            Logger.warning(
              "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} rejected: timestamp too old " <>
                "(delta=#{now - timestamp}s)"
            )
          end
        else
          Logger.warning(
            "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} rejected: invalid HMAC"
          )
        end
    end
  end

  # Packet too short or malformed
  defp handle_gateway_register(_data, sender) do
    Logger.warning("[UdpListener] Malformed GATEWAY_REGISTER from #{inspect(sender)}")
  end

  # Constant-time binary comparison to prevent timing attacks on HMAC verification.
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    a_bytes = :binary.bin_to_list(a)
    b_bytes = :binary.bin_to_list(b)

    Enum.zip(a_bytes, b_bytes)
    |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end)
    |> Kernel.==(0)
  end

  defp secure_compare(_a, _b), do: false

  defp do_register_gateway(sender, node_id, service_name, ttl) do
    # Ensure GatewayForwarder is running
    case GenServer.whereis(GatewayForwarder) do
      nil ->
        Logger.warning(
          "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} but GatewayForwarder not running"
        )

      _pid ->
        GatewayForwarder.register_dynamic_gateway(sender, node_id, service_name, ttl)
    end
  end

  # ---------------------------------------------------------------------------
  # Internal packet handling
  # ---------------------------------------------------------------------------

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
  # Dispatches RELAY_FORWARD through multi-hop pipeline.
  defp handle_inter_relay_packet(data, sender, state) do
    case InterRelay.handle_message(data, sender) do
      {:ok, {:relay_forward, sender_node_id, _ts, payload}} ->
        handle_relay_forward(sender_node_id, payload, sender, state)

      {:ok, _other} ->
        MeshManager.handle_inter_relay(data, sender)

      {:error, reason} ->
        Logger.debug("Failed to decode inter-relay message from #{inspect(sender)}: #{reason}")
        :ok
    end
  end

  # Multi-hop RELAY_FORWARD: check TTL, loop, then deliver or forward.
  defp handle_relay_forward(
         _sender_node_id,
         %{inner_packet: inner, ttl: ttl, path: path},
         _sender,
         state
       ) do
    our_node_id = get_our_node_id()

    cond do
      ttl <= 0 ->
        Logger.debug("Multi-hop: dropping packet with TTL=0")
        :ok

      InterRelay.loop_detected?(our_node_id, path) ->
        Logger.debug("Multi-hop: loop detected, dropping")
        :ok

      true ->
        case try_local_delivery(inner, state) do
          :delivered -> :ok
          :not_local -> forward_to_next_hop(inner, our_node_id, path, ttl - 1, state)
        end
    end
  end

  # Backward compat: RELAY_FORWARD without TTL/path
  defp handle_relay_forward(_sender_node_id, %{inner_packet: inner}, sender, state) do
    handle_packet(inner, sender, state)
  end

  defp try_local_delivery(inner, state) do
    case Pipeline.process(inner, nil) do
      {:pass, parsed} ->
        case SessionRegistry.lookup_session(parsed.session_id) do
          {:ok, {peer_a, _peer_b, _pid}} ->
            :gen_udp.send(state.socket, elem(peer_a, 0), elem(peer_a, 1), inner)
            Stats.increment(:forwarded)
            :delivered

          :error ->
            :not_local
        end

      {:drop, _layer, _reason} ->
        :not_local
    end
  end

  defp forward_to_next_hop(inner, our_node_id, path, ttl, state) do
    new_path = path ++ [our_node_id]

    case Packet.extract_session_id(inner) do
      {:ok, session_id} ->
        case MeshManager.route(session_id) do
          {:forward, next_hop, _} ->
            send_forward_to_relay(inner, our_node_id, new_path, ttl, next_hop, state)

          {:ok, relay} ->
            send_forward_to_relay(inner, our_node_id, new_path, ttl, relay, state)

          _ ->
            :ok
        end

      :error ->
        :ok
    end
  end

  defp send_forward_to_relay(inner, our_node_id, path, ttl, relay, state) do
    forward_data = InterRelay.encode_forward(our_node_id, inner, ttl: ttl, path: path)
    {dest_ip, dest_port} = relay.address
    :gen_udp.send(state.socket, dest_ip, dest_port, forward_data)
    :ok
  end

  defp get_our_node_id do
    try do
      MeshManager.node_id()
    catch
      :exit, _ -> <<0::128>>
    end
  end

  # HELLO packets — first message of a new handshake.
  # If gateways are configured, forward the HELLO to a gateway and track
  # the session for bidirectional forwarding (client ↔ relay ↔ gateway).
  # Otherwise, creates a HALF_OPEN session with peer_a = sender (legacy).
  defp handle_admitted_packet(
         %{type: :handshake, msg_type: :hello} = parsed,
         data,
         sender,
         state
       ) do
    session_id = parsed.session_id

    case SessionRegistry.lookup_session(session_id) do
      {:ok, {peer_a, peer_b, pid}} ->
        cond do
          # Known peer retransmit on a half-open session with no gateway yet —
          # try to upgrade to gateway-forwarded session now (the gateway may have
          # registered since the first HELLO was received).
          sender == peer_a and peer_b == nil and GatewayForwarder.enabled?() ->
            Logger.info(
              "Upgrading half-open session #{Base.encode16(session_id)} to gateway-forwarded " <>
                "(HELLO retransmit from #{inspect(sender)})"
            )

            # Clean up the old half-open session
            if is_pid(pid), do: Session.close(pid)
            SessionRegistry.unregister_session(session_id)

            # Re-create as gateway-forwarded
            forward_hello_to_gateway(session_id, data, sender, parsed, state)

          # Known peer — forward normally
          sender == peer_a or sender == peer_b ->
            Logger.debug("Received HELLO from known peer #{inspect(sender)}")
            :ok

          # Half-open session, this is the second peer
          peer_b == nil and is_pid(pid) ->
            case Session.set_peer_b(pid, sender) do
              :ok ->
                Logger.debug(
                  "HELLO from second peer #{inspect(sender)} — session #{Base.encode16(session_id)} now ESTABLISHED"
                )

                # Forward this HELLO to peer_a
                {dest_ip, dest_port} = peer_a
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)

              {:error, _} ->
                Logger.debug("Received HELLO from #{inspect(sender)} but session already established")
            end

          true ->
            Logger.debug("Received HELLO from unknown peer #{inspect(sender)} on existing session")
        end

      :error ->
        # New session — check if we should forward to a gateway
        if GatewayForwarder.enabled?() do
          forward_hello_to_gateway(session_id, data, sender, parsed, state)
        else
          create_half_open_session(session_id, sender)
        end
    end
  end

  # HELLO_ACK packets — second message, completing the relay's view
  # of the session. If the session is HALF_OPEN, this learns peer_b
  # and transitions to ESTABLISHED.
  defp handle_admitted_packet(
         %{type: :handshake, msg_type: :hello_ack} = parsed,
         data,
         sender,
         state
       ) do
    session_id = parsed.session_id

    case SessionRegistry.lookup_session(session_id) do
      {:ok, {peer_a, peer_b, pid}} ->
        cond do
          # Known peer — forward to the other
          sender == peer_a ->
            if peer_b != nil do
              {dest_ip, dest_port} = peer_b
              :gen_udp.send(state.socket, dest_ip, dest_port, data)
              Stats.increment(:forwarded)

              if is_pid(pid), do: Session.forward(pid)
            end

          sender == peer_b ->
            {dest_ip, dest_port} = peer_a
            :gen_udp.send(state.socket, dest_ip, dest_port, data)
            Stats.increment(:forwarded)

            if is_pid(pid), do: Session.forward(pid)

          # Half-open session, this is the second peer
          peer_b == nil and is_pid(pid) ->
            case Session.set_peer_b(pid, sender) do
              :ok ->
                Logger.debug(
                  "HELLO_ACK from second peer #{inspect(sender)} — session #{Base.encode16(session_id)} now ESTABLISHED"
                )

                # Forward HELLO_ACK to peer_a
                {dest_ip, dest_port} = peer_a
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)

              {:error, _} ->
                Logger.debug("Received HELLO_ACK from #{inspect(sender)} but session not half-open")
            end

          true ->
            Logger.debug("Received HELLO_ACK from unknown peer #{inspect(sender)}")
        end

      :error ->
        Logger.debug("Received HELLO_ACK for unknown session from #{inspect(sender)}")
    end
  end

  # All other packets (data, rekey, close, ping/pong, non-HELLO handshake).
  # The relay's core job: look up the SessionID in the registry to find the
  # OTHER peer's address, then forward the raw packet unchanged.  The relay
  # never decrypts, modifies, or inspects the payload — it's an opaque
  # forwarder keyed on SessionID.
  defp handle_admitted_packet(parsed, data, sender, state) do
    session_id = parsed.session_id

    case SessionRegistry.lookup_session(session_id) do
      {:ok, {peer_a, peer_b, pid}} ->
        cond do
          # Known peer_a — forward to peer_b
          sender == peer_a and peer_b != nil ->
            {dest_ip, dest_port} = peer_b
            :gen_udp.send(state.socket, dest_ip, dest_port, data)
            Stats.increment(:forwarded)
            if is_pid(pid), do: Session.forward(pid)

          # Known peer_b — forward to peer_a
          sender == peer_b ->
            {dest_ip, dest_port} = peer_a
            :gen_udp.send(state.socket, dest_ip, dest_port, data)
            Stats.increment(:forwarded)
            if is_pid(pid), do: Session.forward(pid)

          # Half-open session, new sender is peer_b
          peer_b == nil and sender != peer_a and is_pid(pid) ->
            case Session.set_peer_b(pid, sender) do
              :ok ->
                Logger.debug(
                  "Learned peer_b #{inspect(sender)} from data packet — session #{Base.encode16(session_id)} now ESTABLISHED"
                )

                # Forward this packet to peer_a
                {dest_ip, dest_port} = peer_a
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)

              {:error, _} ->
                :ok
            end

          # peer_a sent but peer_b not yet known — buffer situation
          sender == peer_a and peer_b == nil ->
            Logger.debug(
              "Packet from peer_a but peer_b unknown for session #{Base.encode16(session_id)} — dropping"
            )

            :ok

          # Unknown sender on existing session — check if it's a known gateway
          # whose IP changed (e.g., AWS VPC internal IP vs public Elastic IP).
          # This is the classic dual-NIC / Elastic IP problem: the relay registered
          # peer_b from the public IP seen in the HELLO_ACK, but subsequent data
          # packets may arrive from the VPC-internal IP.
          #
          # IMPORTANT: Only migrate if the IP changed but the port stayed the
          # same, OR if the full {ip, port} matches a registered gateway address.
          # We must NOT migrate when the gateway's registration packet arrives
          # from an ephemeral source port — that would redirect session traffic
          # to a port the gateway isn't listening on.
          true ->
            {sender_ip, sender_port} = sender
            {_peer_b_ip, peer_b_port} = peer_b
            gateway_ips = GatewayForwarder.known_gateway_ips()

            # Allow migration only if:
            # 1. The IP is a known gateway IP, AND
            # 2. The port matches peer_b's original port (IP-only change, e.g. VPC→EIP)
            same_port = sender_port == peer_b_port

            cond do
              sender_ip in gateway_ips and same_port ->
                # Sender is a registered gateway with matching port — safe to migrate
                Logger.info(
                  "Gateway address migration: session #{Base.encode16(session_id)} " <>
                    "peer_b #{inspect(peer_b)} → #{inspect(sender)} (known gateway IP, same port)"
                )

                # Update session registry so future packets match on first check
                if is_pid(pid), do: Session.update_peer_b(pid, sender)
                SessionRegistry.update_peer_b(session_id, sender)

                # Forward to client
                {dest_ip, dest_port} = peer_a
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)
                if is_pid(pid), do: Session.forward(pid)

              # Session-ID routing (Nebula-style): the sender has a valid session
              # but doesn't match peer_a or peer_b's exact address. This covers:
              #
              # 1. iOS separate ACK socket: Swift NWConnection sends ACKs from a
              #    different source port than the main tokio data socket. Both are
              #    from the same client IP. We MUST NOT update peer_a here or the
              #    two ports will flip-flop peer_a back and forth every 5 seconds.
              #
              # 2. True cellular NAT rebinding: the carrier changed the port on
              #    the main data socket. The client's next data packet will come
              #    from the new port and match here too.
              #
              # In both cases, the session_id in the ZTLP header is the routing
              # key. The gateway's AEAD verification provides real authentication.
              # We forward to gateway WITHOUT updating peer_a (return traffic
              # always goes to the address that last matched as peer_a).
              sender_ip not in gateway_ips ->
                Logger.debug(
                  "Session-ID routed: session #{Base.encode16(session_id)} " <>
                    "from #{inspect(sender)} (peer_a=#{inspect(peer_a)}) → forwarding to gateway"
                )

                {dest_ip, dest_port} = peer_b
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)
                if is_pid(pid), do: Session.forward(pid)

              true ->
                if state.mesh_enabled do
                  mesh_route_packet(session_id, data, sender, state)
                else
                  Logger.debug(
                    "Unknown sender #{inspect(sender)} for session #{Base.encode16(session_id)} " <>
                      "(peer_a=#{inspect(peer_a)} peer_b=#{inspect(peer_b)})"
                  )

                :ok
              end
            end
        end

      :error ->
        # Session not in SessionRegistry — try GatewayForwarder (dynamic gateway sessions)
        case GatewayForwarder.lookup(session_id) do
          {:ok, %{client: client_addr, gateway: gateway_addr}} ->
            cond do
              sender == client_addr ->
                {dest_ip, dest_port} = gateway_addr
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)

              sender == gateway_addr ->
                {dest_ip, dest_port} = client_addr
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)

              true ->
                # Sender IP might differ from registered addresses.
                {sender_ip, sender_port} = sender
                {_gw_ip, gw_port} = gateway_addr
                {_client_ip, _client_port} = client_addr

                cond do
                  # Gateway IP migration (VPC vs EIP)
                  sender_ip in GatewayForwarder.known_gateway_ips() and sender_port == gw_port ->
                    {dest_ip, dest_port} = client_addr
                    :gen_udp.send(state.socket, dest_ip, dest_port, data)
                    Stats.increment(:forwarded)

                  # Session-ID routing: sender has valid session but from a
                  # different port (ACK socket or NAT rebind). Forward without
                  # updating client_addr to avoid flip-flop with dual sockets.
                  sender_ip not in GatewayForwarder.known_gateway_ips() ->
                    Logger.debug(
                      "Session-ID routed (GW-fwd): #{Base.encode16(session_id)} " <>
                        "from #{inspect(sender)} → forwarding to gateway"
                    )
                    {dest_ip, dest_port} = gateway_addr
                    :gen_udp.send(state.socket, dest_ip, dest_port, data)
                    Stats.increment(:forwarded)

                  true ->
                    Logger.debug(
                      "Unknown sender #{inspect(sender)} for GW-forwarded session #{Base.encode16(session_id)}"
                    )
                end
            end

          :error ->
            if state.mesh_enabled do
              mesh_route_packet(session_id, data, sender, state)
            else
              Logger.debug("No session found for #{Base.encode16(session_id)} from #{inspect(sender)}")
              :ok
            end
        end
    end
  end

  # Forward a HELLO to a configured gateway.
  # The relay registers the session as {client, gateway} so that responses
  # from the gateway are forwarded back to the client.
  defp forward_hello_to_gateway(session_id, data, client_addr, parsed, state) do
    # Extract service name from HELLO dst_svc_id (16 bytes, zero-padded)
    service_name =
      case Map.get(parsed, :dst_svc_id) do
        nil -> nil
        <<0::128>> -> nil
        svc_raw ->
          svc_raw |> :binary.bin_to_list() |> Enum.take_while(&(&1 != 0)) |> to_string()
      end

    pick_result =
      case service_name do
        nil -> GatewayForwarder.pick_gateway()
        "" -> GatewayForwarder.pick_gateway()
        svc -> GatewayForwarder.pick_gateway_for_service(svc)
      end

    case pick_result do
      {:ok, gateway_addr} ->
        Logger.info(
          "[GatewayFwd] Forwarding HELLO for session #{Base.encode16(session_id)} " <>
            "from #{inspect(client_addr)} to gateway #{inspect(gateway_addr)}"
        )

        # Register with GatewayForwarder for response routing
        GatewayForwarder.register_forwarded_session(session_id, client_addr, gateway_addr)

        # Create a normal session with client=peer_a, gateway=peer_b
        SessionRegistry.register_session(session_id, client_addr, gateway_addr)

        case Session.start_link(
               session_id: session_id,
               peer_a: client_addr,
               peer_b: gateway_addr,
               timeout_ms: Config.session_timeout_ms(),
               half_open_timeout_ms: 30_000
             ) do
          {:ok, pid} ->
            SessionRegistry.update_session_pid(session_id, pid)

            # Set peer_b immediately (session is pre-established)
            Session.set_peer_b(pid, gateway_addr)

          {:error, reason} ->
            Logger.error("[GatewayFwd] Failed to start session: #{inspect(reason)}")
        end

        # Forward the HELLO to the gateway
        {dest_ip, dest_port} = gateway_addr
        :gen_udp.send(state.socket, dest_ip, dest_port, data)
        Stats.increment(:forwarded)

      :error ->
        # No gateways available, fall back to half-open session
        create_half_open_session(session_id, client_addr)
    end
  end

  # Create a standard half-open relay session (peer-to-peer, no gateway).
  defp create_half_open_session(session_id, sender) do
    Logger.debug("New session #{Base.encode16(session_id)} from #{inspect(sender)}")

    SessionRegistry.register_session(session_id, sender, nil)

    case Session.start_link(
           session_id: session_id,
           peer_a: sender,
           peer_b: nil,
           timeout_ms: Config.session_timeout_ms(),
           half_open_timeout_ms: 30_000
         ) do
      {:ok, pid} ->
        SessionRegistry.update_session_pid(session_id, pid)

      {:error, reason} ->
        Logger.error("Failed to start session: #{inspect(reason)}")
    end
  end

  # Mesh routing: hash the SessionID to find which relay owns it,
  # then forward via InterRelay (single-hop or multi-hop).
  defp mesh_route_packet(session_id, data, sender, state) do
    node_id = get_our_node_id()

    case MeshManager.route(session_id) do
      {:local, :self} ->
        Logger.debug(
          "Mesh: session #{inspect(session_id)} maps to us but not found, from #{inspect(sender)}"
        )

        :ok

      {:forward, next_hop, _full_path} ->
        forward_data =
          InterRelay.forward_packet(data, node_id, ttl: InterRelay.default_ttl(), path: [node_id])

        {dest_ip, dest_port} = next_hop.address
        :gen_udp.send(state.socket, dest_ip, dest_port, forward_data)
        :ok

      {:ok, relay} ->
        forward_data = InterRelay.forward_packet(data, node_id)
        {dest_ip, dest_port} = relay.address
        :gen_udp.send(state.socket, dest_ip, dest_port, forward_data)
        :ok

      :error ->
        Logger.debug("Mesh: no relay found for session #{inspect(session_id)}")
        :ok
    end
  end

  defp format_addr({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_addr(addr), do: inspect(addr)
end
