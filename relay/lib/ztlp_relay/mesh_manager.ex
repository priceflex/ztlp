defmodule ZtlpRelay.MeshManager do
  @moduledoc """
  Mesh lifecycle manager for the ZTLP relay mesh.

  GenServer that manages the relay's mesh membership:
  - Bootstraps by sending RELAY_HELLO to configured bootstrap relays
  - Builds and maintains a consistent hash ring of known relays
  - Runs periodic ping sweeps to update PathScores
  - Handles node joins (RELAY_HELLO) and departures (RELAY_LEAVE / timeout)
  - Provides routing: given a SessionID, returns the best relay

  Only active when mesh mode is enabled (ZTLP_RELAY_MESH=true).
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{Config, HashRing, PathScore, RelayRegistry, InterRelay}

  @type state :: %{
    node_id: binary(),
    role: atom(),
    ring: HashRing.ring(),
    socket: :gen_udp.socket() | nil,
    mesh_port: non_neg_integer(),
    ping_interval: non_neg_integer(),
    scores: %{binary() => PathScore.metrics()},
    ping_sent_at: %{binary() => integer()}
  }

  # Client API

  @doc """
  Start the mesh manager.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route a SessionID — returns the best relay for handling this session.

  Returns `{:ok, relay_info}` if a relay is found, or `{:local, :self}`
  if this relay should handle it, or `:error` if no relays are available.
  """
  @spec route(binary()) :: {:ok, map()} | {:local, :self} | :error
  def route(session_id) do
    GenServer.call(__MODULE__, {:route, session_id})
  end

  @doc """
  Get the current mesh status.

  Returns a map with ring info, known relays, scores, etc.
  """
  @spec get_mesh_status() :: map()
  def get_mesh_status do
    GenServer.call(__MODULE__, :get_mesh_status)
  end

  @doc """
  Handle an incoming inter-relay message (called by the mesh UDP listener).
  """
  @spec handle_inter_relay(binary(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def handle_inter_relay(data, sender) do
    GenServer.cast(__MODULE__, {:inter_relay_message, data, sender})
  end

  @doc """
  Get this relay's node_id.
  """
  @spec node_id() :: binary()
  def node_id do
    GenServer.call(__MODULE__, :node_id)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    node_id = Keyword.get(opts, :node_id, Config.relay_node_id())
    role = Keyword.get(opts, :relay_role, Config.relay_role())
    mesh_port = Keyword.get(opts, :mesh_listen_port, Config.mesh_listen_port())
    ping_interval = Keyword.get(opts, :ping_interval_ms, Config.ping_interval_ms())
    bootstrap_relays = Keyword.get(opts, :bootstrap_relays, Config.mesh_bootstrap_relays())

    # Open mesh UDP socket
    socket = case :gen_udp.open(mesh_port, [:binary, {:active, true}]) do
      {:ok, sock} ->
        {:ok, actual_port} = :inet.port(sock)
        Logger.info("ZTLP Mesh listening on port #{actual_port}")
        sock

      {:error, reason} ->
        Logger.warning("Could not open mesh port #{mesh_port}: #{inspect(reason)}, mesh forwarding disabled")
        nil
    end

    # Build initial ring with just ourselves
    our_info = %{
      node_id: node_id,
      address: {Config.listen_address(), Config.listen_port()},
      role: role
    }
    ring = HashRing.new([our_info])

    state = %{
      node_id: node_id,
      role: role,
      ring: ring,
      socket: socket,
      mesh_port: mesh_port,
      ping_interval: ping_interval,
      scores: %{},
      ping_sent_at: %{}
    }

    # Bootstrap: send HELLO to known relays
    if socket do
      bootstrap(socket, node_id, our_info, bootstrap_relays)
      schedule_ping_sweep(ping_interval)
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:route, session_id}, _from, state) do
    candidates = HashRing.get_nodes(state.ring, session_id, 3)

    case candidates do
      [] ->
        {:reply, :error, state}

      _ ->
        # Check if we're the primary candidate
        first = hd(candidates)

        if first.node_id == state.node_id do
          {:reply, {:local, :self}, state}
        else
          # Try PathScore selection among candidates
          case PathScore.select_best(candidates, state.scores) do
            {:ok, best} ->
              if best.node_id == state.node_id do
                {:reply, {:local, :self}, state}
              else
                {:reply, {:ok, best}, state}
              end

            :error ->
              # No scores available — use hash ring primary
              {:reply, {:ok, first}, state}
          end
        end
    end
  end

  def handle_call(:get_mesh_status, _from, state) do
    status = %{
      node_id: state.node_id,
      role: state.role,
      ring_nodes: HashRing.node_count(state.ring),
      known_relays: RelayRegistry.count(),
      scores: state.scores,
      mesh_port: state.mesh_port,
      socket_open: state.socket != nil
    }

    {:reply, status, state}
  end

  def handle_call(:node_id, _from, state) do
    {:reply, state.node_id, state}
  end

  @impl true
  def handle_cast({:inter_relay_message, data, sender}, state) do
    case InterRelay.handle_message(data, sender) do
      {:ok, decoded} ->
        {:noreply, handle_decoded_message(decoded, sender, state)}

      {:error, reason} ->
        Logger.debug("Failed to decode inter-relay message from #{inspect(sender)}: #{reason}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:udp, _socket, src_ip, src_port, data}, state) do
    sender = {src_ip, src_port}

    case InterRelay.handle_message(data, sender) do
      {:ok, decoded} ->
        {:noreply, handle_decoded_message(decoded, sender, state)}

      {:error, reason} ->
        Logger.debug("Failed to decode mesh UDP from #{inspect(sender)}: #{reason}")
        {:noreply, state}
    end
  end

  def handle_info(:ping_sweep, state) do
    state = do_ping_sweep(state)
    schedule_ping_sweep(state.ping_interval)
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

  # Internal message handling

  defp handle_decoded_message({:relay_hello, sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received RELAY_HELLO from #{inspect(sender_node_id)}")

    # Register the new relay
    relay_info = %{
      node_id: sender_node_id,
      address: payload.address,
      role: payload.role
    }
    RelayRegistry.register(relay_info)

    # Add to hash ring
    ring = HashRing.add_node(state.ring, relay_info)

    # Send HELLO_ACK back
    if state.socket do
      our_info = %{
        node_id: state.node_id,
        address: {Config.listen_address(), Config.listen_port()},
        role: state.role,
        capabilities: 0
      }
      ack_data = InterRelay.encode_hello_ack(our_info)
      {ip, port} = payload.address
      :gen_udp.send(state.socket, ip, port, ack_data)
    end

    %{state | ring: ring}
  end

  defp handle_decoded_message({:relay_hello_ack, sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received RELAY_HELLO_ACK from #{inspect(sender_node_id)}")

    relay_info = %{
      node_id: sender_node_id,
      address: payload.address,
      role: payload.role
    }
    RelayRegistry.register(relay_info)

    ring = HashRing.add_node(state.ring, relay_info)
    %{state | ring: ring}
  end

  defp handle_decoded_message({:relay_ping, sender_node_id, _ts, _payload}, _sender, state) do
    # Respond with PONG containing our metrics
    if state.socket do
      metrics = %{
        active_sessions: ZtlpRelay.SessionRegistry.count(),
        max_sessions: Config.max_sessions(),
        uptime_seconds: div(System.monotonic_time(:second), 1)
      }
      pong_data = InterRelay.encode_pong(state.node_id, metrics)

      # Look up the sender's address from registry
      case RelayRegistry.lookup(sender_node_id) do
        {:ok, relay} ->
          {ip, port} = relay.address
          :gen_udp.send(state.socket, ip, port, pong_data)

        :error ->
          Logger.debug("Cannot respond to PING — unknown relay #{inspect(sender_node_id)}")
      end
    end

    # Touch the sender in registry
    RelayRegistry.touch(sender_node_id)
    state
  end

  defp handle_decoded_message({:relay_pong, sender_node_id, _ts, payload}, _sender, state) do
    # Update PathScore metrics for this relay
    now = System.monotonic_time(:millisecond)

    # Calculate RTT from when we sent the ping
    rtt = case Map.get(state.ping_sent_at, sender_node_id) do
      nil -> 100.0  # default if we don't know when we pinged
      sent_at -> max(now - sent_at, 1) / 1.0
    end

    load_factor = PathScore.compute_load_factor(
      payload.active_sessions,
      payload.max_sessions
    )

    # Update existing metrics with EMA for RTT
    old_metrics = Map.get(state.scores, sender_node_id, %{rtt_ms: rtt, loss_rate: 0.0, load_factor: 0.0})
    new_rtt = PathScore.update_rtt(old_metrics.rtt_ms, rtt)

    metrics = %{
      rtt_ms: new_rtt,
      loss_rate: 0.0,  # Updated when pongs are missed
      load_factor: load_factor
    }

    RelayRegistry.update_metrics(sender_node_id, metrics)
    RelayRegistry.touch(sender_node_id)

    ping_sent_at = Map.delete(state.ping_sent_at, sender_node_id)
    %{state | scores: Map.put(state.scores, sender_node_id, metrics), ping_sent_at: ping_sent_at}
  end

  defp handle_decoded_message({:relay_leave, sender_node_id, _ts, _payload}, _sender, state) do
    Logger.info("Relay #{inspect(sender_node_id)} leaving mesh")

    RelayRegistry.unregister(sender_node_id)
    ring = HashRing.remove_node(state.ring, sender_node_id)
    scores = Map.delete(state.scores, sender_node_id)

    %{state | ring: ring, scores: scores}
  end

  defp handle_decoded_message({:relay_forward, _sender_node_id, _ts, %{inner_packet: inner}}, _sender, state) do
    # Forward the inner packet to the UdpListener for processing
    # This is handled by the caller (UdpListener) not here
    Logger.debug("Received RELAY_FORWARD with #{byte_size(inner)} byte inner packet")
    state
  end

  defp handle_decoded_message({:relay_session_sync, _sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received SESSION_SYNC for #{inspect(payload.session_id)}")
    # Register the session locally for forwarding
    ZtlpRelay.SessionRegistry.register_session(
      payload.session_id,
      payload.peer_a,
      payload.peer_b
    )
    state
  end

  # Bootstrap

  defp bootstrap(socket, node_id, our_info, bootstrap_relays) do
    hello = InterRelay.encode_hello(%{
      node_id: node_id,
      address: our_info.address,
      role: our_info[:role] || :all,
      capabilities: 0
    })

    Enum.each(bootstrap_relays, fn relay_str ->
      case parse_relay_address(relay_str) do
        {:ok, {host, port}} ->
          case resolve_host(host) do
            {:ok, ip} ->
              :gen_udp.send(socket, ip, port, hello)
              Logger.debug("Sent RELAY_HELLO to #{relay_str}")

            {:error, reason} ->
              Logger.warning("Cannot resolve bootstrap relay #{relay_str}: #{inspect(reason)}")
          end

        {:error, reason} ->
          Logger.warning("Invalid bootstrap relay address #{relay_str}: #{inspect(reason)}")
      end
    end)
  end

  # Periodic ping sweep

  defp do_ping_sweep(state) do
    relays = RelayRegistry.get_all()
    now = System.monotonic_time(:millisecond)

    ping_data = InterRelay.encode_ping(state.node_id)

    ping_sent_at =
      Enum.reduce(relays, state.ping_sent_at, fn relay, acc ->
        if relay.node_id != state.node_id and state.socket != nil do
          {ip, port} = relay.address
          :gen_udp.send(state.socket, ip, port, ping_data)
          Map.put(acc, relay.node_id, now)
        else
          acc
        end
      end)

    %{state | ping_sent_at: ping_sent_at}
  end

  defp schedule_ping_sweep(interval) do
    Process.send_after(self(), :ping_sweep, interval)
  end

  # Address parsing helpers

  defp parse_relay_address(str) when is_binary(str) do
    case String.split(str, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} -> {:ok, {host, port}}
          _ -> {:error, :invalid_port}
        end

      _ ->
        {:error, :invalid_format}
    end
  end

  defp resolve_host(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} ->
        case :inet.getaddr(String.to_charlist(host), :inet) do
          {:ok, ip} -> {:ok, ip}
          {:error, reason} -> {:error, reason}
        end
    end
  end
end
