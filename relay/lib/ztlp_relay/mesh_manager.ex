defmodule ZtlpRelay.MeshManager do
  @moduledoc """
  Mesh lifecycle manager for the ZTLP relay mesh.

  GenServer that manages the relay's mesh membership:
  - Bootstraps by sending RELAY_HELLO to configured bootstrap relays
  - Builds and maintains a consistent hash ring of known relays
  - Runs periodic ping sweeps to update PathScores with real loss detection
  - Handles node joins (RELAY_HELLO) and departures (RELAY_LEAVE / timeout)
  - Provides routing: given a SessionID, returns the best relay
  - Tracks per-relay probe state with sliding windows for loss/jitter
  - Skips unreachable relays during routing

  Only active when mesh mode is enabled (ZTLP_RELAY_MESH=true).
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{Config, HashRing, PathScore, RelayRegistry, InterRelay}

  # Sliding window size for loss/jitter computation
  @probe_window_size 20

  @type probe_state :: %{
    seq: non_neg_integer(),
    probes: %{non_neg_integer() => map()},
    rtt_samples: [float()],
    missed_sweeps: non_neg_integer()
  }

  @type state :: %{
    node_id: binary(),
    role: atom(),
    ring: HashRing.ring(),
    socket: :gen_udp.socket() | nil,
    mesh_port: non_neg_integer(),
    ping_interval: non_neg_integer(),
    scores: %{binary() => PathScore.metrics()},
    ping_sent_at: %{binary() => integer()},
    probe_states: %{binary() => probe_state()}
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
  Route a SessionID - returns the best relay for handling this session.

  Returns `{:ok, relay_info}` for single-hop, `{:forward, next_hop, full_path}`
  for multi-hop, `{:local, :self}` if this relay handles it, or `:error`.

  Skips relays with `:unreachable` health state.
  """
  @spec route(binary()) :: {:ok, map()} | {:forward, map(), [map()]} | {:local, :self} | :error
  def route(session_id) do
    GenServer.call(__MODULE__, {:route, session_id})
  end

  @doc "Forward a packet via multi-hop path with TTL."
  @spec forward_multihop(binary(), binary(), [map()], non_neg_integer()) :: :ok | {:error, atom()}
  def forward_multihop(inner_packet, sender_node_id, path, ttl \\ InterRelay.default_ttl()) do
    GenServer.call(__MODULE__, {:forward_multihop, inner_packet, sender_node_id, path, ttl})
  end

  @doc """
  Get the current mesh status.
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
      ping_sent_at: %{},
      probe_states: %{}
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
    # Check forwarding table cache first
    cached_path = try do
      ForwardingTable.get(session_id)
    catch
      :error, :badarg -> nil
    end

    case cached_path do
      path when is_list(path) and path != [] ->
        registry_map = Map.new(RelayRegistry.get_all(), fn r -> {r.node_id, r} end)
        first_hop_id = hd(path)
        case Map.get(registry_map, first_hop_id) do
          nil ->
            try do ForwardingTable.delete(session_id) catch :error, :badarg -> :ok end
            {:reply, do_route(session_id, state), state}
          first_hop ->
            full_path = Enum.map(path, fn nid -> Map.get(registry_map, nid, %{node_id: nid}) end)
            {:reply, {:forward, first_hop, full_path}, state}
        end

      _ ->
        {:reply, do_route(session_id, state), state}
    end
  end

  def handle_call({:forward_multihop, inner_packet, sender_node_id, path, ttl}, _from, state) do
    if state.socket == nil do
      {:reply, {:error, :no_socket}, state}
    else
      path_node_ids = Enum.map(path, fn
        %{node_id: nid} -> nid
        nid when is_binary(nid) -> nid
      end)
      forward_data = InterRelay.encode_forward(sender_node_id, inner_packet, ttl: ttl, path: path_node_ids)
      case path do
        [first | _] ->
          case first do
            %{address: {dest_ip, dest_port}} ->
              :gen_udp.send(state.socket, dest_ip, dest_port, forward_data)
              {:reply, :ok, state}
            _ ->
              {:reply, {:error, :no_address}, state}
          end
        [] ->
          {:reply, {:error, :empty_path}, state}
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

    relay_info = %{
      node_id: sender_node_id,
      address: payload.address,
      role: payload.role
    }
    RelayRegistry.register(relay_info)

    ring = HashRing.add_node(state.ring, relay_info)

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

  defp handle_decoded_message({:relay_ping, sender_node_id, _ts, payload}, _sender, state) do
    seq = Map.get(payload, :seq, 0)

    if state.socket do
      metrics = %{
        active_sessions: ZtlpRelay.SessionRegistry.count(),
        max_sessions: Config.max_sessions(),
        uptime_seconds: div(System.monotonic_time(:second), 1)
      }
      pong_data = InterRelay.encode_pong(state.node_id, metrics, seq)

      case RelayRegistry.lookup(sender_node_id) do
        {:ok, relay} ->
          {ip, port} = relay.address
          :gen_udp.send(state.socket, ip, port, pong_data)

        :error ->
          Logger.debug("Cannot respond to PING - unknown relay #{inspect(sender_node_id)}")
      end
    end

    RelayRegistry.touch(sender_node_id)
    state
  end

  defp handle_decoded_message({:relay_pong, sender_node_id, _ts, payload}, _sender, state) do
    now = System.monotonic_time(:millisecond)
    echo_seq = Map.get(payload, :echo_seq, 0)

    probe_state = Map.get(state.probe_states, sender_node_id, new_probe_state())

    {rtt, probe_state} = case Map.get(probe_state.probes, echo_seq) do
      %{sent_at: sent_at, acked: false} ->
        rtt = max(now - sent_at, 1) / 1.0
        probes = Map.put(probe_state.probes, echo_seq, %{sent_at: sent_at, acked: true})
        {rtt, %{probe_state | probes: probes}}

      _ ->
        fallback_rtt = case Map.get(state.ping_sent_at, sender_node_id) do
          nil -> 100.0
          sent_at -> max(now - sent_at, 1) / 1.0
        end
        {fallback_rtt, probe_state}
    end

    probe_state = %{probe_state | missed_sweeps: 0}

    rtt_samples = Enum.take([rtt | probe_state.rtt_samples], @probe_window_size)
    probe_state = %{probe_state | rtt_samples: rtt_samples}

    loss_rate = compute_loss_rate(probe_state)
    jitter_ms = PathScore.compute_jitter(rtt_samples)

    load_factor = PathScore.compute_load_factor(
      payload.active_sessions,
      payload.max_sessions
    )

    old_metrics = Map.get(state.scores, sender_node_id,
      %{rtt_ms: rtt, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 0.0})
    old_rtt = Map.get(old_metrics, :rtt_ms, rtt)
    new_rtt = PathScore.update_rtt(old_rtt, rtt)

    metrics = %{
      rtt_ms: new_rtt,
      loss_rate: loss_rate,
      load_factor: load_factor,
      jitter_ms: jitter_ms
    }

    RelayRegistry.update_metrics(sender_node_id, metrics)
    RelayRegistry.touch(sender_node_id)

    RelayRegistry.update_health(sender_node_id,
      loss_rate: loss_rate,
      rtt_ms: new_rtt,
      missed_sweeps: 0,
      pong_received: true
    )

    ping_sent_at = Map.delete(state.ping_sent_at, sender_node_id)
    probe_states = Map.put(state.probe_states, sender_node_id, probe_state)

    %{state |
      scores: Map.put(state.scores, sender_node_id, metrics),
      ping_sent_at: ping_sent_at,
      probe_states: probe_states
    }
  end

  defp handle_decoded_message({:relay_leave, sender_node_id, _ts, _payload}, _sender, state) do
    Logger.info("Relay #{inspect(sender_node_id)} leaving mesh")

    RelayRegistry.unregister(sender_node_id)
    RelayRegistry.remove_health(sender_node_id)
    ring = HashRing.remove_node(state.ring, sender_node_id)
    scores = Map.delete(state.scores, sender_node_id)
    probe_states = Map.delete(state.probe_states, sender_node_id)

    %{state | ring: ring, scores: scores, probe_states: probe_states}
  end

  defp handle_decoded_message({:relay_forward, _sender_node_id, _ts, %{inner_packet: inner}}, _sender, state) do
    Logger.debug("Received RELAY_FORWARD with #{byte_size(inner)} byte inner packet")
    state
  end

  defp handle_decoded_message({:relay_session_sync, _sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received SESSION_SYNC for #{inspect(payload.session_id)}")
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

  # Periodic ping sweep with probe tracking

  defp do_ping_sweep(state) do
    relays = RelayRegistry.get_all()
    now = System.monotonic_time(:millisecond)

    loss_threshold = now - (state.ping_interval * 2)
    probe_states = detect_losses(state.probe_states, loss_threshold)

    probe_states = Enum.reduce(relays, probe_states, fn relay, ps_acc ->
      if relay.node_id != state.node_id do
        probe_st = Map.get(ps_acc, relay.node_id, new_probe_state())
        last_seq = probe_st.seq
        last_acked = case Map.get(probe_st.probes, last_seq) do
          %{acked: true} -> true
          _ -> last_seq == 0
        end

        if not last_acked and last_seq > 0 do
          missed = probe_st.missed_sweeps + 1
          probe_st = %{probe_st | missed_sweeps: missed}
          loss_rate = compute_loss_rate(probe_st)
          old_rtt = case Map.get(state.scores, relay.node_id) do
            %{rtt_ms: rtt} -> rtt
            _ -> 0.0
          end

          RelayRegistry.update_health(relay.node_id,
            loss_rate: loss_rate,
            rtt_ms: old_rtt,
            missed_sweeps: missed,
            pong_received: false
          )

          Map.put(ps_acc, relay.node_id, probe_st)
        else
          ps_acc
        end
      else
        ps_acc
      end
    end)

    {ping_sent_at, probe_states} =
      Enum.reduce(relays, {state.ping_sent_at, probe_states}, fn relay, {psa, ps} ->
        if relay.node_id != state.node_id and state.socket != nil do
          probe_st = Map.get(ps, relay.node_id, new_probe_state())
          new_seq = probe_st.seq + 1

          ping_data = InterRelay.encode_ping(state.node_id, new_seq)
          {ip, port} = relay.address
          :gen_udp.send(state.socket, ip, port, ping_data)

          probes = Map.put(probe_st.probes, new_seq, %{sent_at: now, acked: false})
          probes = trim_probes(probes, new_seq, @probe_window_size)
          probe_st = %{probe_st | seq: new_seq, probes: probes}

          {Map.put(psa, relay.node_id, now), Map.put(ps, relay.node_id, probe_st)}
        else
          {psa, ps}
        end
      end)

    scores = Enum.reduce(probe_states, state.scores, fn {node_id, probe_st}, scores_acc ->
      loss_rate = compute_loss_rate(probe_st)
      jitter_ms = PathScore.compute_jitter(probe_st.rtt_samples)

      case Map.get(scores_acc, node_id) do
        nil -> scores_acc
        metrics ->
          updated = Map.merge(metrics, %{loss_rate: loss_rate, jitter_ms: jitter_ms})
          Map.put(scores_acc, node_id, updated)
      end
    end)

    %{state | ping_sent_at: ping_sent_at, probe_states: probe_states, scores: scores}
  end

  defp schedule_ping_sweep(interval) do
    Process.send_after(self(), :ping_sweep, interval)
  end

  # Probe state helpers

  defp new_probe_state do
    %{
      seq: 0,
      probes: %{},
      rtt_samples: [],
      missed_sweeps: 0
    }
  end

  defp detect_losses(probe_states, loss_threshold) do
    Enum.into(probe_states, %{}, fn {node_id, probe_st} ->
      probes = Enum.into(probe_st.probes, %{}, fn {seq, probe} ->
        if probe.acked == false and probe.sent_at < loss_threshold do
          {seq, %{probe | acked: :lost}}
        else
          {seq, probe}
        end
      end)
      {node_id, %{probe_st | probes: probes}}
    end)
  end

  defp trim_probes(probes, current_seq, window_size) do
    min_seq = max(current_seq - window_size + 1, 1)
    probes
    |> Enum.filter(fn {seq, _} -> seq >= min_seq end)
    |> Enum.into(%{})
  end

  defp compute_loss_rate(%{probes: probes}) when map_size(probes) == 0, do: 0.0

  defp compute_loss_rate(%{probes: probes}) do
    total = map_size(probes)
    lost = Enum.count(probes, fn {_seq, p} -> p.acked == :lost end)
    pending = Enum.count(probes, fn {_seq, p} -> p.acked == false end)
    resolved = total - pending

    if resolved > 0 do
      lost / resolved
    else
      0.0
    end
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
