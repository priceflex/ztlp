defmodule ZtlpRelay.MeshManager do
  @moduledoc """
  Mesh lifecycle manager for the ZTLP relay mesh.
  """

  use GenServer
  require Logger

  alias ZtlpRelay.NsClient
  alias ZtlpRelay.{Config, HashRing, PathScore, RelayRegistry, InterRelay}

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

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec route(binary()) :: {:ok, map()} | {:local, :self} | :error
  def route(session_id), do: GenServer.call(__MODULE__, {:route, session_id})

  @spec get_mesh_status() :: map()
  def get_mesh_status, do: GenServer.call(__MODULE__, :get_mesh_status)

  @spec handle_inter_relay(binary(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def handle_inter_relay(data, sender), do: GenServer.cast(__MODULE__, {:inter_relay_message, data, sender})

  @spec node_id() :: binary()
  def node_id, do: GenServer.call(__MODULE__, :node_id)

  @impl true
  def init(opts) do
    node_id = Keyword.get(opts, :node_id, Config.relay_node_id())
    role = Keyword.get(opts, :relay_role, Config.relay_role())
    mesh_port = Keyword.get(opts, :mesh_listen_port, Config.mesh_listen_port())
    ping_interval = Keyword.get(opts, :ping_interval_ms, Config.ping_interval_ms())
    bootstrap_relays = Keyword.get(opts, :bootstrap_relays, Config.mesh_bootstrap_relays())
    ns_server = Keyword.get(opts, :ns_server, Config.ns_server())
    ns_discovery_zone = Keyword.get(opts, :ns_discovery_zone, Config.ns_discovery_zone())
    ns_refresh_interval = Keyword.get(opts, :ns_refresh_interval_ms, Config.ns_refresh_interval_ms())

    socket = case :gen_udp.open(mesh_port, [:binary, {:active, true}]) do
      {:ok, sock} ->
        {:ok, actual_port} = :inet.port(sock)
        Logger.info("ZTLP Mesh listening on port \#{actual_port}")
        sock
      {:error, reason} ->
        Logger.warning("Could not open mesh port \#{mesh_port}: \#{inspect(reason)}, mesh forwarding disabled")
        nil
    end

    our_info = %{node_id: node_id, address: {Config.listen_address(), Config.listen_port()}, role: role}
    ring = HashRing.new([our_info])

    state = %{
      node_id: node_id, role: role, ring: ring, socket: socket,
      mesh_port: mesh_port, ping_interval: ping_interval,
      scores: %{}, ping_sent_at: %{}, probe_states: %{}
    }

    if socket do
      bootstrap(socket, node_id, our_info, bootstrap_relays)
      schedule_ping_sweep(ping_interval)
    end

    if socket && ns_server do
      ns_register_self(node_id, ns_discovery_zone, socket)
      send(self(), :ns_discover)
      schedule_ns_refresh(ns_refresh_interval)
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:route, session_id}, _from, state) do
    candidates = HashRing.get_nodes(state.ring, session_id, 3)
    case candidates do
      [] -> {:reply, :error, state}
      _ ->
        reachable = Enum.filter(candidates, fn c ->
          c.node_id == state.node_id or RelayRegistry.get_health(c.node_id) != :unreachable
        end)
        case reachable do
          [] -> {:reply, :error, state}
          _ ->
            first = hd(reachable)
            if first.node_id == state.node_id do
              {:reply, {:local, :self}, state}
            else
              case PathScore.select_best(reachable, state.scores) do
                {:ok, best} ->
                  if best.node_id == state.node_id do
                    {:reply, {:local, :self}, state}
                  else
                    {:reply, {:ok, best}, state}
                  end
                :error -> {:reply, {:ok, first}, state}
              end
            end
        end
    end
  end

  def handle_call(:get_mesh_status, _from, state) do
    status = %{
      node_id: state.node_id, role: state.role,
      ring_nodes: HashRing.node_count(state.ring),
      known_relays: RelayRegistry.count(), scores: state.scores,
      mesh_port: state.mesh_port, socket_open: state.socket != nil
    }
    {:reply, status, state}
  end

  def handle_call(:node_id, _from, state), do: {:reply, state.node_id, state}

  @impl true
  def handle_cast({:inter_relay_message, data, sender}, state) do
    case InterRelay.handle_message(data, sender) do
      {:ok, decoded} -> {:noreply, handle_decoded_message(decoded, sender, state)}
      {:error, reason} ->
        Logger.debug("Failed to decode inter-relay message from \#{inspect(sender)}: \#{reason}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:udp, _socket, src_ip, src_port, data}, state) do
    sender = {src_ip, src_port}
    case InterRelay.handle_message(data, sender) do
      {:ok, decoded} -> {:noreply, handle_decoded_message(decoded, sender, state)}
      {:error, reason} ->
        Logger.debug("Failed to decode mesh UDP from \#{inspect(sender)}: \#{reason}")
        {:noreply, state}
    end
  end

  def handle_info(:ping_sweep, state) do
    state = do_ping_sweep(state)
    schedule_ping_sweep(state.ping_interval)
    {:noreply, state}
  end

  def handle_info(:ns_discover, state) do
    state = do_ns_discovery(state)
    {:noreply, state}
  end

  def handle_info(:ns_refresh, state) do
    state = do_ns_discovery(state)
    ns_register_self(state.node_id, state.ns_discovery_zone, state.socket)
    schedule_ns_refresh(state.ns_refresh_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: socket}) when socket != nil do
    :gen_udp.close(socket)
    :ok
  end
  def terminate(_reason, _state), do: :ok

  defp handle_decoded_message({:relay_hello, sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received RELAY_HELLO from \#{inspect(sender_node_id)}")
    relay_info = %{node_id: sender_node_id, address: payload.address, role: payload.role}
    RelayRegistry.register(relay_info)
    ring = HashRing.add_node(state.ring, relay_info)
    if state.socket do
      our_info = %{node_id: state.node_id, address: {Config.listen_address(), Config.listen_port()}, role: state.role, capabilities: 0}
      ack_data = InterRelay.encode_hello_ack(our_info)
      {ip, port} = payload.address
      :gen_udp.send(state.socket, ip, port, ack_data)
    end
    %{state | ring: ring}
  end

  defp handle_decoded_message({:relay_hello_ack, sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received RELAY_HELLO_ACK from \#{inspect(sender_node_id)}")
    relay_info = %{node_id: sender_node_id, address: payload.address, role: payload.role}
    RelayRegistry.register(relay_info)
    ring = HashRing.add_node(state.ring, relay_info)
    %{state | ring: ring}
  end

  defp handle_decoded_message({:relay_ping, sender_node_id, _ts, payload}, _sender, state) do
    seq = Map.get(payload, :seq, 0)
    if state.socket do
      metrics = %{active_sessions: ZtlpRelay.SessionRegistry.count(), max_sessions: Config.max_sessions(), uptime_seconds: div(System.monotonic_time(:second), 1)}
      pong_data = InterRelay.encode_pong(state.node_id, metrics, seq)
      case RelayRegistry.lookup(sender_node_id) do
        {:ok, relay} ->
          {ip, port} = relay.address
          :gen_udp.send(state.socket, ip, port, pong_data)
        :error -> Logger.debug("Cannot respond to PING - unknown relay \#{inspect(sender_node_id)}")
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
    load_factor = PathScore.compute_load_factor(payload.active_sessions, payload.max_sessions)
    old_metrics = Map.get(state.scores, sender_node_id, %{rtt_ms: rtt, loss_rate: 0.0, load_factor: 0.0, jitter_ms: 0.0})
    old_rtt = Map.get(old_metrics, :rtt_ms, rtt)
    new_rtt = PathScore.update_rtt(old_rtt, rtt)
    metrics = %{rtt_ms: new_rtt, loss_rate: loss_rate, load_factor: load_factor, jitter_ms: jitter_ms}
    RelayRegistry.update_metrics(sender_node_id, metrics)
    RelayRegistry.touch(sender_node_id)
    RelayRegistry.update_health(sender_node_id, loss_rate: loss_rate, rtt_ms: new_rtt, missed_sweeps: 0, pong_received: true)
    ping_sent_at = Map.delete(state.ping_sent_at, sender_node_id)
    probe_states = Map.put(state.probe_states, sender_node_id, probe_state)
    %{state | scores: Map.put(state.scores, sender_node_id, metrics), ping_sent_at: ping_sent_at, probe_states: probe_states}
  end

  defp handle_decoded_message({:relay_leave, sender_node_id, _ts, _payload}, _sender, state) do
    Logger.info("Relay \#{inspect(sender_node_id)} leaving mesh")
    RelayRegistry.unregister(sender_node_id)
    RelayRegistry.remove_health(sender_node_id)
    ring = HashRing.remove_node(state.ring, sender_node_id)
    scores = Map.delete(state.scores, sender_node_id)
    probe_states = Map.delete(state.probe_states, sender_node_id)
    %{state | ring: ring, scores: scores, probe_states: probe_states}
  end

  defp handle_decoded_message({:relay_forward, _sender_node_id, _ts, %{inner_packet: inner} = payload}, _sender, state) do
    ttl = Map.get(payload, :ttl, InterRelay.default_ttl())
    path = Map.get(payload, :path, [])
    Logger.debug("Received RELAY_FORWARD with #{byte_size(inner)} byte inner packet, TTL=#{ttl}, path_len=#{length(path)}")
    state
  end

  defp handle_decoded_message({:relay_session_sync, _sender_node_id, _ts, payload}, _sender, state) do
    Logger.debug("Received SESSION_SYNC for \#{inspect(payload.session_id)}")
    ZtlpRelay.SessionRegistry.register_session(payload.session_id, payload.peer_a, payload.peer_b)
    state
  end

  defp bootstrap(socket, node_id, our_info, bootstrap_relays) do
    hello = InterRelay.encode_hello(%{node_id: node_id, address: our_info.address, role: our_info[:role] || :all, capabilities: 0})
    Enum.each(bootstrap_relays, fn relay_str ->
      case parse_relay_address(relay_str) do
        {:ok, {host, port}} ->
          case resolve_host(host) do
            {:ok, ip} ->
              :gen_udp.send(socket, ip, port, hello)
              Logger.debug("Sent RELAY_HELLO to \#{relay_str}")
            {:error, reason} -> Logger.warning("Cannot resolve bootstrap relay \#{relay_str}: \#{inspect(reason)}")
          end
        {:error, reason} -> Logger.warning("Invalid bootstrap relay address \#{relay_str}: \#{inspect(reason)}")
      end
    end)
  end

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
          RelayRegistry.update_health(relay.node_id, loss_rate: loss_rate, rtt_ms: old_rtt, missed_sweeps: missed, pong_received: false)
          Map.put(ps_acc, relay.node_id, probe_st)
        else
          ps_acc
        end
      else
        ps_acc
      end
    end)

    {ping_sent_at, probe_states} = Enum.reduce(relays, {state.ping_sent_at, probe_states}, fn relay, {psa, ps} ->
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
        metrics -> Map.put(scores_acc, node_id, Map.merge(metrics, %{loss_rate: loss_rate, jitter_ms: jitter_ms}))
      end
    end)

    %{state | ping_sent_at: ping_sent_at, probe_states: probe_states, scores: scores}
  end

  defp schedule_ping_sweep(interval), do: Process.send_after(self(), :ping_sweep, interval)

  defp new_probe_state, do: %{seq: 0, probes: %{}, rtt_samples: [], missed_sweeps: 0}

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
    probes |> Enum.filter(fn {seq, _} -> seq >= min_seq end) |> Enum.into(%{})
  end

  defp compute_loss_rate(%{probes: probes}) when map_size(probes) == 0, do: 0.0
  defp compute_loss_rate(%{probes: probes}) do
    total = map_size(probes)
    lost = Enum.count(probes, fn {_seq, p} -> p.acked == :lost end)
    pending = Enum.count(probes, fn {_seq, p} -> p.acked == false end)
    resolved = total - pending
    if resolved > 0, do: lost / resolved, else: 0.0
  end

  defp parse_relay_address(str) when is_binary(str) do
    case String.split(str, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} -> {:ok, {host, port}}
          _ -> {:error, :invalid_port}
        end
      _ -> {:error, :invalid_format}
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

  # ── NS Discovery ──────────────────────────────────────────────────

  defp do_ns_discovery(state) do
    case NsClient.discover_relays(state.ns_discovery_zone) do
      {:ok, records} ->
        Enum.each(records, fn record -> process_ns_relay_record(record, state) end)
        state
      {:error, _} -> state
    end
  end

  defp process_ns_relay_record(record, state) do
    data = record.data
    node_id_hex = data[:node_id] || data["node_id"]
    endpoints = data[:endpoints] || data["endpoints"] || []

    if is_nil(node_id_hex) or endpoints == [] do
      :ok
    else
      case Base.decode16(node_id_hex, case: :mixed) do
        {:ok, node_id} when node_id != state.node_id ->
          case parse_first_endpoint(endpoints) do
            {:ok, {host, port}} ->
              case resolve_host(host) do
                {:ok, ip} ->
                  RelayRegistry.register(%{node_id: node_id, address: {ip, port}, role: :all})
                  if state.socket do
                    hello = InterRelay.encode_hello(%{
                      node_id: state.node_id,
                      address: {Config.listen_address(), Config.listen_port()},
                      role: state.role, capabilities: 0})
                    :gen_udp.send(state.socket, ip, port, hello)
                  end
                _ -> :ok
              end
            _ -> :ok
          end
        _ -> :ok
      end
    end
  end

  defp parse_first_endpoint([ep | _]) when is_binary(ep), do: parse_relay_address(ep)
  defp parse_first_endpoint(_), do: {:error, :no_endpoints}

  defp ns_register_self(node_id, zone, socket) do
    mesh_port = case :inet.port(socket) do
      {:ok, p} -> p
      _ -> Config.mesh_listen_port()
    end
    info = %{
      node_id: node_id,
      endpoints: ["127.0.0.1:" <> Integer.to_string(mesh_port)],
      capacity: Config.max_sessions(),
      region: Config.relay_region()
    }
    NsClient.register_self(zone, info)
  end

  defp schedule_ns_refresh(interval) do
    Process.send_after(self(), :ns_refresh, interval)
  end
end
