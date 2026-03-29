defmodule ZtlpGateway.Federation do
  @moduledoc """
  Gateway federation for multi-gateway deployments.

  Discovery: Queries NS for gateway SVC records in the zone.
  Health: Periodic UDP pings between gateways.
  Routing: Routes FRAME_OPEN to the gateway that owns the service.
  Migration: Transfers session state between gateways.

  Wire protocol (gateway-to-gateway, UDP):
  - 0x20 PEER_HELLO: {gateway_id, services[], load_percent}
  - 0x21 PEER_PING: {timestamp}
  - 0x22 PEER_PONG: {timestamp, load_percent}
  - 0x23 SESSION_MIGRATE: {session_state_binary}
  - 0x24 SERVICE_QUERY: {service_name} — "do you have this backend?"
  - 0x25 SERVICE_REPLY: {service_name, available, load}
  """

  use GenServer
  require Logger

  @peer_hello 0x20
  @peer_ping 0x21
  @peer_pong 0x22
  @session_migrate 0x23
  @service_query 0x24
  @service_reply 0x25

  @ping_interval_ms 5_000
  @peer_timeout_ms 15_000
  @discovery_interval_ms 60_000

  defstruct [
    :gateway_id,
    :socket,
    :port,
    :zone,
    :ns_server,
    peers: %{},
    local_services: [],
    service_map: %{},
    ping_timer: nil,
    discovery_timer: nil,
    enabled: false
  ]

  defmodule Peer do
    @moduledoc false
    defstruct [
      :gateway_id,
      :addr,
      :services,
      :load_percent,
      :last_seen,
      :rtt_ms,
      :status
    ]
  end

  # ── Wire‑format constants (exposed for tests) ──

  @doc false
  def opcode_peer_hello, do: @peer_hello
  @doc false
  def opcode_peer_ping, do: @peer_ping
  @doc false
  def opcode_peer_pong, do: @peer_pong
  @doc false
  def opcode_session_migrate, do: @session_migrate
  @doc false
  def opcode_service_query, do: @service_query
  @doc false
  def opcode_service_reply, do: @service_reply

  # ── Public API ──

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "List known peers."
  def peers do
    GenServer.call(__MODULE__, :list_peers)
  end

  @doc "Get the best gateway for a service."
  def route_service(service_name) do
    GenServer.call(__MODULE__, {:route_service, service_name})
  end

  @doc "Check if federation is enabled and active."
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc "Initiate session migration to another gateway."
  def migrate_session(session_id, target_gateway_id) do
    GenServer.call(__MODULE__, {:migrate_session, session_id, target_gateway_id})
  end

  @doc "Get load balancing weights for all gateways serving a service."
  def service_weights(service_name) do
    GenServer.call(__MODULE__, {:service_weights, service_name})
  end

  # ── Pure helpers (public for unit‑testing, @doc false) ──

  @doc false
  def generate_gateway_id do
    :crypto.strong_rand_bytes(16)
  end

  @doc false
  def parse_hello_payload(<<load::8, service_count::8, rest::binary>>) do
    services = parse_service_names(rest, service_count, [])
    {services, load}
  end

  def parse_hello_payload(_), do: {[], 0}

  @doc false
  def parse_service_names(_, 0, acc), do: Enum.reverse(acc)

  def parse_service_names(<<len::8, name::binary-size(len), rest::binary>>, count, acc) do
    parse_service_names(rest, count - 1, [name | acc])
  end

  def parse_service_names(_, _, acc), do: Enum.reverse(acc)

  @doc false
  def rebuild_service_map(peers, _local_services) do
    Enum.reduce(peers, %{}, fn {id, peer}, acc ->
      Enum.reduce(peer.services || [], acc, fn service, inner ->
        Map.update(inner, service, [id], &[id | &1])
      end)
    end)
  end

  @doc false
  def format_addr({ip, port}) when is_tuple(ip) do
    ip_str = ip |> Tuple.to_list() |> Enum.join(".")
    "#{ip_str}:#{port}"
  end

  def format_addr(other), do: inspect(other)

  @doc false
  def encode_hello(gateway_id, load, services) do
    service_data =
      Enum.reduce(services, <<>>, fn name, acc ->
        acc <> <<byte_size(name)::8, name::binary>>
      end)

    <<@peer_hello, gateway_id::binary-16, load::8, length(services)::8, service_data::binary>>
  end

  @doc false
  def encode_ping(timestamp) do
    <<@peer_ping, timestamp::64>>
  end

  @doc false
  def encode_service_query(service_name) do
    <<@service_query, byte_size(service_name)::8, service_name::binary>>
  end

  # ── GenServer callbacks ──

  @impl true
  def init(opts) do
    enabled = Keyword.get(opts, :enabled, federation_enabled?())

    if enabled do
      init_enabled(opts)
    else
      {:ok, %__MODULE__{enabled: false}}
    end
  end

  defp init_enabled(opts) do
    gateway_id = Keyword.get_lazy(opts, :gateway_id, &generate_gateway_id/0)
    port = Keyword.get(opts, :port, federation_port())
    zone = Keyword.get(opts, :zone, service_zone())
    ns = Keyword.get(opts, :ns_server, ns_server())
    services = Keyword.get(opts, :local_services, local_services())

    case :gen_udp.open(port, [:binary, active: true, reuseaddr: true]) do
      {:ok, socket} ->
        short_id =
          gateway_id
          |> Base.encode16(case: :lower)
          |> binary_part(0, 12)

        Logger.info("[Federation] Started gateway_id=#{short_id}... port=#{port}")

        state = %__MODULE__{
          gateway_id: gateway_id,
          socket: socket,
          port: port,
          zone: zone,
          ns_server: ns,
          local_services: services,
          enabled: true
        }

        ping_timer = Process.send_after(self(), :ping_peers, @ping_interval_ms)
        discovery_timer = Process.send_after(self(), :discover_peers, 1_000)

        {:ok, %{state | ping_timer: ping_timer, discovery_timer: discovery_timer}}

      {:error, reason} ->
        Logger.error("[Federation] Failed to open UDP socket: #{inspect(reason)}")
        {:ok, %__MODULE__{enabled: false}}
    end
  end

  @impl true
  def handle_call(:list_peers, _from, state) do
    list =
      state.peers
      |> Map.values()
      |> Enum.map(fn p ->
        %{
          gateway_id: Base.encode16(p.gateway_id, case: :lower),
          addr: format_addr(p.addr),
          services: p.services,
          load: p.load_percent,
          status: p.status,
          rtt_ms: p.rtt_ms,
          last_seen: p.last_seen
        }
      end)

    {:reply, list, state}
  end

  def handle_call({:route_service, service_name}, _from, state) do
    result =
      case Map.get(state.service_map, service_name, []) do
        [] ->
          if Enum.any?(state.local_services, fn {name, _} -> name == service_name end) do
            {:local, state.gateway_id}
          else
            {:error, :no_gateway_available}
          end

        gateway_ids ->
          best =
            gateway_ids
            |> Enum.map(fn id -> {id, Map.get(state.peers, id)} end)
            |> Enum.filter(fn {_, peer} -> peer != nil and peer.status == :healthy end)
            |> Enum.sort_by(fn {_, peer} -> peer.load_percent end)
            |> List.first()

          case best do
            {id, peer} -> {:remote, id, peer.addr}
            nil -> {:error, :no_healthy_gateway}
          end
      end

    {:reply, result, state}
  end

  def handle_call(:status, _from, state) do
    info = %{
      enabled: state.enabled,
      gateway_id:
        if(state.gateway_id, do: Base.encode16(state.gateway_id, case: :lower), else: nil),
      peer_count: map_size(state.peers),
      healthy_peers:
        state.peers |> Map.values() |> Enum.count(&(&1.status == :healthy)),
      local_services: Enum.map(state.local_services, fn {name, _} -> name end)
    }

    {:reply, info, state}
  end

  def handle_call({:migrate_session, session_id, target_gateway_id}, _from, state) do
    case Map.get(state.peers, target_gateway_id) do
      nil ->
        {:reply, {:error, :unknown_peer}, state}

      %{status: :unreachable} ->
        {:reply, {:error, :peer_unreachable}, state}

      peer ->
        payload = <<@session_migrate, session_id::binary>>
        {ip, port} = peer.addr
        :gen_udp.send(state.socket, ip, port, payload)

        short_id =
          target_gateway_id
          |> Base.encode16(case: :lower)
          |> binary_part(0, 12)

        Logger.info("[Federation] Initiated session migration to #{short_id}...")
        {:reply, :ok, state}
    end
  end

  def handle_call({:service_weights, service_name}, _from, state) do
    local_weight =
      if Enum.any?(state.local_services, fn {name, _} -> name == service_name end) do
        [{state.gateway_id, 100}]
      else
        []
      end

    remote_weights =
      state.service_map
      |> Map.get(service_name, [])
      |> Enum.map(fn id -> {id, Map.get(state.peers, id)} end)
      |> Enum.filter(fn {_, peer} -> peer != nil and peer.status == :healthy end)
      |> Enum.map(fn {id, peer} -> {id, max(1, 100 - peer.load_percent)} end)

    {:reply, local_weight ++ remote_weights, state}
  end

  # ── Incoming UDP ──

  @impl true
  def handle_info({:udp, _socket, ip, port, data}, state) do
    state = handle_peer_message(data, {ip, port}, state)
    {:noreply, state}
  end

  # ── Periodic tasks ──

  def handle_info(:ping_peers, state) do
    now = System.monotonic_time(:millisecond)

    Enum.each(state.peers, fn {_id, peer} ->
      ping = encode_ping(now)
      {ip, port} = peer.addr
      :gen_udp.send(state.socket, ip, port, ping)
    end)

    # Expire and update statuses
    peers =
      state.peers
      |> Enum.filter(fn {_id, peer} -> now - peer.last_seen < @peer_timeout_ms end)
      |> Enum.map(fn {id, peer} ->
        age = now - peer.last_seen

        status =
          cond do
            age < @ping_interval_ms * 2 -> :healthy
            age < @peer_timeout_ms -> :degraded
            true -> :unreachable
          end

        {id, %{peer | status: status}}
      end)
      |> Map.new()

    timer = Process.send_after(self(), :ping_peers, @ping_interval_ms)
    {:noreply, %{state | peers: peers, ping_timer: timer}}
  end

  def handle_info(:discover_peers, state) do
    state = discover_peers_from_ns(state)
    timer = Process.send_after(self(), :discover_peers, @discovery_interval_ms)
    {:noreply, %{state | discovery_timer: timer}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Private — message handling ──

  defp handle_peer_message(<<@peer_hello, gateway_id::binary-16, rest::binary>>, addr, state) do
    {services, load} = parse_hello_payload(rest)
    now = System.monotonic_time(:millisecond)

    peer = %Peer{
      gateway_id: gateway_id,
      addr: addr,
      services: services,
      load_percent: load,
      last_seen: now,
      rtt_ms: nil,
      status: :healthy
    }

    peers = Map.put(state.peers, gateway_id, peer)
    service_map = rebuild_service_map(peers, state.local_services)

    short_id =
      gateway_id
      |> Base.encode16(case: :lower)
      |> binary_part(0, 12)

    Logger.info(
      "[Federation] Peer joined: #{short_id}... services=#{inspect(services)}"
    )

    send_hello(state.socket, addr, state)

    %{state | peers: peers, service_map: service_map}
  end

  defp handle_peer_message(<<@peer_ping, timestamp::64>>, {ip, port}, state) do
    load = current_load()
    pong = <<@peer_pong, timestamp::64, load::8>>
    :gen_udp.send(state.socket, ip, port, pong)
    state
  end

  defp handle_peer_message(<<@peer_pong, timestamp::64, load::8>>, addr, state) do
    now = System.monotonic_time(:millisecond)
    rtt = now - timestamp

    peers =
      Enum.map(state.peers, fn {id, peer} ->
        if peer.addr == addr do
          {id, %{peer | rtt_ms: rtt, load_percent: load, last_seen: now, status: :healthy}}
        else
          {id, peer}
        end
      end)
      |> Map.new()

    %{state | peers: peers}
  end

  defp handle_peer_message(
         <<@service_query, len::8, service_name::binary-size(len)>>,
         {ip, port},
         state
       ) do
    available = Enum.any?(state.local_services, fn {name, _} -> name == service_name end)
    load = current_load()

    reply =
      <<@service_reply, len::8, service_name::binary,
        (if available, do: 1, else: 0)::8, load::8>>

    :gen_udp.send(state.socket, ip, port, reply)
    state
  end

  defp handle_peer_message(<<@session_migrate, _session_data::binary>>, _addr, state) do
    Logger.info("[Federation] Received session migration request (not yet implemented)")
    state
  end

  defp handle_peer_message(_unknown, _addr, state), do: state

  # ── Private — helpers ──

  defp send_hello(socket, {ip, port}, state) do
    service_names = Enum.map(state.local_services, fn {name, _} -> name end)
    payload = encode_hello(state.gateway_id, current_load(), service_names)
    :gen_udp.send(socket, ip, port, payload)
  end

  defp discover_peers_from_ns(state) do
    # Placeholder — in production, query NS for gateway SVC records
    state
  end

  defp current_load do
    min(100, div(:erlang.system_info(:process_count) * 100, 262_144))
  end

  defp federation_enabled? do
    System.get_env("ZTLP_GATEWAY_FEDERATION_ENABLED") == "true"
  end

  defp federation_port do
    case System.get_env("ZTLP_GATEWAY_FEDERATION_PORT") do
      nil -> 23_098
      val -> String.to_integer(val)
    end
  end

  defp service_zone do
    System.get_env("ZTLP_GATEWAY_SERVICE_ZONE") || "ztlp.local"
  end

  defp ns_server do
    System.get_env("ZTLP_NS_SERVER")
  end

  defp local_services do
    case System.get_env("ZTLP_GATEWAY_SERVICE_NAMES") do
      nil ->
        []

      names ->
        names
        |> String.split(",")
        |> Enum.map(&{String.trim(&1), nil})
    end
  end
end
