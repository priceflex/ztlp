defmodule ZtlpRelay.GatewayForwarder do
  @moduledoc """
  Forwards ZTLP handshake packets between clients and gateways.

  When a relay has configured gateways (`ZTLP_RELAY_GATEWAYS`), HELLO packets
  from clients are forwarded to the gateway. The gateway's response (HELLO_ACK)
  is forwarded back to the client through the relay. This enables clients behind
  UDP-hostile NATs to complete Noise_XX handshakes with gateways they can't
  reach directly.

  ## Session Lifecycle

  1. Client sends HELLO to relay
  2. Relay forwards HELLO to gateway (peer_a = client, peer_b = gateway)
  3. Gateway responds with HELLO_ACK to relay
  4. Relay forwards HELLO_ACK back to client
  5. Client sends HANDSHAKE_FINISH to relay → forwarded to gateway
  6. All subsequent data packets are relayed bidirectionally

  This is transparent to both client and gateway — the relay acts as a
  packet-level forwarder. The Noise_XX handshake and encrypted data are
  never decrypted by the relay (zero-trust property preserved).
  """

  use GenServer

  require Logger

  alias ZtlpRelay.Config

  @type gateway_session :: %{
          client: {:inet.ip_address(), non_neg_integer()},
          gateway: {:inet.ip_address(), non_neg_integer()},
          created_at: integer()
        }

  @type dynamic_gateway :: %{
          address: {:inet.ip_address(), non_neg_integer()},
          node_id: binary(),
          service_name: String.t(),
          expires_at: integer()
        }

  @type state :: %{
          gateways: [{:inet.ip_address(), non_neg_integer()}],
          dynamic_gateways: [dynamic_gateway()],
          sessions: %{binary() => gateway_session()},
          gateway_index: non_neg_integer()
        }

  # Client API

  @doc "Start the gateway forwarder."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if gateway forwarding is enabled.
  Returns true if static gateways are configured OR if any dynamic gateways
  are registered (the forwarder process must be running).
  """
  @spec enabled?() :: boolean()
  def enabled? do
    case GenServer.whereis(__MODULE__) do
      nil ->
        Config.gateway_addresses() != []

      _pid ->
        GenServer.call(__MODULE__, :enabled?)
    end
  end

  @doc """
  Register a forwarded session. Called when a HELLO is forwarded to a gateway.
  Maps the session_id to {client_addr, gateway_addr}.
  """
  @spec register_forwarded_session(binary(), {atom(), integer()}, {atom(), integer()}) :: :ok
  def register_forwarded_session(session_id, client_addr, gateway_addr) do
    GenServer.cast(__MODULE__, {:register, session_id, client_addr, gateway_addr})
  end

  @doc """
  Look up a forwarded session by session_id.
  Returns {:ok, %{client: addr, gateway: addr}} or :error.
  """
  @spec lookup(binary()) :: {:ok, gateway_session()} | :error
  def lookup(session_id) do
    GenServer.call(__MODULE__, {:lookup, session_id})
  end

  @doc """
  Update the client address for a forwarded session (NAT rebinding).
  Called when a client's UDP source port changes mid-session.
  """
  @spec update_client_addr(binary(), {:inet.ip_address(), non_neg_integer()}) :: :ok
  def update_client_addr(session_id, new_client_addr) do
    GenServer.cast(__MODULE__, {:update_client, session_id, new_client_addr})
  end

  @doc """
  Pick a gateway address to forward to (round-robin).
  Returns {:ok, {ip, port}} or :error if no gateways configured.
  """
  @spec pick_gateway() :: {:ok, {:inet.ip_address(), non_neg_integer()}} | :error
  def pick_gateway do
    GenServer.call(__MODULE__, :pick_gateway)
  end

  @doc """
  Pick a gateway that handles the given service name.
  Prefers dynamic gateways registered for this service; falls back to
  static gateways if no dynamic match. Returns :error if none available.
  """
  @spec pick_gateway_for_service(String.t()) :: {:ok, {:inet.ip_address(), non_neg_integer()}} | :error
  def pick_gateway_for_service(service_name) do
    GenServer.call(__MODULE__, {:pick_gateway_for_service, service_name})
  end

  @doc """
  Register a dynamically-discovered gateway.
  Called when the relay receives a GATEWAY_REGISTER packet.
  The address is the source address of the UDP packet (works behind NAT).
  """
  @spec register_dynamic_gateway(
          {:inet.ip_address(), non_neg_integer()},
          binary(),
          String.t(),
          non_neg_integer()
        ) :: :ok
  def register_dynamic_gateway(address, node_id, service_name, ttl) do
    GenServer.cast(__MODULE__, {:register_dynamic, address, node_id, service_name, ttl})
  end

  @doc "List currently registered dynamic gateways."
  @spec dynamic_gateways() :: [dynamic_gateway()]
  def dynamic_gateways do
    GenServer.call(__MODULE__, :dynamic_gateways)
  end

  @doc "Count of active forwarded sessions."
  @spec count() :: non_neg_integer()
  def count do
    GenServer.call(__MODULE__, :count)
  end

  @doc """
  Returns the set of all known gateway IP addresses (both static config
  and dynamically registered). Used by the relay to recognize packets from
  gateways whose source IP differs from the registered peer_b (e.g., AWS
  VPC internal IP vs public Elastic IP).
  """
  @spec known_gateway_ips() :: MapSet.t(:inet.ip_address())
  def known_gateway_ips do
    case GenServer.whereis(__MODULE__) do
      nil ->
        # Not started — fall back to static config
        Config.gateway_addresses()
        |> Enum.map(fn {ip, _port} -> ip end)
        |> MapSet.new()

      _pid ->
        GenServer.call(__MODULE__, :known_gateway_ips)
    end
  end

  @doc "Clear all dynamic gateways and forwarded sessions (for testing)."
  @spec clear_all() :: :ok
  def clear_all do
    GenServer.call(__MODULE__, :clear_all)
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    gateways = Config.gateway_addresses()

    if gateways != [] do
      Logger.info(
        "[GatewayForwarder] Gateway forwarding enabled for #{length(gateways)} static gateway(s): #{inspect(gateways)}"
      )
    end

    # Always schedule cleanup (for sessions and dynamic gateway expiry)
    Process.send_after(self(), :cleanup, 60_000)

    {:ok, %{gateways: gateways, dynamic_gateways: [], sessions: %{}, gateway_index: 0}}
  end

  @impl true
  def handle_cast({:register_dynamic, address, node_id, service_name, ttl}, state) do
    now = System.monotonic_time(:second)
    expires_at = now + ttl

    # Remove any existing entry for this node_id + service_name, then add fresh
    dynamic =
      Enum.reject(state.dynamic_gateways, fn gw ->
        gw.node_id == node_id and gw.service_name == service_name
      end)

    new_entry = %{
      address: address,
      node_id: node_id,
      service_name: service_name,
      expires_at: expires_at
    }

    Logger.info(
      "[GatewayForwarder] Registered dynamic gateway #{Base.encode16(node_id)} " <>
        "service=#{service_name} addr=#{inspect(address)} ttl=#{ttl}s"
    )

    {:noreply, %{state | dynamic_gateways: [new_entry | dynamic]}}
  end

  def handle_cast({:register, session_id, client_addr, gateway_addr}, state) do
    session = %{
      client: client_addr,
      gateway: gateway_addr,
      created_at: System.monotonic_time(:millisecond)
    }

    sessions = Map.put(state.sessions, session_id, session)

    Logger.debug(
      "[GatewayForwarder] Registered forwarded session #{Base.encode16(session_id)}: " <>
        "client=#{inspect(client_addr)} gateway=#{inspect(gateway_addr)}"
    )

    {:noreply, %{state | sessions: sessions}}
  end

  def handle_cast({:update_client, session_id, new_client_addr}, state) do
    case Map.get(state.sessions, session_id) do
      nil ->
        {:noreply, state}

      session ->
        updated = %{session | client: new_client_addr}
        {:noreply, %{state | sessions: Map.put(state.sessions, session_id, updated)}}
    end
  end

  @impl true
  def handle_call({:lookup, session_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil -> {:reply, :error, state}
      session -> {:reply, {:ok, session}, state}
    end
  end

  def handle_call(:pick_gateway, _from, state) do
    now = System.monotonic_time(:second)

    # Combine static gateways with non-expired dynamic gateway addresses
    dynamic_addrs =
      state.dynamic_gateways
      |> Enum.filter(fn gw -> gw.expires_at > now end)
      |> Enum.map(fn gw -> gw.address end)
      |> Enum.uniq()

    all_gateways = state.gateways ++ dynamic_addrs

    case all_gateways do
      [] ->
        {:reply, :error, state}

      _ ->
        index = rem(state.gateway_index, length(all_gateways))
        gateway = Enum.at(all_gateways, index)
        {:reply, {:ok, gateway}, %{state | gateway_index: index + 1}}
    end
  end

  def handle_call({:pick_gateway_for_service, service_name}, _from, state) do
    now = System.monotonic_time(:second)

    # Find dynamic gateways registered for this specific service
    service_gateways =
      state.dynamic_gateways
      |> Enum.filter(fn gw -> gw.expires_at > now and gw.service_name == service_name end)
      |> Enum.map(fn gw -> gw.address end)
      |> Enum.uniq()

    case service_gateways do
      [] ->
        # No dynamic gateway for this service — fall back to static gateways
        case state.gateways do
          [] ->
            {:reply, :error, state}

          _ ->
            index = rem(state.gateway_index, length(state.gateways))
            gateway = Enum.at(state.gateways, index)
            {:reply, {:ok, gateway}, %{state | gateway_index: index + 1}}
        end

      _ ->
        index = rem(state.gateway_index, length(service_gateways))
        gateway = Enum.at(service_gateways, index)
        {:reply, {:ok, gateway}, %{state | gateway_index: index + 1}}
    end
  end

  def handle_call(:dynamic_gateways, _from, state) do
    {:reply, state.dynamic_gateways, state}
  end

  def handle_call(:enabled?, _from, state) do
    now = System.monotonic_time(:second)

    has_dynamic =
      Enum.any?(state.dynamic_gateways, fn gw -> gw.expires_at > now end)

    {:reply, state.gateways != [] or has_dynamic, state}
  end

  def handle_call(:count, _from, state) do
    {:reply, map_size(state.sessions), state}
  end

  def handle_call(:known_gateway_ips, _from, state) do
    now = System.monotonic_time(:second)

    # Static gateway IPs
    static_ips = Enum.map(state.gateways, fn {ip, _port} -> ip end)

    # Dynamic (non-expired) gateway IPs
    dynamic_ips =
      state.dynamic_gateways
      |> Enum.filter(fn gw -> gw.expires_at > now end)
      |> Enum.map(fn gw -> elem(gw.address, 0) end)

    {:reply, MapSet.new(static_ips ++ dynamic_ips), state}
  end

  def handle_call(:clear_all, _from, state) do
    {:reply, :ok, %{state | sessions: %{}, dynamic_gateways: %{}}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now_ms = System.monotonic_time(:millisecond)
    now_s = System.monotonic_time(:second)

    # Remove sessions older than 10 minutes
    max_age_ms = 600_000

    sessions =
      state.sessions
      |> Enum.reject(fn {_id, s} -> now_ms - s.created_at > max_age_ms end)
      |> Map.new()

    removed_sessions = map_size(state.sessions) - map_size(sessions)

    if removed_sessions > 0 do
      Logger.debug("[GatewayForwarder] Cleaned up #{removed_sessions} stale forwarded sessions")
    end

    # Remove expired dynamic gateways
    {active, expired} =
      Enum.split_with(state.dynamic_gateways, fn gw -> gw.expires_at > now_s end)

    if expired != [] do
      Logger.info(
        "[GatewayForwarder] Expired #{length(expired)} dynamic gateway registration(s)"
      )
    end

    Process.send_after(self(), :cleanup, 60_000)
    {:noreply, %{state | sessions: sessions, dynamic_gateways: active}}
  end
end
