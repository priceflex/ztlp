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

  @type state :: %{
          gateways: [{:inet.ip_address(), non_neg_integer()}],
          sessions: %{binary() => gateway_session()},
          gateway_index: non_neg_integer()
        }

  # Client API

  @doc "Start the gateway forwarder."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Check if gateway forwarding is enabled."
  @spec enabled?() :: boolean()
  def enabled? do
    Config.gateway_addresses() != []
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
  Pick a gateway address to forward to (round-robin).
  Returns {:ok, {ip, port}} or :error if no gateways configured.
  """
  @spec pick_gateway() :: {:ok, {:inet.ip_address(), non_neg_integer()}} | :error
  def pick_gateway do
    GenServer.call(__MODULE__, :pick_gateway)
  end

  @doc "Count of active forwarded sessions."
  @spec count() :: non_neg_integer()
  def count do
    GenServer.call(__MODULE__, :count)
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    gateways = Config.gateway_addresses()

    if gateways != [] do
      Logger.info(
        "[GatewayForwarder] Gateway forwarding enabled for #{length(gateways)} gateway(s): #{inspect(gateways)}"
      )
    end

    # Schedule periodic cleanup of stale sessions
    if gateways != [] do
      Process.send_after(self(), :cleanup, 60_000)
    end

    {:ok, %{gateways: gateways, sessions: %{}, gateway_index: 0}}
  end

  @impl true
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

  @impl true
  def handle_call({:lookup, session_id}, _from, state) do
    case Map.get(state.sessions, session_id) do
      nil -> {:reply, :error, state}
      session -> {:reply, {:ok, session}, state}
    end
  end

  def handle_call(:pick_gateway, _from, %{gateways: []} = state) do
    {:reply, :error, state}
  end

  def handle_call(:pick_gateway, _from, state) do
    index = rem(state.gateway_index, length(state.gateways))
    gateway = Enum.at(state.gateways, index)
    {:reply, {:ok, gateway}, %{state | gateway_index: index + 1}}
  end

  def handle_call(:count, _from, state) do
    {:reply, map_size(state.sessions), state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = System.monotonic_time(:millisecond)
    # Remove sessions older than 10 minutes
    max_age_ms = 600_000

    sessions =
      state.sessions
      |> Enum.reject(fn {_id, s} -> now - s.created_at > max_age_ms end)
      |> Map.new()

    removed = map_size(state.sessions) - map_size(sessions)

    if removed > 0 do
      Logger.debug("[GatewayForwarder] Cleaned up #{removed} stale forwarded sessions")
    end

    Process.send_after(self(), :cleanup, 60_000)
    {:noreply, %{state | sessions: sessions}}
  end
end
