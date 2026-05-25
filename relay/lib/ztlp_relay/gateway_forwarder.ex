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

  # ETS table name for peer→session lookups. Populated as a write-through
  # index from the in-memory `sessions` map. See `lookup_by_peer/1`.
  @peer_table :ztlp_gateway_peers

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
  @spec pick_gateway_for_service(String.t()) ::
          {:ok, {:inet.ip_address(), non_neg_integer()}} | :error
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

  @doc """
  Look up a forwarded session by peer address (the {ip, port} of either
  the client or the gateway). Returns `{:ok, session_id, other_peer_addr}`
  if the sender is one of the two peers of an established forwarded
  session, otherwise `:error`.

  This is the fast-path used by the UDP listener to forward Noise transport
  packets (which lack ZTLP headers) between peers after the handshake has
  completed. The lookup is an O(1) ETS read with no GenServer hop, so it
  is safe to call on every inbound packet.

  The ETS table `@peer_table` is populated as a write-through index from
  `handle_cast({:register, ...})` and cleaned up alongside the session map.
  """
  @spec lookup_by_peer({:inet.ip_address(), :inet.port_number()}) ::
          {:ok, binary(), {:inet.ip_address(), :inet.port_number()}} | :error
  def lookup_by_peer(sender) do
    case :ets.lookup(@peer_table, sender) do
      [{^sender, session_id, other_peer}] -> {:ok, session_id, other_peer}
      [] -> :error
    end
  end

  # GenServer callbacks

  @doc """
  Compute the 16-byte truncated SHA-256 of a canonicalised service name.

  Mirrors `proto/src/tunnel.rs::encode_service_name` and
  `gateway/lib/ztlp_gateway/packet.ex::service_hash/1` so the relay can
  resolve incoming HELLO `dst_svc_hash` bytes back to the registered
  gateway's `service_name` string. Canonicalisation: ASCII lowercase +
  trailing-dot strip, then SHA-256, then take the first 16 bytes.

  Public so test code can pin the wire encoding without re-implementing it.
  """
  @spec service_hash(String.t()) :: <<_::128>>
  def service_hash(name) when is_binary(name) do
    canon = name |> String.downcase() |> String.trim_trailing(".")
    :crypto.hash(:sha256, canon) |> :binary.part(0, 16)
  end

  @impl true
  def init(_opts) do
    gateways = Config.gateway_addresses()

    if gateways != [] do
      Logger.info(
        "[GatewayForwarder] Gateway forwarding enabled for #{length(gateways)} static gateway(s): #{inspect(gateways)}"
      )
    end

    # Public ETS table for peer→session lookups. Used by the UDP listener
    # to forward post-handshake Noise transport packets (which have no
    # ZTLP header and thus fail the magic check in the pipeline).
    # Layout: {peer_addr, session_id, other_peer_addr}
    :ets.new(@peer_table, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Always schedule cleanup (for sessions and dynamic gateway expiry)
    Process.send_after(self(), :cleanup, 60_000)

    {:ok, %{gateways: gateways, dynamic_gateways: [], sessions: %{}, gateway_index: 0}}
  end

  @impl true
  def handle_cast({:register_dynamic, address, node_id, service_name, ttl}, state) do
    blocked = Config.blocked_gateway_addresses()

    if MapSet.member?(blocked, address) do
      Logger.info(
        "[GatewayForwarder] Blocked gateway registration from #{inspect(address)} " <>
          "(node #{Base.encode16(node_id)}, service=#{service_name}) — on block list"
      )

      # Remove any existing entry for this blocked gateway (decommission cleanup)
      dynamic =
        Enum.reject(state.dynamic_gateways, fn gw ->
          gw.address == address
        end)

      {:noreply, %{state | dynamic_gateways: dynamic}}
    else
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

      # Setup NAT 5-tuple table for transparent 0.0.0.0 bypass via the Elixir relay.
      if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
        :ets.new(:ztlp_forwarded_quic_tuples, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])
      end

      # Indexing tuples explicitly bound exclusively to registered gateways natively.
      :ets.insert(:ztlp_forwarded_quic_tuples, {:gateway_addr, address})

      Logger.info(
        "[GatewayForwarder] Registered dynamic gateway #{Base.encode16(node_id)} " <>
          "service=#{service_name} addr=#{inspect(address)} ttl=#{ttl}s"
      )

      {:noreply, %{state | dynamic_gateways: [new_entry | dynamic]}}
    end
  end

  def handle_cast({:register, session_id, client_addr, gateway_addr}, state) do
    session = %{
      client: client_addr,
      gateway: gateway_addr,
      created_at: System.monotonic_time(:millisecond)
    }

    sessions = Map.put(state.sessions, session_id, session)

    # Write-through to the public ETS peer index so the UDP listener can
    # forward post-handshake Noise transport packets without a GenServer hop.
    # Both directions are inserted so either peer can find the other.
    :ets.insert(@peer_table, {client_addr, session_id, gateway_addr})
    :ets.insert(@peer_table, {gateway_addr, session_id, client_addr})

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
        # Update both the in-memory map and the ETS peer index. Delete the
        # stale client_addr→session entry and write the new one. The gateway
        # side already points at the new client by virtue of the second
        # insert below.
        :ets.delete(@peer_table, session.client)
        :ets.insert(@peer_table, {new_client_addr, session_id, session.gateway})
        :ets.insert(@peer_table, {session.gateway, session_id, new_client_addr})

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

    # No-preference fallback round-robin used by `forward_hello_to_gateway/5`
    # in `udp_listener.ex` when the client's HELLO carries no `dst_svc_hash`
    # (or the all-zero sentinel).
    #
    # SECURITY: filter dynamic registrations to **gateway-prefixed** service
    # names only — `"gw:<zone>"` (V2 zone-keyed form, since v0.30.5) and
    # `"gw-<slug>"` (V1 legacy slug form). Ad-hoc service registrations like
    # `"z2ls-desktop-lrc"` registered from developer desktops would otherwise
    # appear in the round-robin pool and silently misroute tenant traffic to
    # the wrong endpoint. Observed in production 2026-05-25 when a
    # `ztlp connect bootstrap.<zone>` with no --service flag landed on a
    # `z2ls-desktop-lrc` registration at a developer's home IP instead of
    # the tenant gateway.
    #
    # Non-gateway registrations are still reachable via EXPLICIT name/hash
    # through `pick_gateway_for_service/1` — only the no-preference fallback
    # excludes them.
    dynamic_addrs =
      state.dynamic_gateways
      |> Enum.filter(fn gw -> gw.expires_at > now and gateway_service?(gw.service_name) end)
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

    # Wire-decoupling Option C: callers may pass either
    #   * a String — the canonical service name (legacy, still supported), or
    #   * a 16-byte binary — the truncated SHA-256 hash of the canonical
    #     service name (the on-wire `dst_svc_hash`, what `forward_hello_to_gateway`
    #     receives directly from the HELLO packet).
    #
    # Match against registered gateways by re-hashing each registration's
    # `service_name` string and comparing 16-byte hashes when the caller
    # passed a hash, or by direct string comparison when the caller passed
    # a name.
    #
    # See `proto/src/tunnel.rs::encode_service_name` and
    # `gateway/lib/ztlp_gateway/packet.ex::service_hash/1`.
    #
    # v0.29.4 STRICT-ROUTING: when the caller passes an explicit non-zero
    # service intent (real hash OR real name) and NO registered gateway
    # matches, we return `:error` directly instead of round-robining over
    # all other registered tenants. The pre-v0.29.4 fallback was a silent
    # cross-tenant route footgun — a CLI asking for `gw-test-org-2` could
    # land on `gw-hermese2e-1779353410` and render the wrong tenant's
    # Bootstrap UI when the gateway-index happened to point that way.
    #
    # The all-zero 16-byte hash (no-service-preference sentinel) keeps the
    # legacy round-robin fallback. `forward_hello_to_gateway` in
    # `udp_listener.ex` already short-circuits nil/<<0::128>> through
    # `pick_gateway/0`, but we honor it here too for direct internal
    # callers that pass us the sentinel by mistake.
    all_zero_hash? = service_name == <<0::128>>

    # Wire-decoupling Option C + NodeID-pin path (v0.30.10+):
    #
    # The 16-byte `dst_svc_hash` from a HELLO can carry one of two
    # routing intents:
    #
    #   1. **NS-resolved NodeID (authoritative tenant pin).** When
    #      `cmd_connect` in the CLI resolves the target via ZTLP-NS
    #      and gets the gateway's NodeID back, it stamps that raw
    #      16-byte NodeID into `dst_svc_hash` (see
    #      `proto/src/bin/ztlp-cli.rs::cmd_connect`,
    #      `dst_routing_override`). This OVERRIDES the `--service`
    #      stamping because the NS NodeID is the canonical tenant pin.
    #
    #   2. **SHA-256(service_name)[:16].** Legacy / explicit-only-`--service`
    #      path used by clients that didn't resolve via NS or that
    #      pre-date the NodeID-pin code.
    #
    # We must match BOTH. NodeID match takes priority because it's the
    # authoritative pin — a coincidental SHA-256 collision with another
    # tenant's service_name (cryptographically improbable but pinned
    # by a regression test) must not steal the route.
    {nodeid_match_fn, hash_match_fn, name_match_fn} =
      case service_name do
        <<bin::binary-size(16)>> when bit_size(bin) == 128 ->
          {
            fn gw -> gw.node_id == bin end,
            fn gw -> service_hash(gw.service_name) == bin end,
            fn _gw -> false end
          }

        name when is_binary(name) ->
          {
            fn _gw -> false end,
            fn _gw -> false end,
            fn gw -> gw.service_name == name end
          }

        _ ->
          {fn _gw -> false end, fn _gw -> false end, fn _gw -> false end}
      end

    live_gateways =
      state.dynamic_gateways
      |> Enum.filter(fn gw -> gw.expires_at > now end)

    # Priority-ordered lookup: NodeID match first (authoritative), then
    # service-name hash, then exact name string. Each tier returns its
    # unique addresses; we drop to the next tier only if the prior tier
    # found nothing. This ensures a NodeID match wins over a coincidental
    # service-name hash collision.
    service_gateways =
      case Enum.filter(live_gateways, nodeid_match_fn) do
        [_ | _] = nodeid_hits ->
          nodeid_hits |> Enum.map(& &1.address) |> Enum.uniq()

        [] ->
          case Enum.filter(live_gateways, hash_match_fn) do
            [_ | _] = hash_hits ->
              hash_hits |> Enum.map(& &1.address) |> Enum.uniq()

            [] ->
              live_gateways
              |> Enum.filter(name_match_fn)
              |> Enum.map(& &1.address)
              |> Enum.uniq()
          end
      end

    case service_gateways do
      [] ->
        # No live gateway registered for the requested service.
        #
        # If the caller passed the all-zero "no preference" sentinel, keep
        # the legacy round-robin fallback (back-compat for pre-Option-C
        # clients and any direct internal caller using the sentinel).
        #
        # Otherwise — explicit service hash or name with no match — we
        # return `:error` and let the call site surface the failure.
        # The QUIC CLIENT_ROUTE path in `udp_listener.ex` already logs
        # `"rejected: no gateway registered for service=..."` on `:error`;
        # the HELLO `forward_hello_to_gateway` path drops into a half-open
        # session that the client times out on.
        if all_zero_hash? do
          all_fallback =
            case state.gateways do
              [] ->
                state.dynamic_gateways
                |> Enum.filter(fn gw -> gw.expires_at > now end)
                |> Enum.map(fn gw -> gw.address end)
                |> Enum.uniq()

              static ->
                static
            end

          case all_fallback do
            [] ->
              {:reply, :error, state}

            _ ->
              index = rem(state.gateway_index, length(all_fallback))
              gateway = Enum.at(all_fallback, index)
              {:reply, {:ok, gateway}, %{state | gateway_index: index + 1}}
          end
        else
          # Strict path: explicit service requested, no match → :error.
          # Do NOT silently route to a different tenant.
          {:reply, :error, state}
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

    has_dynamic = Enum.any?(state.dynamic_gateways, fn gw -> gw.expires_at > now end)

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
    :ets.delete_all_objects(@peer_table)
    {:reply, :ok, %{state | sessions: %{}, dynamic_gateways: %{}}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now_ms = System.monotonic_time(:millisecond)
    now_s = System.monotonic_time(:second)

    # Remove sessions older than 10 minutes
    max_age_ms = 600_000

    {sessions, stale} =
      state.sessions
      |> Enum.split_with(fn {_id, s} -> now_ms - s.created_at <= max_age_ms end)

    sessions = Map.new(sessions)

    # Purge stale entries from the ETS peer index too. Both directions
    # were inserted in handle_cast({:register, ...}) so both must be removed.
    Enum.each(stale, fn {_id, s} ->
      :ets.delete(@peer_table, s.client)
      :ets.delete(@peer_table, s.gateway)
    end)

    removed_sessions = length(stale)

    if removed_sessions > 0 do
      Logger.debug("[GatewayForwarder] Cleaned up #{removed_sessions} stale forwarded sessions")
    end

    # Remove expired dynamic gateways
    {active, expired} =
      Enum.split_with(state.dynamic_gateways, fn gw -> gw.expires_at > now_s end)

    if expired != [] do
      Logger.info("[GatewayForwarder] Expired #{length(expired)} dynamic gateway registration(s)")
    end

    Process.send_after(self(), :cleanup, 60_000)
    {:noreply, %{state | sessions: sessions, dynamic_gateways: active}}
  end

  # Returns true when the registered service_name looks like a gateway —
  # either the V2 zone-keyed form `"gw:<zone>"` or the V1 slug form
  # `"gw-<slug>"`. Used by `handle_call(:pick_gateway, ...)` (the
  # no-preference fallback) to exclude ad-hoc non-gateway service
  # registrations from the round-robin pool. See the SECURITY comment
  # in `handle_call(:pick_gateway, ...)`.
  defp gateway_service?("gw:" <> _), do: true
  defp gateway_service?("gw-" <> _), do: true
  defp gateway_service?(_), do: false
end
