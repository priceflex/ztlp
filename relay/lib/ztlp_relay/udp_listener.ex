defmodule ZtlpRelay.UdpListener do
  @moduledoc """
  GenServer wrapping `:gen_udp` in active mode.

  Binds to the configured ZTLP port (default 23095 = 0x5A37) and processes
  incoming UDP packets through the admission pipeline.

  On packet receipt:
  1. Run through the three-layer pipeline
  2. If pass: look up session, forward to other peer via `:gen_udp.send`
  3. If handshake (HELLO/HELLO_ACK): handled for future session creation
  4. If VIP-proxied service: dispatch to VipTcpTerminator for TCP termination

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
    Packet,
    VipTcpTerminator
  }

  # v0.29.3: how often the GenServer sweeps stale `{:client_map, ...}` entries
  # out of `:ztlp_forwarded_quic_tuples`. Entries older than @client_route_ttl_ms
  # are deleted on each tick. The TTL itself is long enough to cover steady-state
  # tunnels through a periodic-keepalive QUIC config (see proto/src/quic_transport.rs);
  # tunnels with fresh traffic are not touched because `do_install_client_route`
  # refreshes the `inserted_at` whenever a new CLIENT_ROUTE arrives.
  @client_route_sweep_interval_ms 60_000
  @client_route_ttl_ms 300_000

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

        # v0.29.3: kick off the periodic stale-client-map sweeper. We send the
        # first tick after the full interval (not immediately) so test harnesses
        # that don't care about the sweeper aren't surprised by a sweep fire
        # during setup.
        Process.send_after(self(), :sweep_client_routes, @client_route_sweep_interval_ms)

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
  def handle_info({:udp, socket, src_ip, src_port, data}, state) do
    sender = {src_ip, src_port}

    # ZTLP control frames addressed TO the relay itself must NEVER be
    # swallowed by the fast peer-table forward below, even when the
    # sender's 5-tuple happens to match the gateway side of an
    # established forwarded session. Without this gate, gateway
    # heartbeats sent from the same `{ip, port}` the gateway used for
    # an earlier HELLO_ACK get blind-forwarded to the client and the
    # gateway silently tombstones out of the relay's registration table
    # after one TTL.
    #
    # We match the EXACT control-type bytes the relay handles
    # (0x0A GATEWAY_REGISTER, 0x0B CLIENT_ROUTE, 0x0E GATEWAY_REGISTER_V2,
    # 0x0F CLIENT_ROUTE_V2) rather than any `0x5A 0x37 0x??` prefix.
    # The wider prefix match would have a 1-in-65536 chance of false-
    # positiving on legitimate Noise transport ciphertext whose first
    # two bytes happen to be `5A 37`, which on a busy tunnel translates
    # to real packet loss. Keep this list in sync with the type-byte
    # branches in the L1 classifier below (search for `0x5A, 0x37,`).
    # Any new control type added there MUST also be added here.
    #
    # The QUIC fast-5-tuple bypass branch below already has the same
    # protection (search `is_ztlp_control_frame`); this is the matching
    # protection for the post-handshake Noise-transport forwarder.
    #
    # Regression test: `heartbeat_after_session_test.exs`.
    # Discovered 2026-05-28 during the v0.34.0 end-to-end walkthrough
    # — the bug is latent since v0.29 (commit bf687ec) but only
    # manifests after a client connects and then the gateway tries to
    # send its next heartbeat from the same 5-tuple.
    is_ztlp_control_frame =
      case data do
        <<0x5A, 0x37, type, _rest::binary>> when type in [0x0A, 0x0B, 0x0E, 0x0F] -> true
        _ -> false
      end

    # First attempt to route known data flows dynamically
    is_data_forwarded =
      if is_ztlp_control_frame do
        false
      else
        GatewayForwarder.lookup_by_peer(sender)
        |> case do
          {:ok, _session_id, other_peer} ->
            :gen_udp.send(socket, elem(other_peer, 0), elem(other_peer, 1), data)
            ZtlpRelay.Stats.increment(:forwarded)
            true

          :error ->
            false
        end
      end

    # ------------------------------------------------------------------
    # QUIC fast 5-tuple bypass — STRICTLY gated.
    #
    # This path only fires when an explicit `{:client_map, sender}`
    # mapping already exists in `:ztlp_forwarded_quic_tuples`. There is
    # NO fallback "guess the gateway" branch and NO ALPN-byte regex
    # parsing — those approaches were tried and rejected because they
    # mangled legacy Noise-UDP traffic (commit 548fc64 regression).
    #
    # The mapping is installed by a future ZTLP control frame
    # (FRAME_CLIENT_ROUTE) that the client sends BEFORE its first QUIC
    # INITIAL packet. Until that frame is implemented, this block is
    # effectively dormant for client→gateway flow but still handles
    # gateway→client return traffic for any pre-existing mapping.
    #
    # Ordering: this runs BEFORE legacy L1 validation (handle_packet/3),
    # so it MUST be conservative — any false positive here will
    # silently drop legitimate Noise-UDP packets.
    # ------------------------------------------------------------------
    is_quic_forwarded =
      if not is_data_forwarded and
           :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined do
        case :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender}) do
          [{{:client_map, ^sender}, {{gw_ip, gw_port}, _inserted_at}}] ->
            # Forward client → mapped gateway. We deliberately do NOT inspect
            # the payload here — the whole point of the QUIC bypass is that
            # the relay forwards opaque QUIC bytes without parsing them.
            #
            # v0.29.3: refresh `inserted_at` on every forwarded packet so the
            # periodic sweeper doesn't evict a long-lived active tunnel. ETS
            # `:set` `:ets.update_element` is atomic and cheap; this is the
            # idiomatic "touch" pattern.
            now_ms = System.monotonic_time(:millisecond)

            :ets.update_element(
              :ztlp_forwarded_quic_tuples,
              {:client_map, sender},
              {2, {{gw_ip, gw_port}, now_ms}}
            )

            :gen_udp.send(socket, gw_ip, gw_port, data)
            true

          # v0.29.2 compat shim: in-flight entries written under the
          # pre-v0.29.3 schema (`gw_addr` directly, without `inserted_at`)
          # are still honoured for one TTL window after upgrade so we do
          # not break live tunnels on relay restart. New inserts always
          # use the tagged shape; the sweeper will GC the old ones.
          [{{:client_map, ^sender}, {gw_ip, gw_port}}] when is_tuple({gw_ip, gw_port}) ->
            :gen_udp.send(socket, gw_ip, gw_port, data)
            true

          [] ->
            # No client mapping. Check if `sender` is a registered gateway
            # returning traffic to a known client. We look up the reverse
            # mapping ({:client_map, _} -> sender) to find the client peer.
            #
            # CRITICAL: We must NEVER reverse-forward ZTLP control frames
            # (GATEWAY_REGISTER 0x5A 0x37 0x06, CLIENT_ROUTE 0x5A 0x37 0x0B,
            # etc.) because those packets are addressed TO the relay itself.
            # If we naively forward them based on the gateway's 5-tuple
            # matching some stale `{:client_map, _}` entry, the gateway's
            # registration heartbeat gets stolen and the gateway tombstones
            # out of the relay's state after one TTL. This was a v0.29.0
            # regression — fixed in v0.29.1 by gating the reverse forward
            # on the data NOT starting with a known control-frame magic.
            #
            # The bytes are filtered, not just the gw-class — any future
            # frame type that uses the 0x5A 0x37 prefix is automatically
            # protected.
            is_ztlp_control_frame =
              case data do
                <<0x5A, 0x37, _type, _rest::binary>> -> true
                _ -> false
              end

            cond do
              is_ztlp_control_frame ->
                # Fall through to legacy classifier so handle_gateway_register/
                # handle_client_route can do their thing.
                false

              true ->
                # v0.29.3: when multiple client_map entries point at the same
                # gateway 5-tuple (which happens whenever the same client host
                # has connected before from a different ephemeral UDP port —
                # the old entries don't auto-clean), we MUST pick the most
                # recently installed one. ETS `:set` `match_object` returns
                # entries in arbitrary hash-bucket order, so the naive `[head|_]`
                # pattern routes gateway-→-client responses to dead ephemeral
                # ports under load. Symptom: QUIC handshake completes on the
                # gateway side but never converges on the client (the response
                # was misrouted), so the user sees "error: connection error:
                # timed out" right after "CLIENT_ROUTE sent". See v0.29.3
                # release notes and `hermes_session_handoff.md` for the full
                # diagnosis.
                matches =
                  :ets.match_object(
                    :ztlp_forwarded_quic_tuples,
                    {{:client_map, :"$1"}, {sender, :"$2"}}
                  )

                pick =
                  matches
                  |> Enum.reduce(nil, fn
                    {{:client_map, client_addr}, {^sender, inserted_at}}, nil ->
                      {client_addr, inserted_at}

                    {{:client_map, client_addr}, {^sender, inserted_at}}, {_, best_at} = _best
                    when inserted_at > best_at ->
                      {client_addr, inserted_at}

                    _, best ->
                      best
                  end)

                # Legacy schema fallback (entries without inserted_at) — same
                # tail-pick behaviour as before so unupgraded entries still
                # route, but ONLY when no tagged entry is present.
                pick =
                  case pick do
                    nil ->
                      case :ets.match_object(
                             :ztlp_forwarded_quic_tuples,
                             {{:client_map, :_}, sender}
                           ) do
                        [{{:client_map, client_addr}, ^sender} | _] ->
                          {client_addr, 0}

                        _ ->
                          nil
                      end

                    other ->
                      other
                  end

                case pick do
                  {{c_ip, c_port}, _inserted_at} ->
                    :gen_udp.send(socket, c_ip, c_port, data)
                    true

                  _ ->
                    # Sender is neither a mapped client nor a gateway with an
                    # active client. Fall through to legacy L1 validation.
                    false
                end
            end
        end
      else
        false
      end

    if not is_data_forwarded and not is_quic_forwarded do
      # L1 validation
      case data do
        <<0x5A, 0x37, 0x0A, rest::binary>> ->
          handle_gateway_register(rest, sender)

        <<0x5A, 0x37, 0x0B, rest::binary>> ->
          handle_client_route(rest, sender, state)

        # V2 wire frames (Task #2 Phase 1.5) — carry an explicit zone_id
        # field so per-zone HMAC verification doesn't rely on the V1
        # `gw-<zone>` service-name convention. See
        # `docs/per_zone_hmac_design.md` § "Wire format" for the byte
        # layout. Operators running per-zone secrets should migrate
        # senders to these frames; V1 frames remain accepted indefinitely
        # via the legacy/service-name-derived zone path.
        <<0x5A, 0x37, 0x0E, rest::binary>> ->
          handle_gateway_register_v2(rest, sender)

        <<0x5A, 0x37, 0x0F, rest::binary>> ->
          handle_client_route_v2(rest, sender, state)

        _ ->
          handle_packet(data, sender, state)
      end
    end

    {:noreply, state}
  end

  def handle_info(:sweep_client_routes, state) do
    # v0.29.3: drop `{:client_map, _}` entries that haven't been refreshed by a
    # fresh CLIENT_ROUTE within @client_route_ttl_ms. Tunnels with active
    # traffic don't need a refresh — QUIC keepalives (see quic_transport.rs)
    # keep the path warm, and `do_install_client_route` updates `inserted_at`
    # whenever the client reconnects. This sweep only catches genuinely-dead
    # entries from old ephemeral source ports that the OS abandoned.
    swept =
      if :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined do
        cutoff = System.monotonic_time(:millisecond) - @client_route_ttl_ms

        :ets.select_delete(
          :ztlp_forwarded_quic_tuples,
          [
            {
              {{:client_map, :"$1"}, {:"$2", :"$3"}},
              [{:<, :"$3", cutoff}],
              [true]
            }
          ]
        )
      else
        0
      end

    if swept > 0 do
      Logger.info("[UdpListener] swept #{swept} stale client_map entries")
    end

    Process.send_after(self(), :sweep_client_routes, @client_route_sweep_interval_ms)
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
  #
  # HMAC verification flows through `ZtlpRelay.HmacSecrets`, which
  # implements the per-zone secret table layered over the legacy
  # single-secret fallback. For V1 frames (this handler), the zone id
  # is derived from the service_name by stripping the `gw-` prefix
  # — operators running per-zone secrets should migrate to V2 frames
  # (type byte `0x0E`) once that wire change lands. Until then a
  # deprecation warning is emitted when a per-zone secret path is hit
  # via V1.
  #
  # See `docs/per_zone_hmac_design.md` for the full design.
  defp handle_gateway_register(
         <<node_id::binary-size(16), service_raw::binary-size(16), ttl::32, timestamp::64,
           hmac::binary-size(32)>>,
         sender
       ) do
    service_name =
      service_raw |> :binary.bin_to_list() |> Enum.take_while(&(&1 != 0)) |> to_string()

    zone_id = derive_zone_from_service(service_name)
    signed_data = <<0x0A, node_id::binary, service_raw::binary, ttl::32, timestamp::64>>

    case ZtlpRelay.HmacSecrets.verify_with_policy(zone_id, signed_data, hmac) do
      {:ok, :primary} ->
        log_v1_deprecation_if_zone_keyed(zone_id, sender)
        guard_timestamp_then_register(sender, node_id, service_name, ttl, timestamp)

      {:ok, :grace} ->
        log_v1_deprecation_if_zone_keyed(zone_id, sender)

        Logger.info(
          "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} verified " <>
            "with grace key — sender should upgrade to current primary key."
        )

        guard_timestamp_then_register(sender, node_id, service_name, ttl, timestamp)

      {:ok, :legacy} ->
        Logger.warning(
          "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} accepted via " <>
            "legacy ZTLP_RELAY_REGISTRATION_SECRET. Migrate to per-zone secret " <>
            "ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)}."
        )

        guard_timestamp_then_register(sender, node_id, service_name, ttl, timestamp)

      {:ok, :unverified_dev} ->
        Logger.debug(
          "[UdpListener] Accepting unverified GATEWAY_REGISTER from #{inspect(sender)} (mode=dev)"
        )

        do_register_gateway(sender, node_id, service_name, ttl)

      {:ok, :unverified_staging} ->
        Logger.warning(
          "[UdpListener] [STAGING] Accepting unverified GATEWAY_REGISTER from " <>
            "#{inspect(sender)} service=#{service_name} zone=#{zone_id} — " <>
            "configure ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "before promoting to prod."
        )

        do_register_gateway(sender, node_id, service_name, ttl)

      {:error, :bad_hmac} ->
        Logger.warning(
          "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} rejected: invalid HMAC " <>
            "(zone=#{zone_id})"
        )

      {:error, :no_secret_configured_prod} ->
        Logger.error(
          "[UdpListener] [PROD] GATEWAY_REGISTER from #{inspect(sender)} REJECTED: " <>
            "no secret configured for zone=#{zone_id}. " <>
            "Set ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "and restart, or downgrade ZTLP_RELAY_HMAC_MODE to staging/dev."
        )
    end
  end

  # Packet too short or malformed
  defp handle_gateway_register(_data, sender) do
    Logger.warning("[UdpListener] Malformed GATEWAY_REGISTER from #{inspect(sender)}")
  end

  # Derive the per-zone key id from a service_name. V1 frames don't carry
  # an explicit zone field, so we use the service-name convention:
  # `gw-<zone>` → `<zone>`. V2-style `gw:<zone>` is also recognized (used
  # when a client supplies the new collision-safe routing key in a
  # CLIENT_ROUTE frame; see docs/plans/2026-05-24-zone-keyed-gateway-
  # register-IMPL.md). Services that don't match either convention use
  # their full service_name as the zone id, which means each such service
  # gets its own slot in the per-zone secret table.
  defp derive_zone_from_service("gw:" <> rest), do: rest
  defp derive_zone_from_service("gw-" <> rest), do: rest
  defp derive_zone_from_service(other), do: other

  # Only log the V1 deprecation when the verification used a per-zone
  # key (legacy + dev/staging unverified paths don't trigger this).
  defp log_v1_deprecation_if_zone_keyed(zone_id, sender) do
    if ZtlpRelay.HmacSecrets.verifying_secrets(zone_id) != [] do
      Logger.info(
        "[UdpListener] V1 GATEWAY_REGISTER from #{inspect(sender)} verified " <>
          "against per-zone key for zone=#{zone_id}. Migrate sender to V2 " <>
          "frame (type 0x0E) once available — see docs/per_zone_hmac_design.md."
      )
    end
  end

  defp guard_timestamp_then_register(sender, node_id, service_name, ttl, timestamp) do
    now = System.system_time(:second)

    if abs(now - timestamp) <= 300 do
      do_register_gateway(sender, node_id, service_name, ttl)
    else
      Logger.warning(
        "[UdpListener] GATEWAY_REGISTER from #{inspect(sender)} rejected: timestamp too old " <>
          "(delta=#{now - timestamp}s)"
      )
    end
  end

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
  # GATEWAY_REGISTER_V2 (FRAME_GATEWAY_REGISTER_V2 / 0x5A 0x37 0x0E)
  # ---------------------------------------------------------------------------
  #
  # Wire format (after `0x5A 0x37 0x0E` magic+type already stripped):
  #
  #   [1  zone_len]
  #   [zone_len  zone_id]              (1..=63 bytes, RFC1035 DNS label)
  #   [16 node_id]
  #   [16 service_padded]              (zero-padded ASCII, matches V1 layout)
  #   [4  ttl]                         (big-endian u32)
  #   [8  timestamp]                   (big-endian unix seconds)
  #   [32 hmac]                        (HMAC-SHA256)
  #
  # Signed material (what HMAC-SHA256 is computed over):
  #
  #   0x0E || zone_len (1B) || zone_id || node_id || service_padded
  #        || ttl (4B) || timestamp (8B)
  #
  # The wire magic (`0x5A 0x37`) is intentionally NOT part of the signed
  # material — it's a framing concern, not a payload concern. The HMAC
  # field itself is also excluded. This mirrors the V1 spec but with the
  # `zone_id` field included explicitly so per-zone secret lookup no
  # longer depends on the `gw-<zone>` service-name convention.
  #
  # See `docs/per_zone_hmac_design.md` § "Wire format" for the canonical
  # spec and rationale.
  defp handle_gateway_register_v2(
         <<zone_len::8, rest::binary>>,
         sender
       )
       when zone_len >= 1 and zone_len <= 63 do
    case rest do
      <<zone_id::binary-size(zone_len), node_id::binary-size(16), service_raw::binary-size(16),
        ttl::32, timestamp::64, hmac::binary-size(32)>> ->
        service_name =
          service_raw
          |> :binary.bin_to_list()
          |> Enum.take_while(&(&1 != 0))
          |> to_string()

        signed_data =
          <<0x0E, zone_len::8, zone_id::binary, node_id::binary, service_raw::binary, ttl::32,
            timestamp::64>>

        verify_gateway_register_v2(
          sender,
          zone_id,
          node_id,
          service_name,
          ttl,
          timestamp,
          signed_data,
          hmac
        )

      _ ->
        Logger.warning(
          "[UdpListener] Malformed GATEWAY_REGISTER_V2 from #{inspect(sender)} " <>
            "(zone_len=#{zone_len}, body too short)"
        )
    end
  end

  defp handle_gateway_register_v2(_data, sender) do
    Logger.warning(
      "[UdpListener] Malformed GATEWAY_REGISTER_V2 from #{inspect(sender)} " <>
        "(zone_len out of range 1..63)"
    )
  end

  defp verify_gateway_register_v2(
         sender,
         zone_id,
         node_id,
         service_name,
         ttl,
         timestamp,
         signed_data,
         hmac
       ) do
    # Routing key for V2 registrations is `gw:<zone_id>`, NOT the legacy
    # 16-byte truncated `service_name` field. This is the whole point of
    # V2: routing by zone prevents cross-tenant slug collisions (e.g.
    # "Tech Rockstars" and "Tech Rockstars Test" both truncating to
    # "gw-tech-rockst" in V1). The gateway continues to emit V1 frames
    # in parallel for back-compat — V1 routes by service_name as before.
    #
    # See docs/plans/2026-05-24-zone-keyed-gateway-register-IMPL.md.
    v2_routing_key = "gw:" <> zone_id

    case ZtlpRelay.HmacSecrets.verify_with_policy(zone_id, signed_data, hmac) do
      {:ok, class} when class in [:primary, :grace] ->
        if class == :grace do
          Logger.info(
            "[UdpListener] GATEWAY_REGISTER_V2 from #{inspect(sender)} verified " <>
              "with grace key (zone=#{zone_id}) — sender should upgrade to current primary key."
          )
        end

        guard_timestamp_then_register(sender, node_id, v2_routing_key, ttl, timestamp)

      {:ok, :legacy} ->
        # V2 frames carry an explicit zone_id; falling back to the legacy
        # single secret is supported during migration but emits a louder
        # warning than V1 because the operator clearly intended per-zone
        # auth (or they would still be sending V1).
        Logger.warning(
          "[UdpListener] GATEWAY_REGISTER_V2 from #{inspect(sender)} zone=#{zone_id} " <>
            "accepted via legacy ZTLP_RELAY_REGISTRATION_SECRET. Configure " <>
            "ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "and remove the legacy fallback."
        )

        guard_timestamp_then_register(sender, node_id, v2_routing_key, ttl, timestamp)

      {:ok, :unverified_dev} ->
        Logger.debug(
          "[UdpListener] Accepting unverified GATEWAY_REGISTER_V2 from #{inspect(sender)} " <>
            "zone=#{zone_id} (mode=dev) routing_key=#{v2_routing_key}"
        )

        do_register_gateway(sender, node_id, v2_routing_key, ttl)

      {:ok, :unverified_staging} ->
        Logger.warning(
          "[UdpListener] [STAGING] Accepting unverified GATEWAY_REGISTER_V2 from " <>
            "#{inspect(sender)} service=#{service_name} zone=#{zone_id} " <>
            "routing_key=#{v2_routing_key} — " <>
            "configure ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "before promoting to prod."
        )

        do_register_gateway(sender, node_id, v2_routing_key, ttl)

      {:error, :bad_hmac} ->
        Logger.warning(
          "[UdpListener] GATEWAY_REGISTER_V2 from #{inspect(sender)} rejected: " <>
            "invalid HMAC (zone=#{zone_id})"
        )

      {:error, :no_secret_configured_prod} ->
        Logger.error(
          "[UdpListener] [PROD] GATEWAY_REGISTER_V2 from #{inspect(sender)} REJECTED: " <>
            "no secret configured for zone=#{zone_id}. " <>
            "Set ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "and restart, or downgrade ZTLP_RELAY_HMAC_MODE to staging/dev."
        )
    end
  end

  # ---------------------------------------------------------------------------
  # CLIENT_ROUTE — α-relay routing setup (FRAME_CLIENT_ROUTE / 0x5A 0x37 0x0B)
  # ---------------------------------------------------------------------------
  #
  # Sent by a QUIC client BEFORE its first QUIC INITIAL packet so the relay
  # can install `{:client_map, sender} -> gateway_addr` in
  # `:ztlp_forwarded_quic_tuples`. Subsequent UDP from the same 5-tuple is
  # then transparently echoed to the registered gateway by the QUIC fast
  # bypass branch in `handle_info/2` above.
  #
  # Wire format (after 0x5A 0x37 0x0B magic+type already stripped):
  #   [16 node_id][1 svc_len][svc_len service][8 timestamp][32 hmac]
  #
  # The HMAC scheme mirrors GATEWAY_REGISTER so the same shared secret in
  # `Config.registration_secret/0` covers both frames. In dev mode (nil
  # secret), the HMAC field is ignored and routing is accepted unverified.
  defp handle_client_route(
         <<node_id::binary-size(16), svc_len::8, rest::binary>>,
         sender,
         _state
       )
       when svc_len > 0 and svc_len <= 63 do
    case rest do
      <<service_name::binary-size(svc_len), timestamp::64-signed, hmac::binary-size(32)>> ->
        process_client_route(sender, node_id, service_name, timestamp, hmac)

      _ ->
        Logger.warning(
          "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} rejected: malformed payload"
        )
    end
  end

  defp handle_client_route(_data, sender, _state) do
    Logger.warning(
      "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} rejected: malformed header (svc_len out of range)"
    )
  end

  defp process_client_route(sender, node_id, service_name, timestamp, hmac) do
    zone_id = derive_zone_from_service(service_name)

    signed =
      <<0x0B, node_id::binary, byte_size(service_name)::8, service_name::binary,
        timestamp::64-signed>>

    case ZtlpRelay.HmacSecrets.verify_with_policy(zone_id, signed, hmac) do
      {:ok, class} when class in [:primary, :grace, :legacy] ->
        if class == :legacy do
          Logger.warning(
            "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} accepted via " <>
              "legacy ZTLP_RELAY_REGISTRATION_SECRET. Migrate to per-zone " <>
              "secret ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)}."
          )
        end

        # Same 300-second window as GATEWAY_REGISTER. CLIENT_ROUTE is one-shot
        # (per-connection), so a tighter window would be safer in production —
        # leaving it consistent for now, revisit when CLIENT_ROUTE replay
        # protection becomes a separate hardening pass.
        now = System.system_time(:second)

        if abs(now - timestamp) <= 300 do
          do_install_client_route(sender, node_id, service_name)
        else
          Logger.warning(
            "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} rejected: timestamp too old " <>
              "(delta=#{now - timestamp}s)"
          )
        end

      {:ok, :unverified_dev} ->
        Logger.debug(
          "[UdpListener] Accepting unverified CLIENT_ROUTE from #{inspect(sender)} " <>
            "service=#{service_name} (mode=dev)"
        )

        do_install_client_route(sender, node_id, service_name)

      {:ok, :unverified_staging} ->
        Logger.warning(
          "[UdpListener] [STAGING] Accepting unverified CLIENT_ROUTE from " <>
            "#{inspect(sender)} service=#{service_name} zone=#{zone_id} — " <>
            "configure ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "before promoting to prod."
        )

        do_install_client_route(sender, node_id, service_name)

      {:error, :bad_hmac} ->
        Logger.warning(
          "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} rejected: invalid HMAC " <>
            "(zone=#{zone_id})"
        )

      {:error, :no_secret_configured_prod} ->
        Logger.error(
          "[UdpListener] [PROD] CLIENT_ROUTE from #{inspect(sender)} REJECTED: " <>
            "no secret configured for zone=#{zone_id}. " <>
            "Set ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "and restart, or downgrade ZTLP_RELAY_HMAC_MODE to staging/dev."
        )
    end
  end

  defp do_install_client_route(sender, node_id, service_name) do
    case GenServer.whereis(GatewayForwarder) do
      nil ->
        Logger.warning(
          "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} but GatewayForwarder not running"
        )

      _pid ->
        # Resolve the target gateway. Try the service-name string first
        # (legacy / explicit `--service NAME` that matches a registration),
        # then fall back to the NS-resolved NodeID carried in the packet.
        #
        # The NodeID fallback is REQUIRED for remote-site, symmetric-NAT'd
        # endpoints (e.g. Casita Village Dental BILLING-COMPUTER, 2026-06-11):
        # the gateway registers under its Z2LS service-name
        # (`z2ls-bill-008247`) but the operator dials a generic
        # `--service ssh`, so the CLIENT_ROUTE service-name field is "ssh"
        # and never matches. The packet's 16-byte node_id, however, IS the
        # gateway's NS-resolved NodeID. `pick_gateway_for_service/1` matches
        # a 16-byte binary against `gw.node_id` (its authoritative tier), so
        # routing by node_id succeeds where the name lookup fails.
        #
        # This mirrors the HELLO/`dst_svc_id` path in
        # `forward_hello_to_gateway/5`, which already routes by NodeID. An
        # all-zero node_id (direct ip:port connect, no NS resolution) is NOT
        # used as a fallback key — that would round-robin onto an arbitrary
        # tenant. Only a real, non-zero NodeID is tried.
        pick_result =
          case GatewayForwarder.pick_gateway_for_service(service_name) do
            {:ok, _} = ok ->
              ok

            :error ->
              case node_id do
                <<0::128>> -> :error
                <<nid::binary-size(16)>> -> GatewayForwarder.pick_gateway_for_service(nid)
                _ -> :error
              end
          end

        case pick_result do
          {:ok, gateway_addr} ->
            ensure_quic_tuple_table()

            # v0.29.3: clean up stale entries from the SAME client source IP
            # pointing to the SAME gateway BEFORE inserting the new mapping.
            # Reason: every `ztlp connect` from the same host opens a fresh
            # ephemeral UDP socket (OS-chosen port), so the previous run's
            # `{:client_map, {ip, old_port}}` entry never gets reused. Left
            # in place, the reverse-forward (gateway→client) `match_object`
            # returns multiple entries in arbitrary ETS hash-bucket order
            # and the [head|_] pick routes responses to dead ports — the
            # exact handshake-flakiness signature seen in v0.29.0..v0.29.2.
            #
            # We only purge entries that share BOTH the client IP AND the
            # target gateway address. We do NOT purge entries from the
            # same IP pointing to a DIFFERENT gateway — the same host can
            # legitimately have concurrent tunnels to multiple tenants.
            {client_ip, _client_port} = sender

            stale_matches =
              :ets.match_object(
                :ztlp_forwarded_quic_tuples,
                {{:client_map, {client_ip, :_}}, {gateway_addr, :_}}
              )

            stale_count =
              Enum.reduce(stale_matches, 0, fn
                {{:client_map, ^sender}, _}, acc ->
                  # Don't delete the entry we're about to overwrite — let
                  # the :ets.insert below replace it atomically.
                  acc

                {{:client_map, other_client}, _}, acc ->
                  :ets.delete(
                    :ztlp_forwarded_quic_tuples,
                    {:client_map, other_client}
                  )

                  acc + 1
              end)

            inserted_at = System.monotonic_time(:millisecond)

            :ets.insert(
              :ztlp_forwarded_quic_tuples,
              {{:client_map, sender}, {gateway_addr, inserted_at}}
            )

            Logger.info(
              "[UdpListener] CLIENT_ROUTE accepted: client=#{inspect(sender)} " <>
                "service=#{service_name} gateway=#{inspect(gateway_addr)} " <>
                "node_id=#{Base.encode16(node_id)} purged_stale=#{stale_count}"
            )

            :ok

          :error ->
            Logger.warning(
              "[UdpListener] CLIENT_ROUTE from #{inspect(sender)} rejected: " <>
                "no gateway registered for service=#{service_name}"
            )
        end
    end
  end

  # ---------------------------------------------------------------------------
  # CLIENT_ROUTE_V2 (FRAME_CLIENT_ROUTE_V2 / 0x5A 0x37 0x0F)
  # ---------------------------------------------------------------------------
  #
  # Wire format (after `0x5A 0x37 0x0F` magic+type already stripped):
  #
  #   [1  zone_len]
  #   [zone_len  zone_id]              (1..=63 bytes, RFC1035 DNS label)
  #   [16 node_id]
  #   [1  svc_len]
  #   [svc_len  service_name]          (1..=63 bytes, length-prefixed)
  #   [8  timestamp]                   (big-endian unix seconds, signed)
  #   [32 hmac]                        (HMAC-SHA256)
  #
  # Signed material:
  #
  #   0x0F || zone_len (1B) || zone_id || node_id || svc_len (1B)
  #        || service_name || timestamp (8B)
  #
  # Same exclusion rules as GATEWAY_REGISTER_V2: wire magic and the HMAC
  # field itself are NOT part of the signed material.
  defp handle_client_route_v2(
         <<zone_len::8, rest::binary>>,
         sender,
         _state
       )
       when zone_len >= 1 and zone_len <= 63 do
    case rest do
      <<zone_id::binary-size(zone_len), node_id::binary-size(16), svc_len::8, rest2::binary>>
      when svc_len >= 1 and svc_len <= 63 ->
        case rest2 do
          <<service_name::binary-size(svc_len), timestamp::64-signed, hmac::binary-size(32)>> ->
            signed_data =
              <<0x0F, zone_len::8, zone_id::binary, node_id::binary, svc_len::8,
                service_name::binary, timestamp::64-signed>>

            process_client_route_v2(
              sender,
              zone_id,
              node_id,
              service_name,
              timestamp,
              signed_data,
              hmac
            )

          _ ->
            Logger.warning(
              "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} rejected: " <>
                "malformed payload (svc_len=#{svc_len})"
            )
        end

      _ ->
        Logger.warning(
          "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} rejected: " <>
            "malformed header (zone_len=#{zone_len}, svc_len out of range or body short)"
        )
    end
  end

  defp handle_client_route_v2(_data, sender, _state) do
    Logger.warning(
      "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} rejected: " <>
        "malformed header (zone_len out of range 1..63)"
    )
  end

  defp process_client_route_v2(
         sender,
         zone_id,
         node_id,
         service_name,
         timestamp,
         signed_data,
         hmac
       ) do
    case ZtlpRelay.HmacSecrets.verify_with_policy(zone_id, signed_data, hmac) do
      {:ok, class} when class in [:primary, :grace, :legacy] ->
        if class == :legacy do
          Logger.warning(
            "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} zone=#{zone_id} " <>
              "accepted via legacy ZTLP_RELAY_REGISTRATION_SECRET. Configure " <>
              "ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
              "and remove the legacy fallback."
          )
        end

        now = System.system_time(:second)

        if abs(now - timestamp) <= 300 do
          do_install_client_route(sender, node_id, service_name)
        else
          Logger.warning(
            "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} rejected: " <>
              "timestamp too old (delta=#{now - timestamp}s)"
          )
        end

      {:ok, :unverified_dev} ->
        Logger.debug(
          "[UdpListener] Accepting unverified CLIENT_ROUTE_V2 from #{inspect(sender)} " <>
            "service=#{service_name} zone=#{zone_id} (mode=dev)"
        )

        do_install_client_route(sender, node_id, service_name)

      {:ok, :unverified_staging} ->
        Logger.warning(
          "[UdpListener] [STAGING] Accepting unverified CLIENT_ROUTE_V2 from " <>
            "#{inspect(sender)} service=#{service_name} zone=#{zone_id} — " <>
            "configure ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "before promoting to prod."
        )

        do_install_client_route(sender, node_id, service_name)

      {:error, :bad_hmac} ->
        Logger.warning(
          "[UdpListener] CLIENT_ROUTE_V2 from #{inspect(sender)} rejected: " <>
            "invalid HMAC (zone=#{zone_id})"
        )

      {:error, :no_secret_configured_prod} ->
        Logger.error(
          "[UdpListener] [PROD] CLIENT_ROUTE_V2 from #{inspect(sender)} REJECTED: " <>
            "no secret configured for zone=#{zone_id}. " <>
            "Set ZTLP_HMAC_SECRET_#{ZtlpRelay.HmacSecrets.slugify_zone(zone_id)} " <>
            "and restart, or downgrade ZTLP_RELAY_HMAC_MODE to staging/dev."
        )
    end
  end

  # The QUIC tuple table is normally created on first GATEWAY_REGISTER. If a
  # CLIENT_ROUTE arrives before any gateway has registered, this guard makes
  # the relay tolerant of either ordering.
  defp ensure_quic_tuple_table do
    if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
      :ets.new(:ztlp_forwarded_quic_tuples, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ok
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
        cond do
          # In mesh mode, check if this is a RELAY_FORWARD message
          # (which won't pass the ZTLP magic check since it uses inter-relay protocol)
          state.mesh_enabled and InterRelay.inter_relay_message?(data) ->
            handle_inter_relay_packet(data, sender, state)

          # Post-handshake Noise transport packets have no ZTLP header and
          # will fail the Layer 1 magic check. If the sender is a known peer
          # of an established forwarded session, blind-forward the raw bytes
          # to the other peer. This is the data-plane path for SSH-over-ZTLP
          # through the gateway forwarder; without it, only the handshake
          # packets ever cross the relay.
          true ->
            case GatewayForwarder.lookup_by_peer(sender) do
              {:ok, _session_id, {dest_ip, dest_port}} ->
                :gen_udp.send(state.socket, dest_ip, dest_port, data)
                Stats.increment(:forwarded)
                :ok

              :error ->
                Logger.debug(
                  "Dropped packet from #{inspect(sender)} at layer #{layer}: #{reason}"
                )

                :ok
            end
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
  # the session for bidirectional forwarding (client <-> relay <-> gateway).
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
                Logger.debug(
                  "Received HELLO from #{inspect(sender)} but session already established"
                )
            end

          true ->
            Logger.debug(
              "Received HELLO from unknown peer #{inspect(sender)} on existing session"
            )
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
                Logger.debug(
                  "Received HELLO_ACK from #{inspect(sender)} but session not half-open"
                )
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
  #
  # VIP intercept: if the session is from an iOS VIP client and the packet
  # targets a VIP-proxied service, the VIP TCP terminator handles it.
  defp handle_admitted_packet(parsed, data, sender, state) do
    session_id = parsed.session_id

    case SessionRegistry.lookup_session(session_id) do
      {:ok, {peer_a, peer_b, pid}} ->
        # VIP intercept: try VIP TCP termination first for data packets from peer_a
        if parsed.type == :data_compact and sender == peer_a do
          case VipTcpTerminator.handle_vip_packet(parsed, data, sender, state.socket) do
            :vip_handled ->
              Stats.increment(:vip_packets_processed)
              if is_pid(pid), do: Session.forward(pid)

            :not_vip_service ->
              forward_classic(data, sender, peer_a, peer_b, pid, state)

            :vip_error ->
              Logger.debug("VIP processing failed for session #{Base.encode16(session_id)}")
              forward_classic(data, sender, peer_a, peer_b, pid, state)
          end
        else
          forward_classic(data, sender, peer_a, peer_b, pid, state)
        end

      :error ->
        # Session not in SessionRegistry — try GatewayForwarder
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
                {sender_ip, sender_port} = sender
                {_gw_ip, gw_port} = gateway_addr

                cond do
                  sender_ip in GatewayForwarder.known_gateway_ips() and sender_port == gw_port ->
                    {dest_ip, dest_port} = client_addr
                    :gen_udp.send(state.socket, dest_ip, dest_port, data)
                    Stats.increment(:forwarded)

                  sender_ip not in GatewayForwarder.known_gateway_ips() ->
                    Logger.debug(
                      "Session-ID routed (GW-fwd): #{Base.encode16(session_id)} " <>
                        "from #{inspect(sender)} -> forwarding to gateway"
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
              Logger.debug(
                "No session found for #{Base.encode16(session_id)} from #{inspect(sender)}"
              )

              :ok
            end
        end
    end
  end

  # Classic opaque relay forwarding — the path that never changes.
  defp forward_classic(data, sender, peer_a, peer_b, pid, state) do
    cond do
      # Known peer_a — forward to peer_b
      sender == peer_a and peer_b != nil ->
        send_forward(state.socket, peer_b, data, pid)

      # Known peer_b — forward to peer_a
      sender == peer_b ->
        send_forward(state.socket, peer_a, data, pid)

      # Unrecognized sender - drop the packet
      sender != peer_a and sender != peer_b and peer_b != nil ->
        Stats.increment(:layer2_drops)
        # We don't log this at info level to prevent log pollution from scanning
        Logger.debug("Dropped data packet from unknown peer: #{inspect(sender)}")
        :ok

      # Half-open session, new sender is peer_b
      peer_b == nil and sender != peer_a and is_pid(pid) ->
        case Session.set_peer_b(pid, sender) do
          :ok ->
            Logger.debug(
              "Learned peer_b #{inspect(sender)} from data packet — session now ESTABLISHED"
            )

            {dest_ip, dest_port} = peer_a
            :gen_udp.send(state.socket, dest_ip, dest_port, data)
            Stats.increment(:forwarded)

          {:error, _} ->
            :ok
        end

      # peer_a sent but peer_b not yet known
      sender == peer_a and peer_b == nil ->
        Logger.debug("Packet from peer_a but peer_b unknown — dropping")

        :ok

      # Unknown sender on existing session — gateway migration or session-ID routing
      true ->
        handle_unknown_sender(data, sender, peer_a, peer_b, pid, state)
    end
  end

  defp handle_unknown_sender(data, sender, peer_a, peer_b, pid, state) do
    {sender_ip, sender_port} = sender
    {peer_b_ip, peer_b_port} = peer_b
    # used in gateway migration detection
    _ = peer_b_ip
    gateway_ips = GatewayForwarder.known_gateway_ips()
    same_port = sender_port == peer_b_port

    cond do
      sender_ip in gateway_ips and same_port ->
        Logger.info("Gateway address migration: peer_b #{inspect(peer_b)} -> #{inspect(sender)}")

        if is_pid(pid), do: Session.update_peer_b(pid, sender)
        SessionRegistry.update_peer_b(state.session_id, sender)

        {dest_ip, dest_port} = peer_a
        :gen_udp.send(state.socket, dest_ip, dest_port, data)
        Stats.increment(:forwarded)
        if is_pid(pid), do: Session.forward(pid)

      sender_ip not in gateway_ips ->
        Logger.debug("Session-ID routed: from #{inspect(sender)} -> forwarding to gateway")

        {dest_ip, dest_port} = peer_b
        :gen_udp.send(state.socket, dest_ip, dest_port, data)
        Stats.increment(:forwarded)
        if is_pid(pid), do: Session.forward(pid)

      state.mesh_enabled ->
        mesh_route_packet(state.session_id, data, sender, state)

      true ->
        Logger.debug(
          "Unknown sender #{inspect(sender)} for session (peer_a=#{inspect(peer_a)} peer_b=#{inspect(peer_b)})"
        )

        :ok
    end
  end

  defp send_forward(socket, {dest_ip, dest_port}, data, pid) do
    :gen_udp.send(socket, dest_ip, dest_port, data)
    Stats.increment(:forwarded)
    if is_pid(pid), do: Session.forward(pid)
  end

  # Forward a HELLO to a configured gateway.
  defp forward_hello_to_gateway(session_id, data, client_addr, parsed, state) do
    # Wire-decoupling Option C: `dst_svc_id` is now a 16-byte truncated
    # SHA-256 of the canonicalised service name — NOT zero-padded ASCII.
    # We pass the raw 16 bytes through to `pick_gateway_for_service/1`,
    # which hashes each registered gateway's `service_name` and matches
    # by hash. The all-zero special case still means "no service preference,
    # round-robin any gateway" (back-compat with pre-Option-C clients and
    # the legacy CLI path that doesn't set the field).
    #
    # This was previously decoded as `bin_to_list |> take_while != 0 |> to_string`
    # which never matched a registered service NAME against a hashed value
    # — every HELLO fell through to the round-robin fallback and landed on
    # whichever gateway happened to be next in the list (~6/7 wrong with 7
    # tenants registered).
    dst_svc_id = Map.get(parsed, :dst_svc_id)

    pick_result =
      case dst_svc_id do
        nil -> GatewayForwarder.pick_gateway()
        <<0::128>> -> GatewayForwarder.pick_gateway()
        <<hash::binary-size(16)>> -> GatewayForwarder.pick_gateway_for_service(hash)
        _ -> GatewayForwarder.pick_gateway()
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
