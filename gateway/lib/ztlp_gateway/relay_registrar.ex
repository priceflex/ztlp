defmodule ZtlpGateway.RelayRegistrar do
  @moduledoc """
  Periodically sends GATEWAY_REGISTER packets to the configured relay.

  When `ZTLP_RELAY_SERVER` is set, this GenServer sends a registration
  packet to the relay on startup and every TTL/2 seconds thereafter.
  The relay uses the source address of the UDP packet to learn the
  gateway's address (works behind NAT).

  ## Registration packet — V1 (default, type byte 0x0A)

  After the ZTLP magic bytes (0x5A37) and type byte (0x0A):

      [16 bytes]  Gateway Node ID
      [16 bytes]  Service name (zero-padded)
      [4 bytes]   TTL in seconds (big-endian)
      [8 bytes]   Timestamp (unix seconds, big-endian)
      [32 bytes]  HMAC-SHA256 of the above fields

  Total: 3 + 16 + 16 + 4 + 8 + 32 = 79 bytes.

  If `ZTLP_RELAY_REGISTRATION_SECRET` is not set, the HMAC field is
  filled with zeros (dev mode).

  ## Registration packet — V2 (opt-in, type byte 0x0E)

  When `ZTLP_GATEWAY_USE_V2_FRAMES=true` AND a per-zone secret is
  configured for the service's derived zone, the registrar emits a V2
  frame instead:

      [1 byte]    zone_len   (1..=63)
      [N bytes]   zone_id    (RFC1035 DNS label, derived from service
                              name: "gw-<zone>" → "<zone>", else
                              service name unchanged)
      [16 bytes]  Gateway Node ID
      [16 bytes]  Service name (zero-padded — matches V1 layout)
      [4 bytes]   TTL in seconds (big-endian)
      [8 bytes]   Timestamp (unix seconds, big-endian)
      [32 bytes]  HMAC-SHA256 of the above fields (excluding wire magic)

  Total: 3 + 1 + zone_len + 16 + 16 + 4 + 8 + 32 = 80 + zone_len bytes.

  Both V1 and V2 are accepted by relays running v0.29.6+. V2 frames
  carry the zone explicitly so per-zone secret lookup on the relay no
  longer depends on the `gw-<zone>` service-name convention.

  ## Flag default

  `ZTLP_GATEWAY_USE_V2_FRAMES` defaults to **false**. Operators flip
  it on once Phase 3 of the per-zone HMAC rollout has provisioned
  `ZTLP_HMAC_SECRET_<ZONE>` for each tenant gateway. If the flag is
  on but no per-zone secret is configured for the derived zone, the
  registrar falls back to V1 emission for that service so a
  half-provisioned gateway doesn't go dark.

  See `docs/per_zone_hmac_design.md` for the full design.
  """

  use GenServer

  require Logger

  alias ZtlpGateway.{Config, HmacSecrets}

  @default_ttl 60
  @type_byte_v1 0x0A
  @type_byte_v2 0x0E

  # Client API

  @doc "Start the relay registrar."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get the current state (for testing/debugging)."
  @spec state() :: map()
  def state do
    GenServer.call(__MODULE__, :state)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    ttl = Keyword.get(opts, :ttl, @default_ttl)

    case Config.relay_server() do
      nil ->
        Logger.info(
          "[RelayRegistrar] No ZTLP_RELAY_SERVER configured, relay registration disabled"
        )

        {:ok, %{relay: nil, ttl: ttl, socket: nil, node_id: nil}}

      relay_addr ->
        node_id = Config.node_id()
        use_v2 = use_v2_frames?()

        Logger.info(
          "[RelayRegistrar] Will register with relay #{inspect(relay_addr)} " <>
            "node_id=#{Base.encode16(node_id)} ttl=#{ttl}s use_v2=#{use_v2}"
        )

        # Use the gateway's main listener socket so the relay sees the same
        # source address:port as handshake traffic. This is critical for NAT
        # traversal — the relay will forward HELLOs to our listener port,
        # not an ephemeral registration port.
        # Delay first registration slightly to let the Listener start first.
        # Accept an optional test_socket for testing without a running Listener
        test_socket = Keyword.get(opts, :test_socket)

        state = %{
          relay: relay_addr,
          ttl: ttl,
          node_id: node_id,
          services: Config.service_names(),
          legacy_secret: Config.registration_secret(),
          use_v2: use_v2,
          test_socket: test_socket
        }

        # Give the Listener time to start and bind its socket
        Process.send_after(self(), :register, 2_000)

        {:ok, state}
    end
  end

  @impl true
  def handle_call(:state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:register, %{relay: nil} = state) do
    {:noreply, state}
  end

  def handle_info(:register, state) do
    # Use an injected test socket if provided, otherwise get the main listener
    # socket so the relay sees our listener port (e.g. 23098) for NAT traversal.
    socket =
      case Map.get(state, :test_socket) do
        nil ->
          try do
            ZtlpGateway.Listener.socket()
          catch
            :exit, _ -> nil
          end

        sock ->
          sock
      end

    if socket do
      for service <- state.services do
        send_registration(
          socket,
          state.relay,
          state.node_id,
          service,
          state.ttl,
          state.legacy_secret,
          state.use_v2
        )
      end

      # Re-register at TTL/2
      interval = div(state.ttl * 1000, 2)
      Process.send_after(self(), :register, interval)
    else
      Logger.warning("[RelayRegistrar] Listener socket not available yet, retrying in 1s")
      Process.send_after(self(), :register, 1_000)
    end

    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, _state) do
    # Socket is owned by Listener — don't close it here
    :ok
  end

  # Public for tests + future explicit callers.

  @doc """
  Read the `ZTLP_GATEWAY_USE_V2_FRAMES` env flag. Defaults to `false`
  so existing deployments emit V1 frames until an operator explicitly
  enables V2.
  """
  @spec use_v2_frames?() :: boolean()
  def use_v2_frames? do
    case System.get_env("ZTLP_GATEWAY_USE_V2_FRAMES") do
      nil -> Application.get_env(:ztlp_gateway, :use_v2_frames, false)
      "true" -> true
      "1" -> true
      "yes" -> true
      _ -> false
    end
  end

  @doc """
  Derive the per-zone key id from a service name. Mirrors the relay's
  V1 derivation rule so V1 and V2 frames for the same service look up
  the same `ZTLP_HMAC_SECRET_<ZONE>` slot.

      iex> ZtlpGateway.RelayRegistrar.derive_zone_from_service("gw-acme")
      "acme"

      iex> ZtlpGateway.RelayRegistrar.derive_zone_from_service("default")
      "default"
  """
  @spec derive_zone_from_service(String.t()) :: String.t()
  def derive_zone_from_service("gw-" <> rest), do: rest
  def derive_zone_from_service(other) when is_binary(other), do: other

  # Internal

  @doc false
  @spec build_registration_packet(binary(), String.t(), non_neg_integer(), binary() | nil) ::
          binary()
  def build_registration_packet(node_id, service_name, ttl, secret) do
    # V1 emission — kept byte-identical to the v0.29.5 layout. Do NOT
    # change without coordinating a wire change with the relay.
    service_padded = pad_service_name(service_name)
    timestamp = System.system_time(:second)

    signed_data =
      <<@type_byte_v1, node_id::binary, service_padded::binary, ttl::32, timestamp::64>>

    hmac =
      case secret do
        nil ->
          # Dev mode — zero HMAC. The relay's mode policy decides whether
          # to accept this; it has nothing to do with the gateway side.
          <<0::256>>

        secret when is_binary(secret) ->
          :crypto.mac(:hmac, :sha256, secret, signed_data)
      end

    <<0x5A, 0x37, @type_byte_v1, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
      hmac::binary>>
  end

  @doc """
  Build a V2 GATEWAY_REGISTER_V2 packet (type byte 0x0E) for the
  given service. The `zone_id` field is derived from the service name
  via `derive_zone_from_service/1` and embedded explicitly in the
  packet.

  The signed material is

      <<0x0E, zone_len, zone_id, node_id, service_padded, ttl, timestamp>>

  — i.e., the wire magic (`0x5A 0x37`) and the HMAC field itself are
  NOT part of the signed input. This matches the relay-side
  `process_gateway_register_v2/8` rule in
  `relay/lib/ztlp_relay/udp_listener.ex`.

  Raises `ArgumentError` if `secret` is nil — V2 has no dev-mode
  zero-HMAC path. The caller (`send_registration/7`) decides whether
  to take the V2 path based on whether a per-zone secret is set.
  """
  @spec build_registration_packet_v2(binary(), String.t(), non_neg_integer(), binary()) ::
          binary()
  def build_registration_packet_v2(node_id, service_name, ttl, secret)
      when is_binary(node_id) and byte_size(node_id) == 16 and is_binary(service_name) and
             is_integer(ttl) and ttl >= 0 and is_binary(secret) do
    zone_id = derive_zone_from_service(service_name)
    zone_len = byte_size(zone_id)

    if zone_len < 1 or zone_len > 63 do
      raise ArgumentError,
            "V2 zone_id must be 1..=63 bytes (got #{zone_len}B for service=#{service_name})"
    end

    service_padded = pad_service_name(service_name)
    timestamp = System.system_time(:second)

    signed_data =
      <<@type_byte_v2, zone_len::8, zone_id::binary, node_id::binary, service_padded::binary,
        ttl::32, timestamp::64>>

    hmac = :crypto.mac(:hmac, :sha256, secret, signed_data)

    <<0x5A, 0x37, @type_byte_v2, zone_len::8, zone_id::binary, node_id::binary,
      service_padded::binary, ttl::32, timestamp::64, hmac::binary>>
  end

  # Pick V1 or V2 emission for a single service. The decision is
  # service-scoped so a multi-service gateway can mix V2-signed and
  # V1-signed registrations in the same tick if the operator has only
  # provisioned per-zone secrets for some of its services.
  defp send_registration(
         socket,
         {relay_ip, relay_port},
         node_id,
         service,
         ttl,
         legacy_secret,
         use_v2
       ) do
    zone_id = derive_zone_from_service(service)

    {packet, mode_tag} =
      cond do
        use_v2 ->
          case HmacSecrets.primary_secret(zone_id) do
            {:ok, per_zone_secret} ->
              {build_registration_packet_v2(node_id, service, ttl, per_zone_secret), :v2}

            {:error, :not_configured} ->
              # V2 was requested but no per-zone secret for this zone —
              # fall back to V1 for this service so the gateway doesn't
              # go silent during a partial Phase 3 rollout. Loud so
              # operators notice the misconfiguration.
              Logger.warning(
                "[RelayRegistrar] use_v2=true but no ZTLP_HMAC_SECRET_#{HmacSecrets.slugify_zone(zone_id)} " <>
                  "configured for service=#{service} zone=#{zone_id}; falling back to V1 emission. " <>
                  "Set the env var or disable ZTLP_GATEWAY_USE_V2_FRAMES."
              )

              {build_registration_packet(node_id, service, ttl, legacy_secret), :v1_fallback}
          end

        true ->
          {build_registration_packet(node_id, service, ttl, legacy_secret), :v1}
      end

    case :gen_udp.send(socket, relay_ip, relay_port, packet) do
      :ok ->
        Logger.debug(
          "[RelayRegistrar] Sent GATEWAY_REGISTER(#{mode_tag}) to " <>
            "#{inspect({relay_ip, relay_port})} service=#{service} zone=#{zone_id}"
        )

      {:error, reason} ->
        Logger.warning(
          "[RelayRegistrar] Failed to send GATEWAY_REGISTER(#{mode_tag}) to " <>
            "#{inspect({relay_ip, relay_port})}: #{inspect(reason)}"
        )
    end
  end

  defp pad_service_name(name) when byte_size(name) >= 16 do
    binary_part(name, 0, 16)
  end

  defp pad_service_name(name) do
    padding_size = 16 - byte_size(name)
    name <> :binary.copy(<<0>>, padding_size)
  end
end
