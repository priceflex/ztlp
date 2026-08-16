defmodule ZtlpRelay.VipTcpTerminator do
  @moduledoc """
  VIP TCP termination supervisor and dispatcher for the ZTLP relay.

  When the relay receives an iOS VIP-proxied ZTLP packet, this module:
  1. Decrypts the tunnel payload using the session key
  2. Parses the VIP mux frame to determine the connection ID and operation
  3. Routes connections to the correct backend via `VipServiceTable`
  4. Spawns or dispatches to a `VipConnection` GenServer for each TCP connection
  5. Metrics are registered for Prometheus/NS publication

  This module ONLY handles packets for services configured in the VIP service
  routing table.  All other traffic is passed through to classic relay
  forwarding (the relay stays opaque for non-VIP traffic).

  ## Trust properties (CRITICAL)

  In VIP mode the relay DOES see plaintext for proxied VIP services.
  The relay becomes part of the trusted computing base for those services.
  Relay→backend TLS/mTLS SHOULD be used wherever possible.

  Classic zero-trust relay mode (where the relay cannot see plaintext)
  continues to operate unchanged for all non-VIP traffic.

  ## Configuration

  Enable VIP mode and configure services:

      config :ztlp_relay,
        vip_enabled: true,
        vip_services: [
          {"vault", {127, 0, 0, 1}, 8080},
          {"web", {127, 0, 0, 1}, 80},
          {"api", {127, 0, 0, 1}, 8443}
        ],
        vip_tls_enabled: true

  Or via environment variables:

      ZTLP_RELAY_VIP_ENABLED=true \\
      ZTLP_RELAY_VIP_SERVICES=vault=127.0.0.1:8080,web=127.0.0.1:80 \\
      ZTLP_RELAY_VIP_TLS_ENABLED=true
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{
    Packet,
    VipFrame,
    VipServiceTable,
    Stats,
    SessionSupervisor
  }

  @type state :: %{
          enabled: boolean(),
          tls_enabled: boolean(),
          udp_socket: port() | nil,
          session_connections: :ets.tid() | nil,
          started_at: integer()
        }

  @type handle_result
        :: :vip_handled
         | :not_vip_service
         | :vip_error

  # Client API

  @doc """
  Start the VIP TCP terminator.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if VIP mode is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    case System.get_env("ZTLP_RELAY_VIP_ENABLED") do
      "true" -> true
      "1" -> true
      nil -> Application.get_env(:ztlp_relay, :vip_enabled, false)
      _ -> false
    end
  end

  @doc """
  Check if relay→backend TLS is enabled.
  """
  @spec tls_enabled?() :: boolean()
  def tls_enabled? do
    case System.get_env("ZTLP_RELAY_VIP_TLS_ENABLED") do
      "true" -> true
      "1" -> true
      nil -> Application.get_env(:ztlp_relay, :vip_tls_enabled, false)
      _ -> false
    end
  end

  @doc """
  Handle an inbound data packet in VIP mode.

  Called by the UDP listener when the packet is for a session that has
  VIP-proxied services configured.

  Returns:
  - `:vip_handled` — the packet was processed by the VIP terminator
  - `:not_vip_service` — the service is not in the VIP routing table; fall back to classic relay
  - `:vip_error` — VIP processing failed (packet should be dropped)
  """
  @spec handle_vip_packet(Packet.data_packet(), binary(), {tuple(), non_neg_integer()}, port()) ::
          handle_result()
  def handle_vip_packet(parsed, raw_data, sender, udp_socket) do
    if not enabled?() do
      :not_vip_service
    end

    case get_session_key(parsed.session_id) do
      nil ->
        Logger.debug("[VIP] No session key for session, falling back to classic relay")
        :not_vip_service

      session_key ->
        # Decrypt the payload
        case decrypt_payload(payload_from(parsed), session_key, parsed, raw_data) do
          {:ok, plaintext} ->
            dispatch_frame(plaintext, parsed, sender, udp_socket, session_key)

          {:error, reason} ->
            Logger.debug("[VIP] Decryption failed: #{reason}")
            :vip_error
        end
    end
  end

  # `parsed.payload` may not exist on every packet variant that reaches
  # here; kept as a tiny indirection point in case Packet.data_packet()
  # gains payload-carrying variants without a `payload` field name.
  defp payload_from(parsed), do: parsed.payload

  @doc """
  Get the active VIP connections summary for metrics.
  """
  @spec connections_summary() :: %{
          active_connections: non_neg_integer(),
          services: [{String.t(), non_neg_integer()}]
        }
  def connections_summary() do
    try do
      ets_name = :ztlp_vip_connections

      all_connections = :ets.tab2list(ets_name)

      active = length(all_connections)

      services =
        all_connections
        |> Enum.reduce(%{}, fn {{_, _}, _pid, svc_name, _backend_addr}, acc ->
          Map.update(acc, svc_name, 1, fn count -> count + 1 end)
        end)
        |> Enum.to_list()

      %{
        active_connections: active,
        services: services
      }
    rescue
      _e in ArgumentError ->
        %{active_connections: 0, services: []}
    catch
      _, _ ->
        %{active_connections: 0, services: []}
    end
  end

  @doc """
  Register a VIP connection for tracking.

  The ETS key is `{session_id, connection_id}` to prevent conn_id-only
  collisions across sessions.  An attacker with a different session cannot
  hijack another session's connection by guessing or crafting a conn_id.
  """
  @spec register_connection(binary(), non_neg_integer(), pid(), String.t(), tuple()) :: :ok
  def register_connection(session_id, connection_id, pid, service_name, backend_addr) do
    :ets.insert(:ztlp_vip_connections, {{session_id, connection_id}, pid, service_name, backend_addr})
    :ok
  end

  @doc """
  Unregister a VIP connection.
  """
  @spec unregister_connection(binary(), non_neg_integer()) :: :ok
  def unregister_connection(session_id, connection_id) do
    :ets.delete(:ztlp_vip_connections, {session_id, connection_id})
    :ok
  end

  # GenServer callbacks

  @impl true
  def init(_opts) do
    enabled = enabled?()
    tls_enabled = tls_enabled?()

    if enabled do
      Logger.info("[VIP] VIP TCP termination enabled (TLS=#{tls_enabled})")
    end

    # ETS table: {session_id, connection_id} → {pid, service_name, backend_addr}
    ets = :ets.new(:ztlp_vip_connections, [:named_table, :set, :public, write_concurrency: true])

    {:ok,
     %{
       enabled: enabled,
       tls_enabled: tls_enabled,
       udp_socket: nil,
       session_connections: ets,
       started_at: System.monotonic_time(:millisecond)
     }}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_cast(:udp_socket_ready, state) do
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Internal helpers ───────────────────────────────────────────────

  @doc false
  # Exposed (not @doc false-hidden from the module, just excluded from
  # public docs) so the regression test suite can exercise the fixed
  # crypto primitives directly without needing to construct a full
  # Packet.data_packet() + raw UDP datagram end-to-end for every case.
  @spec test_get_session_key(binary()) :: binary() | nil
  def test_get_session_key(session_id), do: get_session_key(session_id)

  @doc false
  @spec test_decrypt_payload(binary(), binary(), map(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def test_decrypt_payload(payload, session_key, parsed, raw_data),
    do: decrypt_payload(payload, session_key, parsed, raw_data)

  defp get_session_key(session_id) do
    # [SAST fix: fuq-lvym] Derive a UNIQUE per-session key via HKDF from
    # the operator-configured pre-shared key, mixing in session_id as
    # the HKDF info/context parameter. Previously this ignored
    # session_id entirely and returned the SAME raw configured key for
    # EVERY VIP session — every tunnel on the relay shared one key,
    # compounding the fixed-nonce bug below into full keystream reuse
    # not just within a session but ACROSS every session simultaneously
    # active on the relay.
    #
    # NOTE: this still does not derive the key from the actual Noise
    # handshake (VipTcpTerminator has no access to the per-session
    # Noise transport keys today - that would require threading them
    # in from SessionSupervisor/the session GenServer, a larger
    # integration change). This fix closes the cryptographic
    # cross-session-key-reuse gap using the infrastructure that
    # exists now; deriving from the real handshake key remains a
    # follow-up for whoever finishes wiring up the iOS<->relay VIP
    # data-plane end-to-end (no iOS-side or Rust-side producer for
    # this wire format was found in the codebase as of this fix).
    case ZtlpRelay.Config.vip_session_key() do
      nil ->
        nil

      key when byte_size(key) == 32 ->
        hkdf_sha256(key, "ztlp-vip-session:" <> session_id, 32)

      _ ->
        nil
    end
  end

  # Minimal single-block HKDF-Expand (RFC 5869) using HMAC-SHA256.
  # `key` here is used directly as PRK (skipping HKDF-Extract) since
  # the configured VIP session key is already a uniformly-random
  # 32-byte value, not low-entropy input keying material — this
  # matches the common "derive one key from another via HKDF-Expand
  # only" pattern used when the base key is already a proper key.
  # Single 32-byte block is all we need (T(1) = HMAC-Hash(PRK, info || 0x01)).
  defp hkdf_sha256(prk, info, 32) do
    :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
  end

  defp decrypt_payload(payload, session_key, parsed, raw_data) do
    # The payload in a ZTLP data packet is the encrypted VIP tunnel data.
    # For iOS relay-side VIP, the payload format is:
    #   [AEAD_ciphertext][auth_tag]
    # where auth_tag is the last 16 bytes of the payload.
    #
    # [SAST fix: fuq-lvym] TWO further compounding bugs fixed here:
    #
    # 1. Nonce was a FIXED all-zero 96-bit value (<<0::96>>) for every
    #    single packet. Combined with the shared-key bug above, this
    #    was catastrophic (key, nonce) reuse: ChaCha20-Poly1305 leaks
    #    the XOR of plaintexts under keystream reuse and allows
    #    Poly1305 one-time-key recovery -> forgeries. Now derives the
    #    nonce from the packet's own monotonic packet_seq counter
    #    (zero-padded to 96 bits), which is unique per packet within a
    #    session by construction (see Packet.data_packet() - the relay
    #    already relies on packet_seq elsewhere for anti-replay).
    #
    # 2. AAD was empty (<<>>), so a decrypted VIP payload was not bound
    #    to its own packet header at all - an attacker could splice a
    #    valid ciphertext+tag from one packet onto a different header
    #    (e.g. a different session_id or packet_seq) and it would still
    #    decrypt successfully. Now binds the real packet header AAD via
    #    Packet.extract_aad/1 on the raw wire bytes, matching the same
    #    AAD binding already used for the outer packet's HeaderAuthTag.
    nonce = <<parsed.packet_seq::96>>

    aad =
      case Packet.extract_aad(raw_data) do
        {:ok, aad_bytes} -> aad_bytes
        {:error, _} -> <<>>
      end

    if byte_size(payload) < 17 do
      {:error, :payload_too_short}
    else
      ciphertext = binary_part(payload, 0, byte_size(payload) - 16)
      tag = binary_part(payload, byte_size(payload) - 16, 16)

      case :crypto.crypto_one_time_aead(
             :chacha20_poly1305,
             session_key,
             nonce,
             ciphertext,
             aad,
             tag,
             false
             # decrypt
           ) do
        :error ->
          {:error, :decryption_failed}

        plaintext ->
          {:ok, plaintext}
      end
    end
  end

  defp dispatch_frame(plaintext, parsed, sender, udp_socket, session_key) do
    # Parse the VIP frame
    case VipFrame.parse(plaintext) do
      {:ok, frame} ->
        # Extract service name from the ZTLP packet's dst_svc_id
        service_name = extract_service_name(parsed)

        if VipServiceTable.vip_service?(service_name) do
          # VIP-proxied service → handle in VIP mode
          route_connection(frame, service_name, parsed, sender, udp_socket, session_key)
        else
          # Service not in VIP table → fall back to classic relay
          Logger.debug(
            "[VIP] Service '#{service_name}' not in VIP routing table, falling back to classic relay"
          )

          :not_vip_service
        end

      {:error, reason} ->
        Logger.debug("[VIP] Frame parse failed: #{reason}")
        :vip_error
    end
  end

  defp extract_service_name(%{dst_svc_id: <<0::128>>}), do: ""
  defp extract_service_name(%{dst_svc_id: svc_raw}) do
    svc_raw |> :binary.bin_to_list() |> Enum.take_while(&(&1 != 0)) |> to_string()
  end

  defp extract_service_name(_), do: ""

  defp route_connection(frame, service_name, parsed, sender, udp_socket, session_key) do
    conn_id = frame.connection_id
    session_id = parsed.session_id
    tls_enabled = tls_enabled?()

    # Look up backend address
    case VipServiceTable.lookup(service_name) do
      {:ok, backend_addr} ->
        if frame.frame_type == :syn do
          # New connection → spawn a VipConnection GenServer
          Logger.info(
            "[VIP] SYN conn=#{conn_id} svc=#{service_name} → #{format_addr(backend_addr)}"
          )

          case SessionSupervisor.start_session(
                 connection_id: conn_id,
                 session_id: session_id,
                 client_addr: sender,
                 backend_addr: backend_addr,
                 service_name: service_name,
                 udp_socket: udp_socket,
                 session_key: session_key,
                 tls_enabled: tls_enabled
               ) do
            {:ok, pid} ->
              register_connection(session_id, conn_id, pid, service_name, backend_addr)

              # Send the VIP connection its initial SYN data
              send(pid, {:client_data, frame})

              Stats.increment(:vip_connections_started)

              :vip_handled

            {:error, reason} ->
              Logger.error("[VIP] Failed to start VipConnection: #{inspect(reason)}")
              :vip_error
          end
        else
          # Existing connection → find the VipConnection process
          # Must match on {session_id, conn_id} to prevent cross-session hijack
          case :ets.lookup(:ztlp_vip_connections, {session_id, conn_id}) do
            [{{_, _}, pid, _, _}] when is_pid(pid) ->
              # Dispatch data to the connection process
              send(pid, {:client_data, frame})
              :vip_handled

            [] ->
              # Connection not found — SYN might have been lost
              Logger.debug("[VIP] No connection found for frame conn=#{conn_id}")
              :vip_error
          end
        end

      :error ->
        Logger.warning("[VIP] No backend configured for service '#{service_name}'")
        :vip_error
    end
  end

  defp format_addr({{a, b, c, d}, port}), do: "#{a}.#{b}.#{c}.#{d}:#{port}"
  defp format_addr(addr), do: inspect(addr)
end
