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
    Crypto,
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
  def handle_vip_packet(parsed, _raw_data, sender, udp_socket) do
    if not enabled?() do
      :not_vip_service
    end

    case get_session_key(parsed.session_id) do
      nil ->
        Logger.debug("[VIP] No session key for session, falling back to classic relay")
        :not_vip_service

      session_key ->
        # Decrypt the payload
        case decrypt_payload(parsed.payload, session_key, parsed) do
          {:ok, plaintext} ->
            dispatch_frame(plaintext, parsed, sender, udp_socket, session_key)

          {:error, reason} ->
            Logger.debug("[VIP] Decryption failed: #{reason}")
            :vip_error
        end
    end
  end

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
        |> Enum.reduce(%{}, fn {_conn_id, _pid, svc_name, _backend_addr}, acc ->
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
  """
  @spec register_connection(non_neg_integer(), pid(), String.t(), tuple()) :: :ok
  def register_connection(connection_id, pid, service_name, backend_addr) do
    :ets.insert(:ztlp_vip_connections, {connection_id, pid, service_name, backend_addr})
    :ok
  end

  @doc """
  Unregister a VIP connection.
  """
  @spec unregister_connection(non_neg_integer()) :: :ok
  def unregister_connection(connection_id) do
    :ets.delete(:ztlp_vip_connections, connection_id)
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

    # ETS table: connection_id → {pid, service_name, backend_addr}
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

  defp get_session_key(_session_id) do
    # In iOS relay-side VIP mode, the session key is shared between
    # the NE and the relay for tunnel encryption.  If no key is configured,
    # the relay cannot decrypt and must fall back to classic opaque forwarding.
    #
    # Currently, if the relay has the session key from the handshake,
    # it is available via config or the session context.
    # For phase 1, we use a configured VIP tunnel key.
    case ZtlpRelay.Config.vip_session_key() do
      nil -> nil
      key when byte_size(key) == 32 -> key
      _ -> nil
    end
  end

  defp decrypt_payload(payload, session_key, parsed) do
    # The payload in a ZTLP data packet is the encrypted VIP tunnel data.
    # For iOS relay-side VIP, the payload format is:
    #   [AEAD_ciphertext][auth_tag]
    # where auth_tag is the last 16 bytes of the payload.
    #
    # The AAD for this encryption is the ZTLP packet header minus auth tag,
    # which is what Packet.extract_aad computes for the outer packet.
    #
    # We use the same ChaCha20-Poly1305 AEAD construction as the header auth
    # to decrypt the tunnel payload.

    nonce = <<0::96>>

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
             <<>>,
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
                 session_id: parsed.session_id,
                 client_addr: sender,
                 backend_addr: backend_addr,
                 service_name: service_name,
                 udp_socket: udp_socket,
                 session_key: session_key,
                 tls_enabled: tls_enabled
               ) do
            {:ok, pid} ->
              register_connection(conn_id, pid, service_name, backend_addr)

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
          case :ets.match(:ztlp_vip_connections, {conn_id, :"$1", :_, :_}) do
            [[pid]] when is_pid(pid) ->
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
