defmodule ZtlpGateway.RelayRegistrar do
  @moduledoc """
  Periodically sends GATEWAY_REGISTER packets to the configured relay.

  When `ZTLP_RELAY_SERVER` is set, this GenServer sends a registration
  packet to the relay on startup and every TTL/2 seconds thereafter.
  The relay uses the source address of the UDP packet to learn the
  gateway's address (works behind NAT).

  ## Registration Packet Format

  After the ZTLP magic bytes (0x5A37) and type byte (0x0A):

      [16 bytes]  Gateway Node ID
      [16 bytes]  Service name (zero-padded)
      [4 bytes]   TTL in seconds (big-endian)
      [8 bytes]   Timestamp (unix seconds, big-endian)
      [32 bytes]  HMAC-SHA256 of the above fields

  Total: 3 + 16 + 16 + 4 + 8 + 32 = 79 bytes

  If `ZTLP_RELAY_REGISTRATION_SECRET` is not set, the HMAC field is
  filled with zeros (dev mode).
  """

  use GenServer

  require Logger

  alias ZtlpGateway.Config

  @default_ttl 60
  @type_byte 0x0A

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
        Logger.info("[RelayRegistrar] No ZTLP_RELAY_SERVER configured, relay registration disabled")
        {:ok, %{relay: nil, ttl: ttl, socket: nil, node_id: nil}}

      relay_addr ->
        node_id = Config.node_id()

        Logger.info(
          "[RelayRegistrar] Will register with relay #{inspect(relay_addr)} " <>
            "node_id=#{Base.encode16(node_id)} ttl=#{ttl}s"
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
          secret: Config.registration_secret(),
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
        send_registration(socket, state.relay, state.node_id, service, state.ttl, state.secret)
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

  # Internal

  @doc false
  @spec build_registration_packet(binary(), String.t(), non_neg_integer(), binary() | nil) ::
          binary()
  def build_registration_packet(node_id, service_name, ttl, secret) do
    # Pad service name to 16 bytes (zero-padded)
    service_padded = pad_service_name(service_name)
    timestamp = System.system_time(:second)

    # The signed payload (type + node_id + service + ttl + timestamp)
    signed_data = <<@type_byte, node_id::binary, service_padded::binary, ttl::32, timestamp::64>>

    hmac =
      case secret do
        nil ->
          # Dev mode — zero HMAC
          <<0::256>>

        secret when is_binary(secret) ->
          :crypto.mac(:hmac, :sha256, secret, signed_data)
      end

    # Full packet: magic + type + node_id + service + ttl + timestamp + hmac
    <<0x5A, 0x37, @type_byte, node_id::binary, service_padded::binary, ttl::32, timestamp::64,
      hmac::binary>>
  end

  defp send_registration(socket, {relay_ip, relay_port}, node_id, service, ttl, secret) do
    packet = build_registration_packet(node_id, service, ttl, secret)

    case :gen_udp.send(socket, relay_ip, relay_port, packet) do
      :ok ->
        Logger.debug(
          "[RelayRegistrar] Sent GATEWAY_REGISTER to #{inspect({relay_ip, relay_port})} " <>
            "service=#{service}"
        )

      {:error, reason} ->
        Logger.warning(
          "[RelayRegistrar] Failed to send GATEWAY_REGISTER to #{inspect({relay_ip, relay_port})}: #{inspect(reason)}"
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
