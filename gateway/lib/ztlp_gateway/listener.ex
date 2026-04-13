defmodule ZtlpGateway.Listener do
  @moduledoc """
  UDP listener for the ZTLP Gateway.

  Binds to the configured port and receives all incoming ZTLP packets.
  Each packet runs through the admission pipeline (Layer 1 + 2), then
  is dispatched to the appropriate Session process.

  For HELLO packets (new session requests), the Listener creates a
  new Session process under the SessionSupervisor.

  ## Flow

      UDP packet arrives
      → Layer 1: magic check (reject non-ZTLP)
      → Layer 2: SessionID lookup
        → Known session → forward to Session pid
        → HELLO → create new Session, forward
        → Unknown → drop
  """

  use GenServer

  require Logger

  alias ZtlpGateway.{Packet, Pipeline, Session, SessionRegistry, Config}

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the UDP listener."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the port the listener is bound to.

  Useful when port=0 is used (tests) and we need to know the actual port.
  """
  @spec port() :: non_neg_integer()
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  @doc """
  Get the UDP socket (for sending responses from Session processes).
  """
  @spec socket() :: port()
  def socket do
    GenServer.call(__MODULE__, :get_socket)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, Config.get(:port))

    # The gateway's long-term X25519 keypair.
    # In production this would be loaded from a keystore.
    # For the prototype, generate fresh on startup.
    {static_pub, static_priv} = ZtlpGateway.Crypto.generate_keypair()

    # Use a large receive buffer (4 MB) so that bursts of concurrent sessions
    # don't overflow the socket while the Listener GenServer is busy creating
    # session processes.  Without this, 10+ simultaneous handshakes cause
    # RcvbufErrors and silently dropped data packets.
    case :gen_udp.open(port, [
           :binary,
           {:active, true},
           {:reuseaddr, true},
           {:recbuf, 4_194_304},
           {:sndbuf, 4_194_304}
         ]) do
      {:ok, socket} ->
        {:ok, actual_port} = :inet.port(socket)
        Logger.info("[Listener] ZTLP Gateway listening on UDP port #{actual_port}")

        {:ok,
         %{
           socket: socket,
           port: actual_port,
           static_pub: static_pub,
           static_priv: static_priv
         }}

      {:error, reason} ->
        {:stop, {:listen_failed, reason}}
    end
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
  end

  def handle_call(:get_socket, _from, state) do
    {:reply, state.socket, state}
  end

  # Incoming UDP packet
  @impl true
  def handle_info({:udp, _socket, ip, port, data}, state) do
    case Pipeline.admit(data) do
      {:ok, :new_session} ->
        start_new_session(data, {ip, port}, state)

      {:ok, :known_session, pid} ->
        Session.handle_packet(pid, data, {ip, port})

      {:reject, reason} ->
        # Log rejections to diagnose concurrent session failures
        session_hex =
          case Packet.extract_session_id(data) do
            {:ok, sid} -> Base.encode16(sid)
            _ -> "??"
          end
        Logger.debug("[Listener] Rejected packet: reason=#{reason} session=#{session_hex} len=#{byte_size(data)} from=#{:inet.ntoa(ip)}:#{port}")
        :ok
    end

    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Internal
  # ---------------------------------------------------------------------------

  defp start_new_session(packet_data, client_addr, state) do
    # Check session limit
    current = SessionRegistry.count()
    max = Config.get(:max_sessions)

    if current < max do
      # Session deduplication: if an existing session is already registered
      # from this client address, terminate it before creating a new one.
      # This prevents session accumulation when VPN extensions reconnect
      # frequently (new handshake from same {ip, port}).
      case SessionRegistry.lookup_by_addr(client_addr) do
        {:ok, {old_sid, old_pid}} ->
          Logger.info("[Listener] Replacing session #{Base.encode16(old_sid)} from #{inspect(client_addr)} — new HELLO received")
          # Unregister first so stale routing/cleanup from the old session cannot poison
          # the replacement session that is about to claim the same client_addr.
          SessionRegistry.unregister(old_sid, old_pid)
          # Use DynamicSupervisor.terminate_child for clean shutdown under supervision tree
          DynamicSupervisor.terminate_child(ZtlpGateway.SessionSupervisor, old_pid)

        :error ->
          :ok
      end

      # Use the client's SessionID from the HELLO packet (echoed in HELLO_ACK)
      session_id =
        case Packet.extract_session_id(packet_data) do
          {:ok, <<0::96>>} -> :crypto.strong_rand_bytes(12)
          {:ok, sid} -> sid
          _ -> :crypto.strong_rand_bytes(12)
        end

      # Extract service name from HELLO packet's dst_svc_id field
      service = Packet.extract_service_name(packet_data)

      opts = %{
        session_id: session_id,
        client_addr: client_addr,
        udp_socket: state.socket,
        static_pub: state.static_pub,
        static_priv: state.static_priv,
        service: service
      }

      case DynamicSupervisor.start_child(
             ZtlpGateway.SessionSupervisor,
             {Session, opts}
           ) do
        {:ok, pid} ->
          # Forward the HELLO packet to the new session
          Session.handle_packet(pid, packet_data, client_addr)

        {:error, reason} ->
          Logger.warning("[Listener] Failed to start session: #{inspect(reason)}")
      end
    else
      Logger.warning("[Listener] Max sessions (#{max}) reached, rejecting HELLO")
    end
  end
end
