defmodule ZtlpGateway.Session do
  @moduledoc """
  Per-session GenServer for the ZTLP Gateway.

  Each active ZTLP session gets its own Session process that manages:

  1. **Handshake state machine** — Noise_XX as responder
  2. **Decryption** — incoming ZTLP data → plaintext
  3. **Backend forwarding** — plaintext → TCP backend
  4. **Response encryption** — backend TCP data → ZTLP data packet
  5. **Replay protection** — sequence number tracking
  6. **Idle timeout** — configurable, default 5 minutes

  ## State Machine

      :awaiting_msg1 → (receive msg1) → :awaiting_msg3
                                      → (send msg2)
      :awaiting_msg3 → (receive msg3) → :established
                                      → (policy check)
                                      → (connect backend)
      :established   → (data packets) → decrypt + forward

  ## Lifecycle

  The Session is started by the Listener when a HELLO packet arrives.
  It registers itself in the SessionRegistry. When the session ends
  (timeout, error, or clean close), it unregisters and stops.
  """

  use GenServer

  require Logger

  alias ZtlpGateway.{
    Crypto,
    Handshake,
    Packet,
    SessionRegistry,
    Backend,
    PolicyEngine,
    Identity,
    AuditLog,
    Stats
  }

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type session_state :: :awaiting_msg1 | :awaiting_msg3 | :established

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc """
  Start a new session process.

  ## Parameters (as a map)
  - `:session_id` — 12-byte SessionID for this session (96-bit per ZTLP spec)
  - `:client_addr` — `{ip, port}` of the ZTLP client
  - `:udp_socket` — the gateway's UDP socket (for sending responses)
  - `:static_pub` — gateway's X25519 static public key
  - `:static_priv` — gateway's X25519 static private key
  - `:service` — target backend service name (default: "default")
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Deliver a packet to this session for processing.

  Called by the Listener after Layer 1+2 admission passes.
  The session handles the rest (handshake progression or decryption).
  """
  @spec handle_packet(pid(), binary(), {tuple(), non_neg_integer()}) :: :ok
  def handle_packet(pid, packet_data, from_addr) do
    GenServer.cast(pid, {:packet, packet_data, from_addr})
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    session_id = Map.fetch!(opts, :session_id)
    client_addr = Map.fetch!(opts, :client_addr)
    udp_socket = Map.fetch!(opts, :udp_socket)
    static_pub = Map.fetch!(opts, :static_pub)
    static_priv = Map.fetch!(opts, :static_priv)
    service = Map.get(opts, :service, "default")

    # Register in the session registry
    :ok = SessionRegistry.register(session_id, self())
    Stats.session_opened()

    # Initialize the Noise handshake as responder
    hs = Handshake.init_responder(static_pub, static_priv)

    timeout_ms = ZtlpGateway.Config.get(:session_timeout_ms)

    state = %{
      session_id: session_id,
      client_addr: client_addr,
      udp_socket: udp_socket,
      service: service,
      handshake: hs,
      phase: :awaiting_msg1,
      # Transport keys (set after handshake)
      # client→gateway decrypt key
      i2r_key: nil,
      # gateway→client encrypt key
      r2i_key: nil,
      # Sequence numbers for replay protection
      recv_seq: 0,
      send_seq: 0,
      # Backend connection
      backend_pid: nil,
      # Stats
      bytes_in: 0,
      bytes_out: 0,
      started_at: System.monotonic_time(:millisecond),
      # Timeout
      timeout_ms: timeout_ms,
      timer_ref: schedule_timeout(timeout_ms)
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:packet, packet_data, from_addr}, state) do
    Stats.bytes_received(byte_size(packet_data))

    # Reset idle timeout on every packet
    state = reset_timeout(state)

    case state.phase do
      :awaiting_msg1 ->
        handle_handshake_msg1(packet_data, from_addr, state)

      :awaiting_msg3 ->
        handle_handshake_msg3(packet_data, from_addr, state)

      :established ->
        handle_data_packet(packet_data, from_addr, state)
    end
  end

  # Backend sent data — encrypt and send back to client
  @impl true
  def handle_info({:backend_data, data}, state) do
    case encrypt_and_send(data, state) do
      {:ok, new_state} ->
        {:noreply, new_state}

      {:error, _reason} ->
        terminate_session(state, :encrypt_error)
    end
  end

  # Backend closed the TCP connection
  def handle_info(:backend_closed, state) do
    terminate_session(state, :backend_close)
  end

  # Backend error
  def handle_info({:backend_error, _reason}, state) do
    Stats.backend_error()
    terminate_session(state, :backend_error)
  end

  # Idle timeout
  def handle_info(:session_timeout, state) do
    terminate_session(state, :timeout)
  end

  # Ignore stale timers
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    # Clean up: unregister, close backend, log
    SessionRegistry.unregister(state.session_id)
    Stats.session_closed()

    if state.backend_pid && Process.alive?(state.backend_pid) do
      Backend.close(state.backend_pid)
    end

    duration = System.monotonic_time(:millisecond) - state.started_at

    AuditLog.session_terminated(
      state.session_id,
      :normal,
      duration,
      state.bytes_in,
      state.bytes_out
    )

    :ok
  end

  # ---------------------------------------------------------------------------
  # Handshake Message 1 — → e
  # ---------------------------------------------------------------------------

  defp handle_handshake_msg1(packet_data, _from_addr, state) do
    # Parse the packet to extract the handshake payload
    case Packet.parse(packet_data) do
      {:ok, %{type: :handshake, payload: payload}} ->
        case Handshake.handle_msg1(state.handshake, payload) do
          {:error, reason} ->
            Logger.warning("[Session] Handshake msg1 failed: #{inspect(reason)}")
            Stats.handshake_fail()
            {:stop, :normal, state}

          {hs, _empty_payload} ->
            # Create and send Message 2
            {hs, msg2_bytes} = Handshake.create_msg2(hs)

            # Wrap msg2 in a HELLO_ACK packet
            response = Packet.build_hello_ack(state.session_id, msg2_bytes)
            send_udp(state, response)

            {:noreply, %{state | handshake: hs, phase: :awaiting_msg3}}
        end

      _ ->
        {:noreply, state}
    end
  end

  # ---------------------------------------------------------------------------
  # Handshake Message 3 — → s, se
  # ---------------------------------------------------------------------------

  defp handle_handshake_msg3(packet_data, _from_addr, state) do
    case Packet.parse(packet_data) do
      {:ok, %{type: :handshake, payload: payload}} ->
        case Handshake.handle_msg3(state.handshake, payload) do
          {:error, reason} ->
            Logger.warning("[Session] Handshake msg3 failed: #{inspect(reason)}")
            Stats.handshake_fail()
            {:stop, :normal, state}

          {hs, _payload} ->
            # Derive transport keys
            {:ok, keys} = Handshake.split(hs)

            # Extract client identity from handshake
            remote_static = hs.rs
            identity = Identity.resolve_or_hex(remote_static)

            # Policy check — is this identity allowed to access the service?
            if PolicyEngine.authorize?(identity, state.service) do
              # Try to connect to the backend
              backends = ZtlpGateway.Config.get(:backends)

              case find_backend(backends, state.service) do
                {:ok, %{host: host, port: port}} ->
                  case Backend.start_link({host, port, self()}) do
                    {:ok, backend_pid} ->
                      Stats.handshake_ok()

                      AuditLog.session_established(
                        state.session_id,
                        remote_static,
                        state.client_addr,
                        state.service
                      )

                      {:noreply,
                       %{
                         state
                         | handshake: hs,
                           phase: :established,
                           i2r_key: keys.i2r_key,
                           r2i_key: keys.r2i_key,
                           backend_pid: backend_pid
                       }}

                    {:error, reason} ->
                      Logger.warning("[Session] Backend connect failed: #{inspect(reason)}")
                      Stats.backend_error()
                      {:stop, :normal, state}
                  end

                :error ->
                  Logger.warning("[Session] No backend configured for service: #{state.service}")
                  Stats.backend_error()
                  {:stop, :normal, state}
              end
            else
              # Policy denied
              Logger.info("[Session] Policy denied: #{identity} → #{state.service}")
              Stats.policy_denied()

              AuditLog.policy_denied(
                remote_static,
                state.client_addr,
                state.service,
                :not_authorized
              )

              {:stop, :normal, state}
            end
        end

      _ ->
        {:noreply, state}
    end
  end

  # ---------------------------------------------------------------------------
  # Data packets — decrypt and forward to backend
  # ---------------------------------------------------------------------------

  defp handle_data_packet(packet_data, _from_addr, state) do
    case Packet.parse(packet_data) do
      {:ok, %{type: :data, sequence: seq, payload: encrypted_payload}} ->
        # Replay protection: only accept packets with sequence > last seen
        if seq > state.recv_seq do
          # Decrypt the payload using the initiator→responder key
          # The nonce is derived from the sequence number
          nonce = <<0::32, seq::little-64>>

          # The encrypted payload is ciphertext + 16-byte tag appended
          if byte_size(encrypted_payload) >= 16 do
            ct_len = byte_size(encrypted_payload) - 16
            ct = binary_part(encrypted_payload, 0, ct_len)
            tag = binary_part(encrypted_payload, ct_len, 16)

            case Crypto.decrypt(state.i2r_key, nonce, ct, <<>>, tag) do
              :error ->
                Logger.warning("[Session] Decrypt failed for seq #{seq}")
                {:noreply, state}

              plaintext ->
                # Forward to backend
                if state.backend_pid do
                  Backend.send_data(state.backend_pid, plaintext)
                end

                new_state = %{
                  state
                  | recv_seq: seq,
                    bytes_in: state.bytes_in + byte_size(packet_data)
                }

                {:noreply, new_state}
            end
          else
            {:noreply, state}
          end
        else
          # Replayed or out-of-order packet — silently drop
          {:noreply, state}
        end

      _ ->
        {:noreply, state}
    end
  end

  # ---------------------------------------------------------------------------
  # Encrypt and send response to client
  # ---------------------------------------------------------------------------

  defp encrypt_and_send(plaintext, state) do
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>

    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, plaintext, <<>>)
    encrypted = ct <> tag

    # Build a data packet with a dummy auth tag (12 bytes of zeros for prototype)
    # In production, the header auth tag would be computed over the header fields
    header_auth_tag = :crypto.strong_rand_bytes(16)
    pkt = Packet.build_data(state.session_id, seq,
      header_auth_tag: header_auth_tag,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize(pkt)

    send_udp(state, packet)
    Stats.bytes_sent(byte_size(packet))

    {:ok, %{state | send_seq: seq, bytes_out: state.bytes_out + byte_size(packet)}}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp send_udp(%{udp_socket: socket, client_addr: {ip, port}}, data) do
    :gen_udp.send(socket, ip, port, data)
  end

  defp find_backend(backends, service) do
    case Enum.find(backends, fn b -> b.name == service end) do
      nil -> :error
      backend -> {:ok, backend}
    end
  end

  defp schedule_timeout(ms) do
    Process.send_after(self(), :session_timeout, ms)
  end

  defp reset_timeout(state) do
    if state.timer_ref, do: Process.cancel_timer(state.timer_ref)
    %{state | timer_ref: schedule_timeout(state.timeout_ms)}
  end

  defp terminate_session(state, reason) do
    duration = System.monotonic_time(:millisecond) - state.started_at

    AuditLog.session_terminated(
      state.session_id,
      reason,
      duration,
      state.bytes_in,
      state.bytes_out
    )

    {:stop, :normal, state}
  end
end
