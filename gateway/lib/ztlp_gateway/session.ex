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
  # Constants
  # ---------------------------------------------------------------------------

  # Tunnel frame types (must match Rust tunnel.rs constants)
  @frame_data 0x00
  @frame_ack 0x01
  @frame_fin 0x02
  @frame_nack 0x03
  @frame_reset 0x04
  @frame_close 0x05
  @frame_open 0x06

  # ARQ constants (KCP-inspired)
  @initial_rto_ms 500
  @min_rto_ms 200
  @max_rto_ms 10_000
  @max_retransmits 15
  @retransmit_check_interval_ms 50
  # Linger timeout: how long to keep session alive after backend closes
  # to allow retransmission of unacked data
  @linger_timeout_ms 15_000

  # Pacing: max unacked packets in flight (send window)
  @send_window_size 8
  # Pacing interval: ms between packet sends (spreads burst across time)
  @pacing_interval_ms 2

  # Maximum plaintext payload per ZTLP data packet.
  # Wire overhead: 46 (ZTLP header) + 9 (frame type + data_seq) + 16 (AEAD tag) = 71 bytes.
  # To keep the UDP datagram under 1280 bytes (IPv6 minimum MTU, safe for
  # any internet path including PPPoE, tunnels, and VPN encapsulation):
  #   1280 - 8 (UDP) - 20 (IP) = 1252 max UDP payload
  #   1252 - 71 (ZTLP overhead) = 1181 max plaintext
  # We round down to 1200 for a comfortable margin (wire = ~1271 bytes).
  @max_payload_bytes 1200

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
      # recv_seq starts at -1 so that seq=0 (first data packet) passes the > check
      recv_seq: -1,
      send_seq: 0,
      # Tunnel framing: data_seq for ordered reassembly
      send_data_seq: 0,
      # Backend connection
      backend_pid: nil,
      # Stats
      bytes_in: 0,
      bytes_out: 0,
      started_at: System.monotonic_time(:millisecond),
      # Timeout
      timeout_ms: timeout_ms,
      timer_ref: schedule_timeout(timeout_ms),
      # Buffer for packets that arrive before handshake completes
      pending_packets: [],
      # Send buffer for retransmission (KCP-inspired ARQ)
      # %{packet_seq => {plaintext_frame, sent_at_mono, retransmit_count, data_seq}}
      send_buffer: %{},
      rto_ms: @initial_rto_ms,
      srtt_ms: nil,
      rttvar_ms: nil,
      retransmit_timer_ref: nil,
      # Draining: backend closed, but we keep the session alive to retransmit
      draining: false,
      # Paced send queue: list of plaintext chunks waiting to be sent
      # Each entry is a raw plaintext (not yet framed/encrypted)
      send_queue: :queue.new(),
      # Stream multiplexing: %{stream_id => %{backend_pid: pid}}
      # When populated, the session is in multiplexed mode.
      streams: %{},
      pacing_timer_ref: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:packet, packet_data, from_addr}, state) do
    Stats.bytes_received(byte_size(packet_data))
    Logger.info("[Session] Received #{byte_size(packet_data)} bytes in phase=#{state.phase} from #{inspect(from_addr)}")

    # Reset idle timeout on every packet
    state = reset_timeout(state)

    case state.phase do
      :awaiting_msg1 ->
        # Check if it's a handshake packet; buffer data packets for later
        if Packet.handshake?(packet_data) do
          handle_handshake_msg1(packet_data, from_addr, state)
        else
          Logger.debug("[Session] Buffering #{byte_size(packet_data)} byte packet during msg1 phase")
          {:noreply, %{state | pending_packets: [{packet_data, from_addr} | state.pending_packets]}}
        end

      :awaiting_msg3 ->
        if Packet.handshake?(packet_data) do
          handle_handshake_msg3(packet_data, from_addr, state)
        else
          Logger.debug("[Session] Buffering #{byte_size(packet_data)} byte packet during msg3 phase")
          {:noreply, %{state | pending_packets: [{packet_data, from_addr} | state.pending_packets]}}
        end

      :established ->
        handle_data_packet(packet_data, from_addr, state)
    end
  end

  # Backend sent data — enqueue for paced sending
  @impl true
  def handle_info({:backend_data, data}, state) do
    # Chunk the plaintext data to keep each ZTLP packet under the path MTU.
    # Without chunking, a single TCP read can produce a 1460-byte payload
    # that becomes a 1531-byte ZTLP packet (1559 bytes on wire), requiring
    # IP fragmentation. Fragmented retransmits are unreliable on paths with
    # broken PMTUD or low MTU (PPPoE, tunnels).
    chunks = chunk_data(data, @max_payload_bytes)
    send_queue = Enum.reduce(chunks, state.send_queue, fn chunk, q ->
      :queue.in(chunk, q)
    end)
    state = %{state | send_queue: send_queue}

    # Try to send immediately if window allows
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Backend closed the TCP connection — enter draining mode
  # Keep session alive to drain send_queue + retransmit unacked data + FIN
  def handle_info(:backend_closed, state) do
    queue_len = :queue.len(state.send_queue)
    buf_len = map_size(state.send_buffer)

    if queue_len == 0 and buf_len == 0 do
      # Nothing queued or in flight — send FIN and terminate
      state = if state.r2i_key, do: send_fin(state), else: state
      terminate_session(state, :backend_close)
    else
      Logger.info("[Session] Backend closed, entering drain mode (#{queue_len} queued, #{buf_len} in send_buffer)")
      # Schedule linger timeout
      Process.send_after(self(), :linger_timeout, @linger_timeout_ms)
      # Ensure retransmit timer is running
      retransmit_timer_ref = schedule_retransmit_timer(state.retransmit_timer_ref, state.rto_ms)
      state = %{state | draining: true, backend_pid: nil, retransmit_timer_ref: retransmit_timer_ref}
      # Try to flush the queue — FIN will be sent when queue + buffer are both empty
      state = flush_send_queue(state)
      {:noreply, state}
    end
  end

  # Linger timeout expired — terminate even if send_buffer not empty
  def handle_info(:linger_timeout, state) do
    if state.draining do
      Logger.info("[Session] Linger timeout expired, #{map_size(state.send_buffer)} unacked packets remaining")
      terminate_session(state, :linger_timeout)
    else
      {:noreply, state}
    end
  end

  # Backend error (legacy single-stream)
  def handle_info({:backend_error, _reason}, state) do
    Stats.backend_error()
    terminate_session(state, :backend_error)
  end

  # ── Multiplexed stream backend messages ──

  # Backend sent data on a specific stream — enqueue with stream_id tag
  def handle_info({:backend_data, stream_id, data}, state) when is_integer(stream_id) do
    chunks = chunk_data(data, @max_payload_bytes - 4)  # 4 bytes for stream_id header
    send_queue = Enum.reduce(chunks, state.send_queue, fn chunk, q ->
      :queue.in({:stream, stream_id, chunk}, q)
    end)
    state = %{state | send_queue: send_queue}
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Backend closed on a specific stream — send stream FIN, clean up stream
  def handle_info({:backend_closed, stream_id}, state) when is_integer(stream_id) do
    Logger.info("[Session] Stream #{stream_id} backend closed")
    # Enqueue a stream-FIN marker so it gets sent after all pending data for this stream
    send_queue = :queue.in({:stream_fin, stream_id}, state.send_queue)
    streams = Map.delete(state.streams, stream_id)
    state = %{state | send_queue: send_queue, streams: streams}
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Backend error on a specific stream — close that stream, keep session alive
  def handle_info({:backend_error, stream_id, reason}, state) when is_integer(stream_id) do
    Logger.warning("[Session] Stream #{stream_id} backend error: #{inspect(reason)}")
    # Send stream close to client
    send_queue = :queue.in({:stream_close, stream_id}, state.send_queue)
    streams = Map.delete(state.streams, stream_id)
    state = %{state | send_queue: send_queue, streams: streams}
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Idle timeout
  def handle_info(:session_timeout, state) do
    terminate_session(state, :timeout)
  end

  # Pacing timer — send next packet from queue if window allows
  def handle_info(:pacing_tick, state) do
    state = %{state | pacing_timer_ref: nil}
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Retransmit timer — check send_buffer for timed-out packets
  def handle_info(:retransmit_check, state) do
    now = System.monotonic_time(:millisecond)

    {state, expired_count} =
      Enum.reduce(state.send_buffer, {state, 0}, fn {seq, {packet, sent_at, retransmit_count, ds}}, {acc, exp_count} ->
        elapsed = now - sent_at

        cond do
          retransmit_count >= @max_retransmits ->
            Logger.warning("[Session] RTO: data_seq=#{ds} exceeded #{@max_retransmits} retransmits, dropping")
            {%{acc | send_buffer: Map.delete(acc.send_buffer, seq)}, exp_count + 1}

          elapsed > per_packet_rto(acc.rto_ms, retransmit_count) ->
            # Re-encrypt with a NEW packet_seq to avoid anti-replay rejection
            # and nonce reuse. The stored `packet` is actually the plaintext frame.
            new_seq = acc.send_seq + 1
            new_nonce = <<0::32, new_seq::little-64>>
            {ct, tag} = Crypto.encrypt(acc.r2i_key, new_nonce, packet, <<>>)
            encrypted = ct <> tag
            new_pkt = Packet.build_data(acc.session_id, new_seq,
              payload: encrypted,
              payload_len: byte_size(encrypted)
            )
            new_packet = Packet.serialize_data_with_auth(new_pkt, acc.r2i_key)

            Logger.debug("[Session] RTO retransmit data_seq=#{ds} old_seq=#{seq} new_seq=#{new_seq} elapsed=#{elapsed}ms rto=#{per_packet_rto(acc.rto_ms, retransmit_count)}ms attempt=#{retransmit_count + 1}")
            send_udp(acc, new_packet)

            # Remove old entry, add new one with new seq
            updated_buffer = acc.send_buffer
              |> Map.delete(seq)
              |> Map.put(new_seq, {packet, now, retransmit_count + 1, ds})
            {%{acc | send_buffer: updated_buffer, send_seq: new_seq}, exp_count}

          true ->
            {acc, exp_count}
        end
      end)

    if expired_count > 0 do
      Logger.debug("[Session] RTO: dropped #{expired_count} packets exceeding max retransmits")
    end

    # Reschedule if buffer is non-empty
    retransmit_timer_ref =
      if map_size(state.send_buffer) > 0 do
        interval = min(div(state.rto_ms, 2), @retransmit_check_interval_ms)
        interval = max(interval, 10)
        Process.send_after(self(), :retransmit_check, interval)
      else
        nil
      end

    {:noreply, %{state | retransmit_timer_ref: retransmit_timer_ref}}
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
            {:ok, keys} = Handshake.split(hs, state.session_id)

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

                      new_state =
                        %{
                          state
                          | handshake: hs,
                            phase: :established,
                            i2r_key: keys.i2r_key,
                            r2i_key: keys.r2i_key,
                            backend_pid: backend_pid,
                            pending_packets: []
                        }

                      # Process any packets that arrived during handshake
                      new_state = process_pending_packets(Enum.reverse(state.pending_packets), new_state)

                      {:noreply, new_state}

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
      {:ok, %{type: type, packet_seq: seq, payload: encrypted_payload}} when type in [:data, :data_compact] ->
        Logger.info("[Session] Data packet: type=#{type} seq=#{seq} payload_len=#{byte_size(encrypted_payload)} recv_seq=#{state.recv_seq}")
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
                Logger.warning("[Session] Decrypt FAILED for seq #{seq}, key_len=#{byte_size(state.i2r_key)}, ct_len=#{ct_len}, tag_len=#{byte_size(tag)}")
                {:noreply, state}

              plaintext ->
                Logger.info("[Session] Decrypted #{byte_size(plaintext)} bytes, first_byte=#{:binary.at(plaintext, 0)}")
                state = %{state | recv_seq: seq, bytes_in: state.bytes_in + byte_size(packet_data)}
                handle_tunnel_frame(plaintext, state)
            end
          else
            Logger.warning("[Session] Payload too short: #{byte_size(encrypted_payload)} bytes")
            {:noreply, state}
          end
        else
          Logger.info("[Session] Replayed/out-of-order: seq=#{seq} <= recv_seq=#{state.recv_seq}")
          {:noreply, state}
        end

      {:ok, other} ->
        Logger.info("[Session] Non-data packet in established phase: type=#{Map.get(other, :type, :unknown)}")
        {:noreply, state}

      {:error, reason} ->
        Logger.warning("[Session] Packet parse failed: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  # Parse tunnel frame
  # Multiplexed mode: [FRAME_DATA | stream_id(4 BE) | payload]
  # Legacy mode: [FRAME_DATA | data_seq(8 BE) | payload]
  defp handle_tunnel_frame(<<@frame_data, rest::binary>>, state) do
    if map_size(state.streams) > 0 do
      # Multiplexed mode: [stream_id(4) | payload]
      <<stream_id::big-32, payload::binary>> = rest
      case Map.get(state.streams, stream_id) do
        %{backend_pid: pid} when pid != nil ->
          if byte_size(payload) > 0 do
            Logger.info("[Session] Stream #{stream_id} forwarding #{byte_size(payload)} bytes to backend: #{inspect(String.slice(payload, 0..60))}")
            Backend.send_data(pid, payload)
          end
        _ ->
          Logger.warning("[Session] Data for unknown stream #{stream_id}, dropping #{byte_size(payload)} bytes")
      end
      state = send_ack(state.recv_seq, state)
      {:noreply, state}
    else
      # Legacy single-stream mode: [data_seq(8) | payload]
      <<data_seq::big-64, payload::binary>> = rest
      Logger.info("[Session] FRAME_DATA data_seq=#{data_seq} payload_len=#{byte_size(payload)} backend_pid=#{inspect(state.backend_pid)}")
      if state.backend_pid && byte_size(payload) > 0 do
        Logger.info("[Session] Forwarding #{byte_size(payload)} bytes to backend: #{inspect(String.slice(payload, 0..60))}")
        Backend.send_data(state.backend_pid, payload)
      end
      state = send_ack(state.recv_seq, state)
      {:noreply, state}
    end
  end

  defp handle_tunnel_frame(<<@frame_ack, acked_data_seq::big-64, _rest::binary>>, state) do
    # Cumulative ACK from client: "I've received everything up to and including data_seq N"
    now = System.monotonic_time(:millisecond)

    {acked_entries, remaining} =
      Enum.split_with(state.send_buffer, fn {_seq, {_pkt, _sent_at, _rc, ds}} ->
        is_integer(ds) and ds <= acked_data_seq
      end)

    # Update RTT from acked entries (only non-retransmitted, per Karn's algorithm)
    state =
      Enum.reduce(acked_entries, state, fn {_seq, {_pkt, sent_at, retransmit_count, _ds}}, acc ->
        if retransmit_count == 0 do
          update_rtt(acc, now - sent_at)
        else
          acc
        end
      end)

    send_buffer = Map.new(remaining)

    Logger.debug("[Session] ACK data_seq=#{acked_data_seq}, removed #{length(acked_entries)} from send_buffer, #{map_size(send_buffer)} remaining")

    state = %{state | send_buffer: send_buffer}

    # ACK freed window space — try to flush more from the queue
    state = flush_send_queue(state)

    # If draining with empty queue and empty send_buffer, all data delivered
    if state.draining and map_size(state.send_buffer) == 0 and :queue.is_empty(state.send_queue) do
      Logger.info("[Session] All data ACKed during drain, terminating cleanly")
      terminate_session(state, :drain_complete)
    else
      {:noreply, state}
    end
  end

  defp handle_tunnel_frame(<<@frame_ack, _rest::binary>>, state) do
    # Malformed ACK (too short) — ignore
    {:noreply, state}
  end

  defp handle_tunnel_frame(<<@frame_nack, count::big-16, rest::binary>>, state) do
    # NACK from client: list of missing data_seqs to retransmit immediately
    nacked_data_seqs = parse_nack_seqs(rest, count, [])
    Logger.info("[Session] NACK received: #{count} missing data_seqs: #{inspect(nacked_data_seqs)}")

    now = System.monotonic_time(:millisecond)

    state =
      Enum.reduce(nacked_data_seqs, state, fn nacked_ds, acc ->
        # Find the send_buffer entry matching this data_seq
        case Enum.find(acc.send_buffer, fn {_seq, {_pkt, _sent_at, _rc, ds}} -> ds == nacked_ds end) do
          {seq, {plaintext_frame, _sent_at, retransmit_count, ds}} ->
            if retransmit_count < @max_retransmits do
              # Re-encrypt with new packet_seq (same reason as RTO retransmit)
              new_seq = acc.send_seq + 1
              new_nonce = <<0::32, new_seq::little-64>>
              {ct, tag} = Crypto.encrypt(acc.r2i_key, new_nonce, plaintext_frame, <<>>)
              encrypted = ct <> tag
              new_pkt = Packet.build_data(acc.session_id, new_seq,
                payload: encrypted,
                payload_len: byte_size(encrypted)
              )
              new_packet = Packet.serialize_data_with_auth(new_pkt, acc.r2i_key)

              Logger.info("[Session] NACK retransmit data_seq=#{ds} old_seq=#{seq} new_seq=#{new_seq} attempt=#{retransmit_count + 1}")
              send_udp(acc, new_packet)
              updated_buffer = acc.send_buffer
                |> Map.delete(seq)
                |> Map.put(new_seq, {plaintext_frame, now, retransmit_count + 1, ds})
              %{acc | send_buffer: updated_buffer, send_seq: new_seq}
            else
              Logger.warning("[Session] NACK retransmit data_seq=#{ds} exceeded max_retransmits, dropping")
              %{acc | send_buffer: Map.delete(acc.send_buffer, seq)}
            end

          nil ->
            Logger.debug("[Session] NACK for unknown data_seq=#{nacked_ds}, ignoring")
            acc
        end
      end)

    {:noreply, state}
  end

  defp handle_tunnel_frame(<<@frame_nack, _rest::binary>>, state) do
    # Malformed NACK (too short for count) — ignore
    {:noreply, state}
  end

  defp handle_tunnel_frame(<<@frame_reset, _rest::binary>>, state) do
    # Client is starting a new TCP stream — reconnect backend.
    # Clear ALL pending send state: the old backend's response data is
    # irrelevant to the new TCP connection. Without clearing, old response
    # chunks (with stale data_seqs) interleave with new response data,
    # causing out-of-order delivery to the client's VIP proxy.
    Logger.info("[Session] Received RESET frame, reconnecting backend (clearing #{:queue.len(state.send_queue)} queued + #{map_size(state.send_buffer)} in-flight)")
    if state.backend_pid && Process.alive?(state.backend_pid) do
      Backend.close(state.backend_pid)
    end

    # Cancel any pending retransmit/pacing timers
    state = cancel_timers(state)

    backends = ZtlpGateway.Config.get(:backends)

    case find_backend(backends, state.service) do
      {:ok, %{host: host, port: port}} ->
        case Backend.start_link({host, port, self()}) do
          {:ok, new_pid} ->
            {:noreply, %{state |
              backend_pid: new_pid,
              send_data_seq: 0,
              send_queue: :queue.new(),
              send_buffer: %{},
              draining: false
            }}

          {:error, _reason} ->
            terminate_session(state, :backend_reconnect_failed)
        end

      :error ->
        terminate_session(state, :no_backend)
    end
  end

  # FRAME_OPEN: client wants to open a new multiplexed stream
  defp handle_tunnel_frame(<<@frame_open, stream_id::big-32>>, state) do
    Logger.info("[Session] FRAME_OPEN stream_id=#{stream_id}")
    backends = ZtlpGateway.Config.get(:backends)

    case find_backend(backends, state.service) do
      {:ok, %{host: host, port: port}} ->
        case Backend.start_link({host, port, self(), stream_id}) do
          {:ok, pid} ->
            streams = Map.put(state.streams, stream_id, %{backend_pid: pid})
            Logger.info("[Session] Stream #{stream_id} opened, backend=#{inspect(pid)}, total_streams=#{map_size(streams)}")
            {:noreply, %{state | streams: streams}}

          {:error, reason} ->
            Logger.warning("[Session] Stream #{stream_id} backend connect failed: #{inspect(reason)}")
            # Send FRAME_CLOSE back to client for this stream
            send_queue = :queue.in({:stream_close, stream_id}, state.send_queue)
            state = %{state | send_queue: send_queue}
            state = flush_send_queue(state)
            {:noreply, state}
        end

      :error ->
        Logger.warning("[Session] No backend for service #{state.service}")
        {:noreply, state}
    end
  end

  # FRAME_CLOSE: client is closing a stream
  defp handle_tunnel_frame(<<@frame_close, stream_id::big-32>>, state) do
    Logger.info("[Session] FRAME_CLOSE stream_id=#{stream_id}")
    case Map.get(state.streams, stream_id) do
      %{backend_pid: pid} when pid != nil ->
        if Process.alive?(pid), do: Backend.close(pid)
      _ ->
        :ok
    end
    streams = Map.delete(state.streams, stream_id)
    {:noreply, %{state | streams: streams}}
  end

  defp handle_tunnel_frame(_other, state) do
    # Unknown frame type — ignore
    {:noreply, state}
  end

  # Send an ACK frame back to the client (returns updated state)
  defp send_ack(packet_seq, state) do
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>

    # ACK frame: [FRAME_ACK(1) | acked_packet_seq(8 BE)]
    ack_frame = <<@frame_ack, packet_seq::big-64>>
    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, ack_frame, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)

    send_udp(state, packet)
    %{state | send_seq: seq}
  end

  # ---------------------------------------------------------------------------
  # Encrypt and send response to client
  # ---------------------------------------------------------------------------

  # Flush the send queue: send packets as long as the send window allows.
  # Paces sends by scheduling a timer for the next packet if the queue
  # is non-empty but the window is full.
  defp flush_send_queue(state) do
    inflight = map_size(state.send_buffer)
    cond do
      :queue.is_empty(state.send_queue) ->
        # Nothing to send. If draining with empty buffer, we're done.
        if state.draining and inflight == 0 do
          Logger.info("[Session] Send queue and buffer both empty during drain, sending FIN")
          send_fin(state)
        else
          state
        end

      inflight >= @send_window_size ->
        # Window full — schedule pacing timer to retry
        state = schedule_pacing_timer(state)
        state

      true ->
        # Send one item from the queue
        {{:value, item}, remaining} = :queue.out(state.send_queue)
        state = %{state | send_queue: remaining}

        result = case item do
          {:stream, stream_id, plaintext} ->
            # Multiplexed data: [FRAME_DATA | stream_id(4 BE) | data_seq(8 BE) | payload]
            encrypt_and_send_stream(stream_id, plaintext, state)

          {:stream_fin, stream_id} ->
            # Stream FIN: [FRAME_FIN | stream_id(4 BE)]
            encrypt_and_send_control(<<@frame_fin, stream_id::big-32>>, state)

          {:stream_close, stream_id} ->
            # Stream close: [FRAME_CLOSE | stream_id(4 BE)]
            encrypt_and_send_control(<<@frame_close, stream_id::big-32>>, state)

          plaintext when is_binary(plaintext) ->
            # Legacy single-stream data
            encrypt_and_send(plaintext, state)
        end

        case result do
          {:ok, new_state} ->
            # If more in queue and window allows, schedule next send
            if not :queue.is_empty(remaining) do
              schedule_pacing_timer(new_state)
            else
              # Queue empty. If draining, check if we should send FIN
              if new_state.draining do
                # FIN will be sent when all buffered packets are ACKed
                new_state
              else
                new_state
              end
            end
          {:error, _reason} ->
            state
        end
    end
  end

  defp schedule_pacing_timer(%{pacing_timer_ref: nil} = state) do
    ref = Process.send_after(self(), :pacing_tick, @pacing_interval_ms)
    %{state | pacing_timer_ref: ref}
  end
  defp schedule_pacing_timer(state), do: state

  # Cancel any pending retransmit and pacing timers (used on RESET/cleanup).
  defp cancel_timers(state) do
    if state.retransmit_timer_ref, do: Process.cancel_timer(state.retransmit_timer_ref)
    if state.pacing_timer_ref, do: Process.cancel_timer(state.pacing_timer_ref)
    %{state | retransmit_timer_ref: nil, pacing_timer_ref: nil}
  end

  defp encrypt_and_send(plaintext, state) do
    seq = state.send_seq + 1
    data_seq = state.send_data_seq
    nonce = <<0::32, seq::little-64>>

    # Wrap in tunnel frame: [FRAME_DATA(1) | data_seq(8 BE) | payload]
    framed = <<@frame_data, data_seq::big-64, plaintext::binary>>

    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, framed, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)

    send_udp(state, packet)
    Stats.bytes_sent(byte_size(packet))

    # Store plaintext frame in send buffer for retransmission.
    # We store the plaintext (not encrypted packet) because retransmits
    # need a NEW packet_seq (nonce) — reusing the same nonce would be
    # a nonce-reuse violation AND the client's anti-replay window would
    # reject duplicate packet_seqs.
    now = System.monotonic_time(:millisecond)
    send_buffer = Map.put(state.send_buffer, seq, {framed, now, 0, data_seq})

    # Schedule retransmit timer if not already scheduled
    retransmit_timer_ref = schedule_retransmit_timer(state.retransmit_timer_ref, state.rto_ms)

    {:ok, %{state |
      send_seq: seq,
      send_data_seq: data_seq + 1,
      bytes_out: state.bytes_out + byte_size(packet),
      send_buffer: send_buffer,
      retransmit_timer_ref: retransmit_timer_ref
    }}
  end

  # Encrypt and send a multiplexed stream data frame.
  # Wire format: [FRAME_DATA | stream_id(4 BE) | data_seq(8 BE) | payload]
  defp encrypt_and_send_stream(stream_id, plaintext, state) do
    seq = state.send_seq + 1
    data_seq = state.send_data_seq
    nonce = <<0::32, seq::little-64>>

    framed = <<@frame_data, stream_id::big-32, data_seq::big-64, plaintext::binary>>

    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, framed, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)

    send_udp(state, packet)
    Stats.bytes_sent(byte_size(packet))

    now = System.monotonic_time(:millisecond)
    send_buffer = Map.put(state.send_buffer, seq, {framed, now, 0, data_seq})
    retransmit_timer_ref = schedule_retransmit_timer(state.retransmit_timer_ref, state.rto_ms)

    {:ok, %{state |
      send_seq: seq,
      send_data_seq: data_seq + 1,
      bytes_out: state.bytes_out + byte_size(packet),
      send_buffer: send_buffer,
      retransmit_timer_ref: retransmit_timer_ref
    }}
  end

  # Encrypt and send a control frame (FIN/CLOSE per stream — no retransmit needed).
  defp encrypt_and_send_control(control_frame, state) do
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>

    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, control_frame, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)

    send_udp(state, packet)
    Stats.bytes_sent(byte_size(packet))

    {:ok, %{state |
      send_seq: seq,
      bytes_out: state.bytes_out + byte_size(packet)
    }}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp send_udp(%{udp_socket: socket, client_addr: {ip, port}}, data) do
    :gen_udp.send(socket, ip, port, data)
  end

  defp find_backend(backends, service) do
    case Enum.find(backends, fn b -> b.name == service end) do
      nil ->
        # Fall back to "default" backend if the requested service isn't found
        case Enum.find(backends, fn b -> b.name == "default" end) do
          nil -> :error
          backend -> {:ok, backend}
        end

      backend ->
        {:ok, backend}
    end
  end

  defp schedule_timeout(ms) do
    Process.send_after(self(), :session_timeout, ms)
  end

  defp reset_timeout(state) do
    if state.timer_ref, do: Process.cancel_timer(state.timer_ref)
    %{state | timer_ref: schedule_timeout(state.timeout_ms)}
  end

  defp process_pending_packets([], state), do: state
  defp process_pending_packets([{packet_data, from_addr} | rest], state) do
    Logger.info("[Session] Processing buffered #{byte_size(packet_data)} byte packet")
    case handle_data_packet(packet_data, from_addr, state) do
      {:noreply, new_state} ->
        process_pending_packets(rest, new_state)
      {:stop, _reason, new_state} ->
        # Session terminating, stop processing
        new_state
    end
  end

  defp terminate_session(state, reason) do
    # Close all multiplexed stream backends
    Enum.each(state.streams, fn {_sid, %{backend_pid: pid}} ->
      if pid && Process.alive?(pid), do: Backend.close(pid)
    end)

    # Send FIN to client if we have transport keys and not already draining
    # (draining already sent FIN on entry)
    state =
      if state.r2i_key && !state.draining do
        send_fin(state)
      else
        state
      end

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

  # ---------------------------------------------------------------------------
  # ARQ helpers — send buffer, retransmit, RTT estimation
  # ---------------------------------------------------------------------------

  # Send FIN frame to client with final data_seq
  defp send_fin(state) do
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>
    fin_frame = <<@frame_fin, state.send_data_seq::big-64>>
    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, fin_frame, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)

    send_udp(state, packet)

    # Buffer the FIN plaintext frame for retransmission (not encrypted packet)
    now = System.monotonic_time(:millisecond)
    send_buffer = Map.put(state.send_buffer, seq, {fin_frame, now, 0, :fin})
    retransmit_timer_ref = schedule_retransmit_timer(state.retransmit_timer_ref, state.rto_ms)

    Logger.info("[Session] Sent FIN with final data_seq=#{state.send_data_seq}")

    %{state | send_seq: seq, send_buffer: send_buffer, retransmit_timer_ref: retransmit_timer_ref}
  end

  # Update RTT estimates using TCP-style EWMA (RFC 6298)
  defp update_rtt(state, rtt) when rtt > 0 do
    case state.srtt_ms do
      nil ->
        # First RTT measurement
        srtt = rtt
        rttvar = div(rtt, 2)
        rto = srtt + max(100, 4 * rttvar)
        rto = clamp_rto(rto)
        %{state | srtt_ms: srtt, rttvar_ms: rttvar, rto_ms: rto}

      srtt ->
        # Subsequent measurements: EWMA
        rttvar = div(3 * state.rttvar_ms, 4) + div(abs(rtt - srtt), 4)
        new_srtt = div(7 * srtt, 8) + div(rtt, 8)
        rto = new_srtt + max(100, 4 * rttvar)
        rto = clamp_rto(rto)
        %{state | srtt_ms: new_srtt, rttvar_ms: rttvar, rto_ms: rto}
    end
  end

  defp update_rtt(state, _rtt), do: state

  defp clamp_rto(rto) do
    rto |> max(@min_rto_ms) |> min(@max_rto_ms)
  end

  # Parse NACK payload: N x 8-byte big-endian data_seqs
  defp parse_nack_seqs(_rest, 0, acc), do: Enum.reverse(acc)
  defp parse_nack_seqs(<<ds::big-64, rest::binary>>, remaining, acc) when remaining > 0 do
    parse_nack_seqs(rest, remaining - 1, [ds | acc])
  end
  defp parse_nack_seqs(_rest, _remaining, acc), do: Enum.reverse(acc)

  # Schedule retransmit timer if not already scheduled
  defp schedule_retransmit_timer(nil, rto_ms) do
    interval = min(div(rto_ms, 2), @retransmit_check_interval_ms)
    interval = max(interval, 10)
    Process.send_after(self(), :retransmit_check, interval)
  end
  defp schedule_retransmit_timer(existing_ref, _rto_ms), do: existing_ref

  # Per-packet RTO with mild backoff (1.5x per attempt, KCP-style).
  # Pure exponential (2x) is too aggressive for high-loss paths — the later
  # retransmits are spaced too far apart. 1.5x is the KCP default.
  # Capped at @max_rto_ms.
  defp per_packet_rto(base_rto, retransmit_count) do
    backed_off = base_rto * :math.pow(1.5, retransmit_count) |> round()
    min(backed_off, @max_rto_ms)
  end

  # Split binary data into chunks of at most `max_size` bytes.
  defp chunk_data(data, max_size) when byte_size(data) <= max_size, do: [data]
  defp chunk_data(data, max_size) do
    chunk_data_acc(data, max_size, [])
  end

  defp chunk_data_acc(<<>>, _max_size, acc), do: Enum.reverse(acc)
  defp chunk_data_acc(data, max_size, acc) when byte_size(data) <= max_size do
    Enum.reverse([data | acc])
  end
  defp chunk_data_acc(data, max_size, acc) do
    <<chunk::binary-size(max_size), rest::binary>> = data
    chunk_data_acc(rest, max_size, [chunk | acc])
  end
end
