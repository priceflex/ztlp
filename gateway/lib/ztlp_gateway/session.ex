defmodule ZtlpGateway.Sack do
  @moduledoc """
  Pure-function helpers for Selective Acknowledgment (SACK) in ZTLP.

  Provides SACK block generation, serialization, and parsing used by
  `ZtlpGateway.Session` for selective retransmission. Extracted as a
  separate module for direct testability (like `ZtlpGateway.RecvWindow`
  and `ZtlpGateway.Rekey`).

  ## SACK ACK Format

  Extends the cumulative ACK frame with optional SACK blocks:

      [0x01 | cumulative_ack(8 BE) | sack_count(1) | sack_block_1_start(8 BE) | sack_block_1_end(8 BE) | ...]

  - `cumulative_ack`: highest contiguous delivered sequence (unchanged)
  - `sack_count`: number of SACK blocks (0 = legacy cumulative ACK, max 3)
  - Each SACK block: `[start_seq, end_seq]` — inclusive range of received-but-not-contiguous sequences

  When `sack_count` is 0, the frame is backward-compatible with legacy ACK.
  """

  @max_sack_blocks 3

  @doc "Maximum number of SACK blocks per ACK frame."
  def max_sack_blocks, do: @max_sack_blocks

  @doc """
  Build SACK blocks from the receive window state.

  Given the current `recv_window` MapSet and `recv_window_base`, finds
  contiguous ranges of received sequences above the base (which represent
  out-of-order packets). Returns up to 3 blocks as `[{start, end}, ...]`.

  Returns an empty list when there are no gaps (all received packets are
  contiguous from the base).
  """
  def build_sack_blocks(recv_window, recv_window_base) do
    recv_window
    |> MapSet.to_list()
    |> Enum.filter(&(&1 > recv_window_base))
    |> Enum.sort()
    |> chunk_contiguous()
    |> Enum.take(@max_sack_blocks)
  end

  @doc """
  Group a sorted list of integers into contiguous ranges.

  ## Examples

      iex> ZtlpGateway.Sack.chunk_contiguous([6, 7, 8, 11, 12, 13, 14, 15])
      [{6, 8}, {11, 15}]

      iex> ZtlpGateway.Sack.chunk_contiguous([])
      []
  """
  def chunk_contiguous([]), do: []
  def chunk_contiguous([first | rest]) do
    chunk_contiguous(rest, first, first, [])
  end

  defp chunk_contiguous([], start, stop, acc) do
    Enum.reverse([{start, stop} | acc])
  end
  defp chunk_contiguous([n | rest], start, stop, acc) when n == stop + 1 do
    chunk_contiguous(rest, start, n, acc)
  end
  defp chunk_contiguous([n | rest], start, stop, acc) do
    chunk_contiguous(rest, n, n, [{start, stop} | acc])
  end

  @doc """
  Encode a SACK ACK frame (without the FRAME_ACK type byte prefix — caller adds it).

  Returns the binary: `<<cumulative_ack::64, sack_count::8, sack_data::binary>>`

  The caller prepends `<<@frame_ack>>` before encrypting.
  """
  def encode_sack_ack(cumulative_ack, sack_blocks) do
    sack_data = Enum.reduce(sack_blocks, <<>>, fn {start, stop}, acc ->
      acc <> <<start::big-64, stop::big-64>>
    end)
    <<cumulative_ack::big-64, length(sack_blocks)::8, sack_data::binary>>
  end

  @doc """
  Parse SACK blocks from the trailing data after the cumulative ACK.

  Given `sack_count` and `sack_data` binary, returns a list of `{start, end}` tuples.
  Returns an empty list for count 0 or malformed data.
  """
  def parse_sack_blocks(0, _sack_data), do: []
  def parse_sack_blocks(count, sack_data) when is_integer(count) and count > 0 do
    parse_sack_blocks_loop(count, sack_data, [])
  end
  def parse_sack_blocks(_count, _sack_data), do: []

  defp parse_sack_blocks_loop(0, _data, acc), do: Enum.reverse(acc)
  defp parse_sack_blocks_loop(remaining, <<start::big-64, stop::big-64, rest::binary>>, acc) when remaining > 0 do
    parse_sack_blocks_loop(remaining - 1, rest, [{start, stop} | acc])
  end
  defp parse_sack_blocks_loop(_remaining, _data, acc), do: Enum.reverse(acc)

  @doc """
  Process incoming SACK blocks into a sacked_set MapSet.

  Takes existing sacked_set and a list of `{start, end}` SACK blocks,
  returns updated sacked_set with all sequences in the SACK ranges added.
  """
  def add_to_sacked_set(sacked_set, sack_blocks) do
    Enum.reduce(sack_blocks, sacked_set, fn {start, stop}, acc ->
      Enum.reduce(start..stop, acc, fn seq, inner_acc ->
        MapSet.put(inner_acc, seq)
      end)
    end)
  end

  @doc """
  Prune the sacked_set by removing sequences at or below the cumulative ACK.

  These sequences are fully acknowledged and no longer need tracking.
  """
  def prune_sacked_set(sacked_set, cumulative_ack) do
    sacked_set
    |> Enum.filter(fn seq -> seq > cumulative_ack end)
    |> MapSet.new()
  end
end

defmodule ZtlpGateway.Rekey do
  @moduledoc """
  Pure-function helpers for FRAME_REKEY session key rotation.

  Provides key derivation and rekey state management used by
  `ZtlpGateway.Session` for periodic key rotation. Extracted as a
  separate module for direct testability (like `ZtlpGateway.RecvWindow`).

  ## Protocol

  FRAME_REKEY (0x0A) rotates encryption keys every 2^32 packets or 24 hours
  (whichever comes first) without disconnecting.

  1. Gateway sends `<<0x0A, key_material::32-bytes>>` encrypted with current r2i_key
  2. Client ACKs with `<<0x0A, client_key_material::32-bytes>>` encrypted with current i2r_key
  3. Both sides derive new keys: `BLAKE2s(current_key || key_material)`
  4. Keys switch atomically after ACK
  """

  @default_rekey_interval_ms 86_400_000
  @default_rekey_packet_limit 4_294_967_296

  @doc "Returns the default rekey interval in milliseconds (24 hours)."
  def default_interval_ms, do: @default_rekey_interval_ms

  @doc "Returns the default rekey packet limit (2^32)."
  def default_packet_limit, do: @default_rekey_packet_limit

  @doc """
  Create initial rekey state fields.

  Returns a map of rekey-related fields to merge into the session state.
  """
  def initial_state(opts \\ %{}) do
    %{
      rekey_packet_count: 0,
      rekey_interval_ms: Map.get(opts, :rekey_interval_ms, @default_rekey_interval_ms),
      rekey_packet_limit: Map.get(opts, :rekey_packet_limit, @default_rekey_packet_limit),
      rekey_pending: false,
      rekey_timer_ref: nil,
      pending_r2i_key: nil,
      pending_i2r_key: nil,
      rekey_count: 0
    }
  end

  @doc """
  Derive a new key from the current key and fresh key material using BLAKE2s.

  Returns a 32-byte binary.
  """
  def derive_new_key(current_key, key_material) do
    :crypto.hash(:blake2s, current_key <> key_material)
  end

  @doc """
  Check whether a rekey should be initiated based on the current state.

  Returns `:initiate` if a rekey should start, or `:skip` with a reason.
  """
  def should_rekey?(state) do
    cond do
      state.rekey_pending ->
        {:skip, :already_pending}

      state.rekey_packet_count >= state.rekey_packet_limit ->
        :initiate

      true ->
        {:skip, :below_threshold}
    end
  end

  @doc """
  Apply rekey initiation to state: set pending flag and compute pending r2i key.

  Takes the current state and key_material (32 random bytes).
  Returns updated state fields as a map (caller merges into full state).
  """
  def initiate(state, key_material) do
    pending_r2i = derive_new_key(state.r2i_key, key_material)

    %{
      rekey_pending: true,
      pending_r2i_key: pending_r2i
    }
  end

  @doc """
  Complete a rekey after receiving the client's ACK with their key material.

  Returns updated state fields as a map, or `:not_pending` if no rekey was in progress.
  """
  def complete(state, client_key_material) do
    if state.rekey_pending do
      new_i2r = derive_new_key(state.i2r_key, client_key_material)

      {:ok,
        %{
          r2i_key: state.pending_r2i_key,
          i2r_key: new_i2r,
          rekey_pending: false,
          pending_r2i_key: nil,
          pending_i2r_key: nil,
          rekey_packet_count: 0,
          rekey_count: state.rekey_count + 1
        }}
    else
      :not_pending
    end
  end
end

defmodule ZtlpGateway.RecvWindow do
  @moduledoc """
  Pure-function sliding receive window for out-of-order packet acceptance.

  Tracks received packet sequence numbers within a fixed-size window and
  buffers payloads for in-order delivery. This module is used by
  `ZtlpGateway.Session` for its receive path and is also directly testable.
  """

  @recv_window_size 256

  @doc "Returns the window size constant."
  def window_size, do: @recv_window_size

  @doc """
  Create a new receive window state.

  With no arguments, creates an unanchored window — the base will be set
  to the first accepted packet's sequence number. Pass an integer base
  to create a window anchored at that sequence.
  """
  def new(base \\ :unset) do
    %{
      recv_window: MapSet.new(),
      recv_window_base: base,
      recv_buffer: %{}
    }
  end

  @doc """
  Attempt to accept a packet with the given sequence number and data.

  If the window base is `:unset`, the first accepted packet anchors the window.

  Returns:
  - `{:ok, window_state}` — packet accepted and added to buffer
  - `{:duplicate, :below_window}` — seq is below the window base (already delivered)
  - `{:duplicate, :already_received}` — seq is within window but already received
  - `{:rejected, :beyond_window}` — seq is beyond the window (too far ahead)
  """
  def accept(window, seq, data) do
    # Anchor the window on first packet if unset
    window =
      if window.recv_window_base == :unset do
        %{window | recv_window_base: seq}
      else
        window
      end

    cond do
      seq < window.recv_window_base ->
        {:duplicate, :below_window}

      seq >= window.recv_window_base + @recv_window_size ->
        {:rejected, :beyond_window}

      MapSet.member?(window.recv_window, seq) ->
        {:duplicate, :already_received}

      true ->
        {:ok, %{window |
          recv_window: MapSet.put(window.recv_window, seq),
          recv_buffer: Map.put(window.recv_buffer, seq, data)
        }}
    end
  end

  @doc """
  Deliver as many contiguous packets as possible starting from the window base.

  Returns `{delivered_packets, new_window_state}` where `delivered_packets`
  is an ordered list of `{seq, data}` tuples.
  """
  def deliver(window) do
    deliver_loop(window, [])
  end

  defp deliver_loop(window, acc) do
    base = window.recv_window_base
    if MapSet.member?(window.recv_window, base) do
      data = window.recv_buffer[base]
      window = %{window |
        recv_window: MapSet.delete(window.recv_window, base),
        recv_buffer: Map.delete(window.recv_buffer, base),
        recv_window_base: base + 1
      }
      deliver_loop(window, [{base, data} | acc])
    else
      {Enum.reverse(acc), window}
    end
  end

  @doc """
  Returns the cumulative ACK value: the highest contiguously delivered sequence.
  This is `recv_window_base - 1`. Returns `nil` if no packets have been delivered
  (base is still at the initial value or `:unset`).
  """
  def cumulative_ack(window, initial_base \\ :unset) do
    cond do
      window.recv_window_base == :unset -> nil
      window.recv_window_base == initial_base -> nil
      true -> window.recv_window_base - 1
    end
  end

  @doc "Returns the number of buffered (out-of-order) packets."
  def buffered_count(window), do: map_size(window.recv_buffer)
end

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
    Bbr,
    Config,
    Crypto,
    Handshake,
    Packet,
    Rekey,
    Sack,
    SessionRegistry,
    Backend,
    BackendPool,
    PolicyEngine,
    Identity,
    AuditLog,
    AuditCollector,
    Stats,
    CertProvisioner,
    TlsTerminator
  }

  # ---------------------------------------------------------------------------
  # Constants
  # ---------------------------------------------------------------------------

  # Sliding receive window size for out-of-order packet acceptance.
  # Packets within [recv_window_base, recv_window_base + window_size) are
  # accepted and buffered; delivered to the backend in sequence order.
  @recv_window_size 256

  # Tunnel frame types (must match Rust tunnel.rs constants)
  @frame_data 0x00
  @frame_ack 0x01
  @frame_fin 0x02
  @frame_nack 0x03
  @frame_reset 0x04
  @frame_close 0x05
  @frame_open 0x06
  @frame_rekey 0x0A

  # ARQ constants (KCP-inspired, tuned for relay paths)
  # Default initial RTO accommodates full relay round-trip:
  # phone → cell tower (50-200ms) → internet → relay → gateway → back.
  # The adaptive EWMA (RFC 6298) converges to actual RTT within 3-4 packets.
  @initial_rto_ms 300
  @min_rto_ms 100
  @max_rto_ms 30_000
  @max_retransmits 20
  @retransmit_check_interval_ms 50
  # Linger timeout removed — legacy sessions no longer drain on backend close.
  # The :linger_timeout handler remains as a safety no-op.

  # Congestion control (TCP-like AIMD)
  # Initial congestion window — 64 covers up to ~77KB without slow start.
  # This handles concurrent 5x GET 10KB (45 packets) in a single burst,
  # plus small requests without needing slow start at all.
  @initial_cwnd 64
  # Maximum congestion window (packets). 256 × 1200 = 307KB.
  # Conservative max to avoid overwhelming cellular/relay paths.
  @max_cwnd 256
  # Minimum cwnd (never go below this)
  @min_cwnd 4
  # Slow-start threshold — switch to linear growth at 128 packets (153KB)
  @initial_ssthresh 128

  # Toggle BBR congestion control (true = BBR, false = legacy AIMD)
  @use_bbr true

  # Pacing interval: ms between burst sends
  @pacing_interval_ms 1
  # Max packets sent per pacing tick — limits instantaneous burst
  @burst_size 8

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

    # Register in the session registry (with client_addr for dedup lookup)
    :ok = SessionRegistry.register(session_id, self(), client_addr)
    Stats.session_opened()

    # Initialize the Noise handshake as responder
    hs = Handshake.init_responder(static_pub, static_priv)

    timeout_ms = Config.get(:session_timeout_ms)

    rekey_state = Rekey.initial_state()

    state =
      %{
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
        # Sliding receive window for out-of-order packet acceptance.
        # Replaces strict recv_seq > check with a window that buffers and
        # reorders packets — critical for cellular where reordering is common.
        # recv_window_base starts as :unset; the first accepted data packet
        # anchors the window at that sequence number.
        recv_window: MapSet.new(),
        recv_window_base: :unset,
        recv_buffer: %{},
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
        # Backend address for legacy reconnection on idle-close
        backend_addr: nil,
        # Stream multiplexing: %{stream_id => %{backend_pid: pid}}
        # When populated, the session is in multiplexed mode.
        streams: %{},
        mux_mode: false,
        pacing_timer_ref: nil,
        # Congestion control — BBR (default) or AIMD (fallback)
        bbr: if(@use_bbr, do: Bbr.new(), else: nil),
        cwnd: @initial_cwnd,
        ssthresh: @initial_ssthresh,
        # Track data_seq of last ACK for duplicate detection
        last_acked_data_seq: -1,
        # SACK: set of data_seqs that have been selectively acknowledged
        # by the client. Retransmit logic skips these sequences.
        sacked_set: MapSet.new()
      }
      |> Map.merge(rekey_state)

    {:ok, state}
  end

  @impl true
  def handle_cast({:packet, packet_data, from_addr}, state) do
    Stats.bytes_received(byte_size(packet_data))
    Logger.debug("[Session] Received #{byte_size(packet_data)} bytes in phase=#{state.phase} from #{inspect(from_addr)}")

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

  # Backend closed the TCP connection
  # In mux mode: drain that stream's data and keep session alive (handled separately)
  # In legacy mode: backend may close idle connections (e.g. vaultwarden HTTP timeout).
  # Instead of killing the session, clear backend_pid so it reconnects on next data.
  def handle_info(:backend_closed, state) do
    if state.mux_mode do
      # Mux mode shouldn't get bare :backend_closed (uses {:backend_closed, stream_id}).
      # If it does, ignore — individual stream closures handle their own cleanup.
      Logger.warning("[Session] Unexpected bare :backend_closed in mux mode, ignoring")
      {:noreply, state}
    else
      queue_len = :queue.len(state.send_queue)
      buf_len = map_size(state.send_buffer)

      # For legacy sessions, keep alive for backend reconnect instead of draining.
      # Even if there are a few unacked packets in send_buffer, those will be
      # retransmitted by the existing retransmit timer. No need to kill the session.
      Logger.info("[Session] Legacy backend closed (#{queue_len} queued, #{buf_len} in send_buffer, cwnd=#{Float.round(state.cwnd + 0.0, 1)}), flushing + FIN")
      state = %{state | backend_pid: nil}
      # Flush remaining queued data to the client — the backend sent its response
      # and closed, but we still need to deliver the queued packets.
      # Then queue a FIN so the client knows the response is complete.
      state = if queue_len > 0 or buf_len > 0 do
        # Queue FIN after remaining data
        send_queue = :queue.in(:legacy_fin, state.send_queue)
        state = %{state | send_queue: send_queue}
        state = flush_send_queue(state)
        Logger.info("[Session] After flush: #{:queue.len(state.send_queue)} queued, #{map_size(state.send_buffer)} in send_buffer, pacing_timer=#{inspect(state.pacing_timer_ref != nil)}")
        state
      else
        state
      end
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

  # ── TLS terminator messages ──

  # Decrypted data from TLS bridge — forward to the backend
  def handle_info({:tls_decrypted, stream_id, data}, state) do
    case Map.get(state.streams, stream_id) do
      %{backend_pid: pid} when pid != nil ->
        Backend.send_data(pid, data)
      _ ->
        Logger.warning("[Session] TLS decrypted data for unknown stream #{stream_id}")
    end
    {:noreply, state}
  end

  # TLS bridge closed — close the mux stream
  def handle_info({:tls_closed, stream_id}, state) do
    Logger.info("[Session] TLS bridge closed for stream #{stream_id}")
    case Map.get(state.streams, stream_id) do
      %{backend_pid: pid, tls_socket: sock} ->
        if pid && Process.alive?(pid), do: Backend.close(pid)
        if sock, do: :gen_tcp.close(sock)
      _ -> :ok
    end
    send_queue = :queue.in({:stream_close, stream_id}, state.send_queue)
    streams = Map.delete(state.streams, stream_id)
    state = %{state | send_queue: send_queue, streams: streams}
    state = flush_send_queue(state)
    {:noreply, state}
  end

  # Encrypted TLS response data from the local socket pair.
  # When the TLS bridge encrypts backend response data, it comes out
  # the client_socket side as raw bytes. We send these to the phone
  # via the ZTLP mux stream.
  def handle_info({:tcp, socket, data}, state) do
    # Find which stream owns this socket
    case find_stream_by_tls_socket(state.streams, socket) do
      {stream_id, _stream} ->
        chunks = chunk_data(data, @max_payload_bytes - 4)
        send_queue = Enum.reduce(chunks, state.send_queue, fn chunk, q ->
          :queue.in({:stream, stream_id, chunk}, q)
        end)
        state = %{state | send_queue: send_queue}
        state = flush_send_queue(state)
        {:noreply, state}

      nil ->
        # Not a TLS socket — might be a stale connection
        {:noreply, state}
    end
  end

  def handle_info({:tcp_closed, socket}, state) do
    case find_stream_by_tls_socket(state.streams, socket) do
      {stream_id, _} ->
        Logger.info("[Session] TLS client socket closed for stream #{stream_id}")
        send(self(), {:tls_closed, stream_id})
      _ -> :ok
    end
    {:noreply, state}
  end

  # ── Multiplexed stream backend messages ──

  # Backend sent data on a specific stream — enqueue with stream_id tag
  # For TLS-terminated streams, route through TLS bridge for re-encryption
  def handle_info({:backend_data, stream_id, data}, state) when is_integer(stream_id) do
    case Map.get(state.streams, stream_id) do
      %{tls_state: :active, tls_bridge_pid: bridge_pid} when bridge_pid != nil ->
        # TLS stream: send to bridge for encryption, encrypted data comes
        # back via {:tcp, client_socket, encrypted_data} in handle_info
        send(bridge_pid, {:backend_response, data})
        {:noreply, state}

      _ ->
        # Plain stream: send directly
        chunks = chunk_data(data, @max_payload_bytes - 4)
        send_queue = Enum.reduce(chunks, state.send_queue, fn chunk, q ->
          :queue.in({:stream, stream_id, chunk}, q)
        end)
        state = %{state | send_queue: send_queue}
        state = flush_send_queue(state)
        {:noreply, state}
    end
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
    queue_len = :queue.len(state.send_queue)
    buf_len = map_size(state.send_buffer)
    if queue_len > 0 do
      Logger.debug("[Session] pacing_tick: #{queue_len} queued, #{buf_len} in send_buffer, cwnd=#{Float.round(state.cwnd + 0.0, 1)}")
    end
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
          # Skip SACK'd sequences — the client already has them
          is_integer(ds) and MapSet.member?(acc.sacked_set, ds) ->
            Logger.debug("[Session] Skipping retransmit for SACK'd data_seq=#{ds}")
            {%{acc | send_buffer: Map.delete(acc.send_buffer, seq)}, exp_count}

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

            # Multiplicative decrease on loss (only once per loss event)
            # BBR does not reduce cwnd on loss — it's model-based, not loss-based
            acc = if not @use_bbr and retransmit_count == 0 do
              new_ssthresh = max(trunc(acc.cwnd / 2), @min_cwnd)
              new_cwnd = max(new_ssthresh, @min_cwnd)
              Logger.debug("[Session] Loss detected: cwnd #{Float.round(acc.cwnd, 1)} → #{new_cwnd}, ssthresh → #{new_ssthresh}")
              %{acc | cwnd: new_cwnd, ssthresh: new_ssthresh}
            else
              acc
            end

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

  # ── Async backend connect results (mux streams) ──

  # Backend connection succeeded — transition stream to :connected, flush buffer
  def handle_info({:backend_connect_result, stream_id, {:ok, pid}}, state) do
    case Map.get(state.streams, stream_id) do
      %{state: :connecting, connect_timeout_ref: tref} = stream ->
        # Cancel the connect timeout
        if tref, do: Process.cancel_timer(tref)

        # Link the backend to this session (it was unlinked from the spawner)
        Process.link(pid)

        Logger.info("[Session] Stream #{stream_id} connected, flushing #{length(stream.buffer)} buffered chunks")

        # Flush buffered data to the backend (buffer is prepend-order, reverse for FIFO)
        flush_stream_buffer(stream, pid)

        updated = %{stream |
          state: :connected,
          backend_pid: pid,
          buffer: [],
          connect_timeout_ref: nil
        }
        streams = Map.put(state.streams, stream_id, updated)

        if updated.tls_creds do
          Logger.info("[Session] Stream #{stream_id} opened with TLS termination (service=#{updated.service}), total_streams=#{map_size(streams)}")
        else
          Logger.info("[Session] Stream #{stream_id} opened (service=#{updated.service}), total_streams=#{map_size(streams)}")
        end

        # Audit: stream opened
        AuditCollector.log_event(%{
          event: "stream.opened",
          component: "gateway",
          level: "info",
          service: updated.service,
          details: %{
            session_id: Base.encode16(state.session_id),
            stream_id: stream_id,
            total_streams: map_size(streams)
          }
        })

        {:noreply, %{state | streams: streams}}

      _ ->
        # Stream was already closed/removed (e.g. client sent FRAME_CLOSE during connect).
        # Close the backend we just connected since nobody needs it.
        if Process.alive?(pid), do: BackendPool.close(pid)
        Logger.info("[Session] Stream #{stream_id} connect result arrived but stream already gone, closing backend")
        {:noreply, state}
    end
  end

  # Backend connection failed — send FRAME_CLOSE to client, remove stream
  def handle_info({:backend_connect_result, stream_id, {:error, reason}}, state) do
    case Map.get(state.streams, stream_id) do
      %{state: :connecting, connect_timeout_ref: tref} ->
        if tref, do: Process.cancel_timer(tref)
        Logger.warning("[Session] Stream #{stream_id} backend connect failed: #{inspect(reason)}")
        send_queue = :queue.in({:stream_close, stream_id}, state.send_queue)
        streams = Map.delete(state.streams, stream_id)
        state = %{state | send_queue: send_queue, streams: streams}
        state = flush_send_queue(state)
        {:noreply, state}

      _ ->
        # Stream already gone — nothing to do
        {:noreply, state}
    end
  end

  # Connect timeout expired — close the stream if still connecting
  def handle_info({:connect_timeout, stream_id}, state) do
    case Map.get(state.streams, stream_id) do
      %{state: :connecting} ->
        Logger.warning("[Session] Stream #{stream_id} connect timeout (10s), sending FRAME_CLOSE")
        send_queue = :queue.in({:stream_close, stream_id}, state.send_queue)
        streams = Map.delete(state.streams, stream_id)
        state = %{state | send_queue: send_queue, streams: streams}
        state = flush_send_queue(state)
        {:noreply, state}

      _ ->
        # Stream already connected or gone — ignore stale timeout
        {:noreply, state}
    end
  end

  # Rekey timer — initiate key rotation if not already pending
  def handle_info(:rekey_timer, state) do
    if state.phase == :established and not state.rekey_pending do
      Logger.info("[Session] Rekey timer fired, initiating key rotation")
      state = do_initiate_rekey(state)
      {:noreply, state}
    else
      # Reschedule if pending (will be rescheduled after completion)
      {:noreply, state}
    end
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

    # Audit: session terminated
    AuditCollector.log_event(%{
      event: "session.terminated",
      component: "gateway",
      level: "info",
      details: %{
        session_id: Base.encode16(state.session_id),
        reason: "normal",
        duration_ms: duration,
        bytes_in: state.bytes_in,
        bytes_out: state.bytes_out
      }
    })

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
              backends = Config.get(:backends)

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

                      # Start rekey timer for periodic key rotation
                      rekey_timer_ref = Process.send_after(self(), :rekey_timer, state.rekey_interval_ms)

                      new_state =
                        %{
                          state
                          | handshake: hs,
                            phase: :established,
                            i2r_key: keys.i2r_key,
                            r2i_key: keys.r2i_key,
                            backend_pid: backend_pid,
                            backend_addr: {host, port, self()},
                            pending_packets: [],
                            rekey_timer_ref: rekey_timer_ref
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
        Logger.debug("[Session] Data packet: type=#{type} seq=#{seq} payload_len=#{byte_size(encrypted_payload)} window_base=#{state.recv_window_base}")

        # Sliding receive window: accept packets within
        # [recv_window_base, recv_window_base + @recv_window_size).
        # On the first data packet, the window base is anchored to that seq.
        state =
          if state.recv_window_base == :unset do
            %{state | recv_window_base: seq}
          else
            state
          end

        cond do
          # Already delivered (below window base)
          seq < state.recv_window_base ->
            Logger.debug("[Session] Duplicate seq=#{seq} below base=#{state.recv_window_base}")
            {:noreply, state}

          # Beyond window (too far ahead)
          seq >= state.recv_window_base + @recv_window_size ->
            Logger.debug("[Session] Seq=#{seq} beyond window max=#{state.recv_window_base + @recv_window_size - 1}")
            {:noreply, state}

          # Already received (within window but duplicate)
          MapSet.member?(state.recv_window, seq) ->
            Logger.debug("[Session] Duplicate seq=#{seq} already in window")
            {:noreply, state}

          # Within window, not yet received — decrypt and accept
          true ->
            decrypt_and_accept(packet_data, seq, encrypted_payload, state)
        end

      {:ok, other} ->
        Logger.debug("[Session] Non-data packet in established phase: type=#{Map.get(other, :type, :unknown)}")
        {:noreply, state}

      {:error, reason} ->
        Logger.warning("[Session] Packet parse failed: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  # Decrypt a packet and, on success, add it to the receive window buffer.
  # Then deliver as many in-order packets as possible.
  defp decrypt_and_accept(packet_data, seq, encrypted_payload, state) do
    # Decrypt the payload using the initiator→responder key
    # The nonce is derived from the packet sequence number
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
          Logger.debug("[Session] Decrypted #{byte_size(plaintext)} bytes, first_byte=#{:binary.at(plaintext, 0)}")
          # Accept: add to window and buffer
          state = %{state |
            recv_window: MapSet.put(state.recv_window, seq),
            recv_buffer: Map.put(state.recv_buffer, seq, plaintext),
            bytes_in: state.bytes_in + byte_size(packet_data)
          }
          # Deliver as many contiguous packets as possible
          deliver_recv_window(state)
      end
    else
      Logger.warning("[Session] Payload too short: #{byte_size(encrypted_payload)} bytes")
      {:noreply, state}
    end
  end

  # Deliver buffered packets in sequence order starting from recv_window_base.
  # Each delivered packet is passed to handle_tunnel_frame/2.
  # After delivery, sends a cumulative ACK for the highest contiguous seq.
  defp deliver_recv_window(state) do
    case deliver_recv_window_loop(state, false) do
      {:stop, reason, stop_state} ->
        {:stop, reason, stop_state}

      {:ok, new_state, true} ->
        # Delivered at least one packet — send cumulative ACK
        new_state = send_ack(new_state.recv_window_base - 1, new_state)
        {:noreply, new_state}

      {:ok, new_state, false} ->
        # No contiguous delivery possible (gap at base), packet is buffered
        {:noreply, new_state}
    end
  end

  defp deliver_recv_window_loop(state, delivered_any) do
    base = state.recv_window_base
    if MapSet.member?(state.recv_window, base) do
      plaintext = state.recv_buffer[base]
      # Advance window BEFORE delivering, so handle_tunnel_frame sees updated state
      state = %{state |
        recv_window: MapSet.delete(state.recv_window, base),
        recv_buffer: Map.delete(state.recv_buffer, base),
        recv_window_base: base + 1
      }
      case handle_tunnel_frame(plaintext, state) do
        {:noreply, new_state} ->
          deliver_recv_window_loop(new_state, true)

        {:stop, reason, stop_state} ->
          {:stop, reason, stop_state}
      end
    else
      {:ok, state, delivered_any}
    end
  end

  # Parse tunnel frame
  # Multiplexed mode: [FRAME_DATA | stream_id(4 BE) | payload]
  # Legacy mode: [FRAME_DATA | data_seq(8 BE) | payload]
  #
  # IMPORTANT: Use `mux_mode` flag (set on first FRAME_OPEN) instead of
  # checking map_size(streams) > 0. There's a race between FRAME_CLOSE
  # removing the last stream and the next FRAME_OPEN arriving — during that
  # window, streams is empty but the client is still in mux mode. Without
  # this flag, the FRAME_DATA gets misinterpreted as legacy format.
  defp handle_tunnel_frame(<<@frame_data, rest::binary>>, state) do
    if state.mux_mode do
      # Multiplexed mode: [stream_id(4) | payload]
      <<stream_id::big-32, payload::binary>> = rest
      state =
        case Map.get(state.streams, stream_id) do
          %{tls_state: :active, tls_socket: tls_sock} when tls_sock != nil ->
            # TLS-terminated stream: write encrypted data to local TLS bridge socket
            if byte_size(payload) > 0 do
              :gen_tcp.send(tls_sock, payload)
            end
            state

          %{tls_state: :pending_handshake, tls_creds: creds} = stream ->
            # First data on a TLS stream — start the TLS bridge and write the ClientHello
            case TlsTerminator.start_bridge(
              creds.cert_pem, creds.key_pem, creds.chain_pem,
              self(), stream_id
            ) do
              {:ok, client_socket, bridge_pid} ->
                if byte_size(payload) > 0 do
                  :gen_tcp.send(client_socket, payload)
                end
                updated = %{stream | tls_state: :active, tls_socket: client_socket, tls_bridge_pid: bridge_pid}
                %{state | streams: Map.put(state.streams, stream_id, updated)}

              {:error, reason} ->
                Logger.warning("[Session] TLS bridge failed for stream #{stream_id}: #{inspect(reason)}")
                state
            end

          %{state: :connecting, buffer: buffer} = stream ->
            # Stream is still connecting — buffer data for flush on connect
            if byte_size(payload) > 0 do
              Logger.debug("[Session] Stream #{stream_id} buffering #{byte_size(payload)} bytes during connect")
              updated = %{stream | buffer: [payload | buffer]}
              %{state | streams: Map.put(state.streams, stream_id, updated)}
            else
              state
            end

          %{backend_pid: pid} when pid != nil ->
            # Plain stream: forward directly to backend
            if byte_size(payload) > 0 do
              Logger.debug("[Session] Stream #{stream_id} forwarding #{byte_size(payload)} bytes to backend: #{inspect(String.slice(payload, 0..60))}")
              Backend.send_data(pid, payload)
            end
            state

          _ ->
            Logger.warning("[Session] Data for unknown stream #{stream_id}, dropping #{byte_size(payload)} bytes")
            state
        end
      # ACK is sent by deliver_recv_window after in-order delivery
      {:noreply, state}
    else
      # Legacy single-stream mode: [data_seq(8) | payload]
      <<data_seq::big-64, payload::binary>> = rest
      Logger.debug("[Session] FRAME_DATA data_seq=#{data_seq} payload_len=#{byte_size(payload)} backend_pid=#{inspect(state.backend_pid)}")

      # Reconnect backend if it was closed (e.g. idle timeout from vaultwarden)
      state =
        if is_nil(state.backend_pid) and byte_size(payload) > 0 and not state.draining do
          Logger.debug("[Session] Legacy backend nil, reconnecting to #{inspect(state.backend_addr)}")
          case Backend.start_link(state.backend_addr) do
            {:ok, pid} ->
              Logger.debug("[Session] Legacy backend reconnected: #{inspect(pid)}")
              %{state | backend_pid: pid}
            {:error, reason} ->
              Logger.warning("[Session] Legacy backend reconnect failed: #{inspect(reason)}")
              state
          end
        else
          state
        end

      if state.backend_pid && byte_size(payload) > 0 do
        Logger.debug("[Session] Forwarding #{byte_size(payload)} bytes to backend: #{inspect(String.slice(payload, 0..60))}")
        Backend.send_data(state.backend_pid, payload)
      end
      # ACK is sent by deliver_recv_window after in-order delivery
      {:noreply, state}
    end
  end

  # Keepalive: exactly 1-byte 0x01 frame from iOS VPN extension.
  # This matches BEFORE the ACK handler because @frame_ack == 0x01 and a
  # proper ACK frame is 9+ bytes (1 type + 8 data_seq). A single-byte 0x01
  # is a keepalive — just reset the idle timer, never forward to the backend.
  # This prevents the keepalive → backend reconnect → immediate close cycle
  # that occurs when vaultwarden closes idle TCP connections.
  defp handle_tunnel_frame(<<0x01>>, state) do
    Logger.debug("[Session] Keepalive received, resetting idle timer")
    {:noreply, reset_timeout(state)}
  end

  defp handle_tunnel_frame(<<@frame_ack, acked_data_seq::big-64, sack_count::8, sack_data::binary>>, state) do
    # Cumulative ACK with SACK blocks from client
    state = process_cumulative_ack(acked_data_seq, state)

    # Process SACK blocks — mark those data_seqs as selectively acknowledged
    sack_blocks = Sack.parse_sack_blocks(sack_count, sack_data)
    sacked_set = Sack.add_to_sacked_set(state.sacked_set, sack_blocks)
    sacked_set = Sack.prune_sacked_set(sacked_set, acked_data_seq)
    state = %{state | sacked_set: sacked_set}

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

  # Legacy ACK without SACK blocks (backward compatible)
  defp handle_tunnel_frame(<<@frame_ack, acked_data_seq::big-64>>, state) do
    state = process_cumulative_ack(acked_data_seq, state)

    state = flush_send_queue(state)

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
    Logger.debug("[Session] NACK received: #{count} missing data_seqs: #{inspect(nacked_data_seqs)}")

    now = System.monotonic_time(:millisecond)

    # Fast retransmit loss event — reduce cwnd once (AIMD only; BBR is model-based)
    state = if not @use_bbr do
      new_ssthresh = max(trunc(state.cwnd / 2), @min_cwnd)
      new_cwnd = max(new_ssthresh, @min_cwnd)
      %{state | cwnd: new_cwnd, ssthresh: new_ssthresh}
    else
      state
    end

    # Filter out data_seqs that were already SACK'd — the client has them
    nacked_data_seqs = Enum.reject(nacked_data_seqs, &MapSet.member?(state.sacked_set, &1))

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

              Logger.debug("[Session] NACK retransmit data_seq=#{ds} old_seq=#{seq} new_seq=#{new_seq} attempt=#{retransmit_count + 1}")
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

    backends = Config.get(:backends)

    case find_backend(backends, state.service) do
      {:ok, %{host: host, port: port}} ->
        case Backend.start_link({host, port, self()}) do
          {:ok, new_pid} ->
            # Reset all send state for new stream, including congestion control
            retransmit_ref = Process.send_after(self(), :retransmit_check, @retransmit_check_interval_ms)
            {:noreply, %{state |
              backend_pid: new_pid,
              send_data_seq: 0,
              send_queue: :queue.new(),
              send_buffer: %{},
              draining: false,
              cwnd: @initial_cwnd,
              ssthresh: @initial_ssthresh,
              last_acked_data_seq: -1,
              retransmit_timer_ref: retransmit_ref,
              bbr: if(@use_bbr, do: Bbr.new(), else: nil)
            }}

          {:error, _reason} ->
            terminate_session(state, :backend_reconnect_failed)
        end

      :error ->
        terminate_session(state, :no_backend)
    end
  end

  # FRAME_OPEN with service name: [0x06 | stream_id(4) | svc_len(1) | svc_name]
  # The packet router sends per-stream service names for VIP routing.
  defp handle_tunnel_frame(<<@frame_open, stream_id::big-32, svc_len::8, svc_name::binary-size(svc_len)>>, state) do
    Logger.info("[Session] FRAME_OPEN stream_id=#{stream_id} service=#{svc_name}")
    open_mux_stream(stream_id, svc_name, state)
  end

  # FRAME_OPEN without service name: [0x06 | stream_id(4)]
  # Legacy VIP proxy sends bare FRAME_OPEN; use session-level service.
  defp handle_tunnel_frame(<<@frame_open, stream_id::big-32>>, state) do
    Logger.info("[Session] FRAME_OPEN stream_id=#{stream_id} (session service=#{state.service})")
    open_mux_stream(stream_id, state.service, state)
  end

  # FRAME_CLOSE: client is closing a stream
  defp handle_tunnel_frame(<<@frame_close, stream_id::big-32>>, state) do
    Logger.info("[Session] FRAME_CLOSE stream_id=#{stream_id}")
    case Map.get(state.streams, stream_id) do
      %{state: :connecting, connect_timeout_ref: tref} ->
        # Cancel connect timeout; the spawned connect will send a result
        # message that we'll ignore since the stream is already removed.
        if tref, do: Process.cancel_timer(tref)

      %{backend_pid: pid} when pid != nil ->
        # Return pooled connection for reuse instead of closing it
        if Process.alive?(pid), do: BackendPool.checkin(pid)

      _ ->
        :ok
    end
    # Audit: stream closed
    AuditCollector.log_event(%{
      event: "stream.closed",
      component: "gateway",
      level: "info",
      details: %{
        session_id: Base.encode16(state.session_id),
        stream_id: stream_id
      }
    })

    streams = Map.delete(state.streams, stream_id)
    {:noreply, %{state | streams: streams}}
  end

  # FRAME_REKEY: client's ACK with their key material for key rotation
  defp handle_tunnel_frame(<<@frame_rekey, client_key_material::binary-32>>, state) do
    case Rekey.complete(state, client_key_material) do
      {:ok, rekey_updates} ->
        Logger.info("[Session] Rekey ##{rekey_updates.rekey_count} complete, keys rotated")
        # Schedule next rekey timer
        rekey_timer_ref = Process.send_after(self(), :rekey_timer, state.rekey_interval_ms)
        state =
          state
          |> Map.merge(rekey_updates)
          |> Map.put(:rekey_timer_ref, rekey_timer_ref)
        {:noreply, state}

      :not_pending ->
        # Client-initiated rekey or stale — ignore for now
        Logger.debug("[Session] Received FRAME_REKEY but no rekey pending, ignoring")
        {:noreply, state}
    end
  end

  # Client FIN: the client's TCP side closed (e.g. POST body fully sent).
  # Close the write half of the backend TCP connection so the backend knows
  # no more data is coming and can finalize its response.
  defp handle_tunnel_frame(<<@frame_fin, fin_data_seq::big-64>>, state) do
    Logger.info("[Session] Received client FIN (data_seq=#{fin_data_seq})")
    if state.backend_pid && Process.alive?(state.backend_pid) do
      # Shutdown the write side of the backend socket so the backend sees EOF
      # and sends its response. The read side stays open for the response.
      Backend.shutdown_write(state.backend_pid)
    end
    {:noreply, state}
  end

  defp handle_tunnel_frame(_other, state) do
    # Unknown frame type — ignore
    {:noreply, state}
  end

  # ── Mux stream opener (extracted to avoid splitting handle_tunnel_frame clauses) ──

  defp open_mux_stream(stream_id, service_name, state) do
    # Once we see a FRAME_OPEN, this session is permanently in mux mode.
    # This prevents a race where all streams close temporarily and the next
    # FRAME_DATA gets misinterpreted as legacy format.
    state = %{state | mux_mode: true}
    backends = Config.get(:backends)

    case find_backend(backends, service_name) do
      {:ok, %{host: host, port: port}} ->
        # Check if we should do TLS termination for this stream.
        # When a cert is provisioned for this service, gateway terminates
        # TLS and forwards plain HTTP to the backend.
        tls_creds = case CertProvisioner.lookup(service_name) do
          {:ok, creds} -> creds
          :error -> nil
        end

        # Async backend connection: spawn a process to connect without
        # blocking the session GenServer. Data arriving for this stream
        # during connection is buffered and flushed on success.
        # Uses the BackendPool for connection reuse across mux streams.
        session_pid = self()
        spawn(fn ->
          result = BackendPool.checkout(host, port, session_pid, stream_id)
          send(session_pid, {:backend_connect_result, stream_id, result})
        end)

        # 10-second connect timeout prevents hanging streams
        timeout_ref = Process.send_after(self(), {:connect_timeout, stream_id}, 10_000)

        stream_state = %{
          state: :connecting,
          backend_pid: nil,
          buffer: [],
          connect_timeout_ref: timeout_ref,
          tls_state: if(tls_creds, do: :pending_handshake, else: nil),
          tls_creds: tls_creds,
          tls_socket: nil,
          tls_bridge_pid: nil,
          service: service_name
        }
        streams = Map.put(state.streams, stream_id, stream_state)
        Logger.info("[Session] Stream #{stream_id} connecting async (service=#{service_name}), total_streams=#{map_size(streams)}")
        {:noreply, %{state | streams: streams}}

      :error ->
        Logger.warning("[Session] No backend for service #{service_name}")
        {:noreply, state}
    end
  end

  # Send an ACK frame back to the client with SACK blocks (returns updated state)
  defp send_ack(packet_seq, state) do
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>

    # Build SACK blocks from the receive window (out-of-order packets above base)
    sack_blocks = Sack.build_sack_blocks(state.recv_window, state.recv_window_base)
    sack_payload = Sack.encode_sack_ack(packet_seq, sack_blocks)

    # ACK frame: [FRAME_ACK(1) | cumulative_ack(8 BE) | sack_count(1) | sack_blocks...]
    ack_frame = <<@frame_ack, sack_payload::binary>>
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
    flush_send_queue(state, @burst_size)
  end

  defp flush_send_queue(state, 0) do
    # Burst limit reached — schedule next tick if more to send
    if not :queue.is_empty(state.send_queue) do
      schedule_pacing_timer(state)
    else
      state
    end
  end

  defp flush_send_queue(state, remaining_burst) do
    inflight = map_size(state.send_buffer)
    window_full = if @use_bbr do
      not Bbr.can_send?(state.bbr)
    else
      effective_window = min(trunc(state.cwnd), @max_cwnd)
      inflight >= effective_window
    end
    cond do
      :queue.is_empty(state.send_queue) ->
        # Nothing to send. If draining with empty buffer, we're done.
        if state.draining and inflight == 0 do
          Logger.info("[Session] Send queue and buffer both empty during drain, sending FIN")
          send_fin(state)
        else
          state
        end

      window_full ->
        # Window full — schedule pacing timer to retry
        schedule_pacing_timer(state)

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

          :legacy_fin ->
            # Legacy FIN: sent after backend closes and all data is flushed.
            # Include data_seq so client waits for all preceding data before closing.
            # send_data_seq is already the NEXT seq (one past last sent), which is
            # exactly what the client expects as the FIN boundary.
            fin_seq = state.send_data_seq
            Logger.info("[Session] Sending legacy FIN to client (data_seq=#{fin_seq}, backend response complete)")
            encrypt_and_send_control(<<@frame_fin, fin_seq::big-64>>, state)

          plaintext when is_binary(plaintext) ->
            # Legacy single-stream data
            encrypt_and_send(plaintext, state)
        end

        case result do
          {:ok, new_state} ->
            # Continue burst — send more packets in this tick
            flush_send_queue(new_state, remaining_burst - 1)
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

  # Cancel any pending retransmit, pacing, and rekey timers (used on RESET/cleanup).
  defp cancel_timers(state) do
    if state.retransmit_timer_ref, do: Process.cancel_timer(state.retransmit_timer_ref)
    if state.pacing_timer_ref, do: Process.cancel_timer(state.pacing_timer_ref)
    if state.rekey_timer_ref, do: Process.cancel_timer(state.rekey_timer_ref)
    %{state | retransmit_timer_ref: nil, pacing_timer_ref: nil, rekey_timer_ref: nil}
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

    new_state = %{state |
      send_seq: seq,
      send_data_seq: data_seq + 1,
      bytes_out: state.bytes_out + byte_size(packet),
      send_buffer: send_buffer,
      retransmit_timer_ref: retransmit_timer_ref,
      rekey_packet_count: state.rekey_packet_count + 1
    }

    # Track inflight in BBR
    new_state = if @use_bbr do
      %{new_state | bbr: Bbr.on_send(new_state.bbr, byte_size(framed))}
    else
      new_state
    end

    new_state = maybe_initiate_rekey(new_state)
    {:ok, new_state}
  end

  # Encrypt and send a multiplexed stream data frame.
  # Wire format: [FRAME_DATA | stream_id(4 BE) | data_seq(8 BE) | payload]
  defp encrypt_and_send_stream(stream_id, plaintext, state) do
    seq = state.send_seq + 1
    data_seq = state.send_data_seq
    nonce = <<0::32, seq::little-64>>

    # Frame format: [FRAME_DATA | stream_id(4 BE) | data_seq(8 BE) | payload]
    # data_seq is the global transport sequence — used by client for ACKs.
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

    new_state = %{state |
      send_seq: seq,
      send_data_seq: data_seq + 1,
      bytes_out: state.bytes_out + byte_size(packet),
      send_buffer: send_buffer,
      retransmit_timer_ref: retransmit_timer_ref,
      rekey_packet_count: state.rekey_packet_count + 1
    }

    # Track inflight in BBR
    new_state = if @use_bbr do
      %{new_state | bbr: Bbr.on_send(new_state.bbr, byte_size(framed))}
    else
      new_state
    end

    new_state = maybe_initiate_rekey(new_state)
    {:ok, new_state}
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

  # Check if a rekey should be initiated based on packet count threshold.
  # Called after each data packet send.
  defp maybe_initiate_rekey(state) do
    case Rekey.should_rekey?(state) do
      :initiate -> do_initiate_rekey(state)
      {:skip, _reason} -> state
    end
  end

  # Initiate a rekey: generate key material, send FRAME_REKEY, update state.
  defp do_initiate_rekey(state) do
    key_material = :crypto.strong_rand_bytes(32)

    # Send FRAME_REKEY with key_material (encrypted with current r2i_key)
    frame = <<@frame_rekey, key_material::binary>>
    seq = state.send_seq + 1
    nonce = <<0::32, seq::little-64>>
    {ct, tag} = Crypto.encrypt(state.r2i_key, nonce, frame, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(state.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, state.r2i_key)
    send_udp(state, packet)

    # Compute pending key and update state
    rekey_updates = Rekey.initiate(state, key_material)

    Logger.info("[Session] Rekey initiated (packet_count=#{state.rekey_packet_count}), waiting for client ACK")

    state
    |> Map.put(:send_seq, seq)
    |> Map.merge(rekey_updates)
  end

  defp send_udp(%{udp_socket: socket, client_addr: {ip, port}}, data) do
    :gen_udp.send(socket, ip, port, data)
  end

  # Find which stream owns a given TLS client socket
  defp find_stream_by_tls_socket(streams, socket) do
    Enum.find(streams, fn {_id, s} ->
      Map.get(s, :tls_socket) == socket
    end)
  end

  # Flush buffered data accumulated during :connecting state to the backend.
  # Buffer is a list with most recent data prepended (O(1) append), so we
  # reverse to restore original order before sending.
  defp flush_stream_buffer(stream, pid) do
    stream.buffer
    |> Enum.reverse()
    |> Enum.each(fn data -> Backend.send_data(pid, data) end)
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
    Logger.debug("[Session] Processing buffered #{byte_size(packet_data)} byte packet")
    case handle_data_packet(packet_data, from_addr, state) do
      {:noreply, new_state} ->
        process_pending_packets(rest, new_state)
      {:stop, _reason, new_state} ->
        # Session terminating, stop processing
        new_state
    end
  end

  defp terminate_session(state, reason) do
    # Close all multiplexed stream backends (including :connecting streams with nil backend_pid)
    Enum.each(state.streams, fn {_sid, stream} ->
      pid = Map.get(stream, :backend_pid)
      if pid && Process.alive?(pid), do: Backend.close(pid)
      # Cancel any pending connect timeout
      tref = Map.get(stream, :connect_timeout_ref)
      if tref, do: Process.cancel_timer(tref)
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

    # Audit: session terminated (with reason)
    AuditCollector.log_event(%{
      event: "session.terminated",
      component: "gateway",
      level: "info",
      details: %{
        session_id: Base.encode16(state.session_id),
        reason: to_string(reason),
        duration_ms: duration,
        bytes_in: state.bytes_in,
        bytes_out: state.bytes_out
      }
    })

    {:stop, :normal, state}
  end

  # ---------------------------------------------------------------------------
  # Cumulative ACK processing (shared between SACK and legacy ACK handlers)
  # ---------------------------------------------------------------------------

  defp process_cumulative_ack(acked_data_seq, state) do
    now = System.monotonic_time(:millisecond)

    {acked_entries, remaining} =
      Enum.split_with(state.send_buffer, fn {_seq, {_pkt, _sent_at, _rc, ds}} ->
        is_integer(ds) and ds <= acked_data_seq
      end)

    newly_acked = length(acked_entries)

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

    # Congestion control: BBR or AIMD
    state = if @use_bbr do
      if newly_acked > 0 and acked_data_seq > state.last_acked_data_seq do
        # Calculate acked_bytes and RTT for BBR
        acked_bytes = newly_acked * @max_payload_bytes
        rtt_ms = state.srtt_ms || @initial_rto_ms
        bbr = Bbr.on_ack(state.bbr, acked_bytes, rtt_ms, now)
        %{state | bbr: bbr, last_acked_data_seq: acked_data_seq}
      else
        state
      end
    else
      # Legacy AIMD: grow window on new ACKs
      if newly_acked > 0 and acked_data_seq > state.last_acked_data_seq do
        cwnd = state.cwnd
        ssthresh = state.ssthresh
        new_cwnd = if cwnd < ssthresh do
          min(cwnd + newly_acked, @max_cwnd)
        else
          min(cwnd + newly_acked / cwnd, @max_cwnd)
        end
        %{state | cwnd: new_cwnd, last_acked_data_seq: acked_data_seq}
      else
        state
      end
    end

    Logger.debug("[Session] ACK data_seq=#{acked_data_seq}, acked=#{newly_acked}, cwnd=#{Float.round(state.cwnd, 1)}, ssthresh=#{state.ssthresh}, buffer=#{map_size(send_buffer)}")

    %{state | send_buffer: send_buffer}
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
