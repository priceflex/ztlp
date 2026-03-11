defmodule ZtlpRelay.InterRelay do
  @moduledoc """
  Inter-relay communication protocol over UDP.

  Relays communicate using a simple binary protocol for mesh operations:
  discovery (HELLO/HELLO_ACK), health probing (PING/PONG), packet
  forwarding (FORWARD), session synchronization (SESSION_SYNC), and
  graceful departure (LEAVE).

  All messages share a common header:
    <<msg_type::8, sender_node_id::binary-16, timestamp::64, ...payload>>

  Message types:
    - 0x01 RELAY_HELLO — introduce self (node_id, address, role, capabilities)
    - 0x02 RELAY_HELLO_ACK — acknowledgment with own info
    - 0x03 RELAY_PING — probe for metrics
    - 0x04 RELAY_PONG — response with metrics
    - 0x05 RELAY_FORWARD — forward a wrapped ZTLP packet
    - 0x06 RELAY_SESSION_SYNC — sync session state
    - 0x07 RELAY_LEAVE — graceful departure
  """

  require Logger

  # Message type constants
  @relay_hello 0x01
  @relay_hello_ack 0x02
  @relay_ping 0x03
  @relay_pong 0x04
  @relay_forward 0x05
  @relay_session_sync 0x06
  @relay_leave 0x07
  @relay_drain 0x08
  @relay_drain_cancel 0x09

  @type msg_type ::
          :relay_hello
          | :relay_hello_ack
          | :relay_ping
          | :relay_pong
          | :relay_forward
          | :relay_session_sync
          | :relay_leave
          | :relay_drain
          | :relay_drain_cancel

  @type relay_info :: %{
          node_id: binary(),
          address: {:inet.ip_address(), :inet.port_number()},
          role: atom(),
          capabilities: non_neg_integer()
        }

  @type pong_metrics :: %{
          active_sessions: non_neg_integer(),
          max_sessions: non_neg_integer(),
          uptime_seconds: non_neg_integer()
        }

  @type session_sync :: %{
          session_id: binary(),
          peer_a: {:inet.ip_address(), :inet.port_number()},
          peer_b: {:inet.ip_address(), :inet.port_number()}
        }

  # Encoding

  @doc """
  Encode a RELAY_HELLO message.

  `info` must have `:node_id` (16 bytes), `:address` ({ip, port}),
  `:role` (atom), and optionally `:capabilities` (uint32, default 0).
  """
  @spec encode_hello(relay_info()) :: binary()
  def encode_hello(info) do
    {ip, port} = info.address
    role_byte = encode_role(info[:role] || :all)
    capabilities = info[:capabilities] || 0

    <<@relay_hello::8, info.node_id::binary-size(16), timestamp()::64, encode_ip(ip)::binary,
      port::16, role_byte::8, capabilities::32>>
  end

  @doc """
  Encode a RELAY_HELLO_ACK message.
  """
  @spec encode_hello_ack(relay_info()) :: binary()
  def encode_hello_ack(info) do
    {ip, port} = info.address
    role_byte = encode_role(info[:role] || :all)
    capabilities = info[:capabilities] || 0

    <<@relay_hello_ack::8, info.node_id::binary-size(16), timestamp()::64, encode_ip(ip)::binary,
      port::16, role_byte::8, capabilities::32>>
  end

  @doc """
  Encode a RELAY_PING message with an optional sequence number.
  """
  @spec encode_ping(binary(), non_neg_integer()) :: binary()
  def encode_ping(sender_node_id, seq \\ 0) when byte_size(sender_node_id) == 16 do
    <<@relay_ping::8, sender_node_id::binary-size(16), timestamp()::64, seq::32>>
  end

  @doc """
  Encode a RELAY_PONG message with metrics and echo sequence number.
  """
  @spec encode_pong(binary(), pong_metrics(), non_neg_integer()) :: binary()
  def encode_pong(sender_node_id, metrics, echo_seq \\ 0) when byte_size(sender_node_id) == 16 do
    <<@relay_pong::8, sender_node_id::binary-size(16), timestamp()::64,
      metrics.active_sessions::32, metrics.max_sessions::32, metrics.uptime_seconds::32,
      echo_seq::32>>
  end

  @default_ttl 4

  @doc """
  Encode a RELAY_FORWARD message wrapping a ZTLP packet with multi-hop support.

  Wire format:
      <<0x05, sender::16-bytes, ts::64, ttl::8, path_len::8,
        path::(path_len*16)-bytes, inner_len::32, inner::binary>>

  ## Options
  - `:ttl` — hop count (default 4)
  - `:path` — list of 16-byte NodeID binaries already traversed (default [])
  """
  @spec encode_forward(binary(), binary(), keyword()) :: binary()
  def encode_forward(sender_node_id, inner_packet, opts \\ [])
      when byte_size(sender_node_id) == 16 and is_binary(inner_packet) do
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    path = Keyword.get(opts, :path, [])
    path_len = length(path)

    path_binary =
      Enum.reduce(path, <<>>, fn nid, acc -> <<acc::binary, nid::binary-size(16)>> end)

    len = byte_size(inner_packet)

    <<@relay_forward::8, sender_node_id::binary-size(16), timestamp()::64, ttl::8, path_len::8,
      path_binary::binary, len::32, inner_packet::binary>>
  end

  @doc """
  Encode a RELAY_SESSION_SYNC message.
  """
  @spec encode_session_sync(binary(), session_sync()) :: binary()
  def encode_session_sync(sender_node_id, sync) when byte_size(sender_node_id) == 16 do
    {ip_a, port_a} = sync.peer_a
    {ip_b, port_b} = sync.peer_b

    <<@relay_session_sync::8, sender_node_id::binary-size(16), timestamp()::64,
      sync.session_id::binary-size(12), encode_ip(ip_a)::binary, port_a::16,
      encode_ip(ip_b)::binary, port_b::16>>
  end

  @doc """
  Encode a RELAY_LEAVE message.
  """
  @spec encode_leave(binary()) :: binary()
  def encode_leave(sender_node_id) when byte_size(sender_node_id) == 16 do
    <<@relay_leave::8, sender_node_id::binary-size(16), timestamp()::64>>
  end

  @doc """
  Encode a RELAY_DRAIN message (type 0x08).
  Notifies mesh peers this relay is draining and should not receive new sessions.
  """
  @spec encode_drain(binary(), non_neg_integer()) :: binary()
  def encode_drain(sender_node_id, timeout_ms)
      when byte_size(sender_node_id) == 16 do
    <<@relay_drain::8, sender_node_id::binary-size(16), timestamp()::64, timeout_ms::32>>
  end

  @doc """
  Encode a RELAY_DRAIN_CANCEL message (type 0x09).
  Notifies mesh peers this relay is back to normal operation.
  """
  @spec encode_drain_cancel(binary()) :: binary()
  def encode_drain_cancel(sender_node_id)
      when byte_size(sender_node_id) == 16 do
    <<@relay_drain_cancel::8, sender_node_id::binary-size(16), timestamp()::64>>
  end

  @doc """
  Generic encode for drain messages (used by MeshManager).
  """
  @spec encode(atom(), binary(), map()) :: binary()
  def encode(:drain, sender_node_id, %{timeout_ms: timeout_ms}) do
    encode_drain(sender_node_id, timeout_ms)
  end

  def encode(:drain_cancel, sender_node_id, _opts) do
    encode_drain_cancel(sender_node_id)
  end

  # Decoding

  @doc """
  Decode a raw inter-relay message binary.

  Returns `{:ok, {msg_type, sender_node_id, timestamp, payload_map}}`
  or `{:error, reason}`.
  """
  @spec decode(binary()) ::
          {:ok, {msg_type(), binary(), non_neg_integer(), map()}} | {:error, atom()}

  def decode(
        <<@relay_hello::8, sender::binary-size(16), ts::64, ip_bytes::binary-size(4), port::16,
          role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello, sender, ts,
      %{
        address: {decode_ip(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  def decode(
        <<@relay_hello_ack::8, sender::binary-size(16), ts::64, ip_bytes::binary-size(4),
          port::16, role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello_ack, sender, ts,
      %{
        address: {decode_ip(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  def decode(<<@relay_ping::8, sender::binary-size(16), ts::64, seq::32>>) do
    {:ok, {:relay_ping, sender, ts, %{seq: seq}}}
  end

  def decode(
        <<@relay_pong::8, sender::binary-size(16), ts::64, active::32, max::32, uptime::32,
          echo_seq::32>>
      ) do
    {:ok,
     {:relay_pong, sender, ts,
      %{
        active_sessions: active,
        max_sessions: max,
        uptime_seconds: uptime,
        echo_seq: echo_seq
      }}}
  end

  def decode(
        <<@relay_forward::8, sender::binary-size(16), ts::64, ttl::8, path_len::8, rest::binary>>
      ) do
    path_bytes = path_len * 16

    case rest do
      <<path_binary::binary-size(path_bytes), len::32, inner::binary>> ->
        if byte_size(inner) == len do
          path = for <<nid::binary-size(16) <- path_binary>>, do: nid
          {:ok, {:relay_forward, sender, ts, %{inner_packet: inner, ttl: ttl, path: path}}}
        else
          {:error, :forward_length_mismatch}
        end

      _ ->
        {:error, :forward_length_mismatch}
    end
  end

  def decode(
        <<@relay_session_sync::8, sender::binary-size(16), ts::64, session_id::binary-size(12),
          ip_a_bytes::binary-size(4), port_a::16, ip_b_bytes::binary-size(4), port_b::16>>
      ) do
    {:ok,
     {:relay_session_sync, sender, ts,
      %{
        session_id: session_id,
        peer_a: {decode_ip(ip_a_bytes), port_a},
        peer_b: {decode_ip(ip_b_bytes), port_b}
      }}}
  end

  def decode(<<@relay_leave::8, sender::binary-size(16), ts::64>>) do
    {:ok, {:relay_leave, sender, ts, %{}}}
  end

  def decode(<<@relay_drain::8, sender::binary-size(16), ts::64, timeout_ms::32>>) do
    {:ok, {:relay_drain, sender, ts, %{timeout_ms: timeout_ms}}}
  end

  def decode(<<@relay_drain_cancel::8, sender::binary-size(16), ts::64>>) do
    {:ok, {:relay_drain_cancel, sender, ts, %{}}}
  end

  def decode(<<type::8, _::binary>>)
      when type not in [
             @relay_hello,
             @relay_hello_ack,
             @relay_ping,
             @relay_pong,
             @relay_forward,
             @relay_session_sync,
             @relay_leave,
             @relay_drain,
             @relay_drain_cancel
           ] do
    {:error, :unknown_message_type}
  end

  def decode(_), do: {:error, :malformed_message}

  @doc """
  Handle a raw inter-relay message and dispatch to the appropriate handler.

  Returns `{:ok, decoded}` for processing by the caller.
  """
  @spec handle_message(binary(), {:inet.ip_address(), :inet.port_number()}) ::
          {:ok, {msg_type(), binary(), non_neg_integer(), map()}} | {:error, atom()}
  def handle_message(data, _sender) do
    decode(data)
  end

  @doc """
  Wrap a ZTLP packet for forwarding to another relay.

  Options: `:ttl`, `:path` (same as encode_forward).
  """
  @spec forward_packet(binary(), binary(), keyword()) :: binary()
  def forward_packet(inner_packet, sender_node_id, opts \\ []) do
    encode_forward(sender_node_id, inner_packet, opts)
  end

  @doc """
  Unwrap a RELAY_FORWARD message, returning the inner ZTLP packet.
  """
  @spec unwrap_forward(binary()) :: {:ok, binary()} | {:error, atom() | tuple()}
  def unwrap_forward(data) do
    case decode(data) do
      {:ok, {:relay_forward, _sender, _ts, %{inner_packet: inner}}} -> {:ok, inner}
      {:ok, {other_type, _, _, _}} -> {:error, {:not_forward, other_type}}
      {:error, _} = err -> err
    end
  end

  @doc "Unwrap RELAY_FORWARD returning full payload (sender, inner, ttl, path)."
  @spec unwrap_forward_full(binary()) :: {:ok, {binary(), map()}} | {:error, atom() | tuple()}
  def unwrap_forward_full(data) do
    case decode(data) do
      {:ok, {:relay_forward, sender, _ts, payload}} -> {:ok, {sender, payload}}
      {:ok, {other_type, _, _, _}} -> {:error, {:not_forward, other_type}}
      {:error, _} = err -> err
    end
  end

  @doc "Check if node_id appears in the traversed path (loop detection)."
  @spec loop_detected?(binary(), [binary()]) :: boolean()
  def loop_detected?(node_id, path), do: Enum.any?(path, &(&1 == node_id))

  @doc "Returns the default TTL for multi-hop forwarding."
  @spec default_ttl() :: non_neg_integer()
  def default_ttl, do: @default_ttl

  @doc """
  Check if a raw binary is an inter-relay message (first byte is a known type).
  """
  @spec inter_relay_message?(binary()) :: boolean()
  def inter_relay_message?(<<type::8, _::binary>>)
      when type in [
             @relay_hello,
             @relay_hello_ack,
             @relay_ping,
             @relay_pong,
             @relay_forward,
             @relay_session_sync,
             @relay_leave
           ],
      do: true

  def inter_relay_message?(_), do: false

  # Helpers

  defp timestamp do
    System.system_time(:millisecond)
  end

  defp encode_ip({a, b, c, d}), do: <<a::8, b::8, c::8, d::8>>

  defp decode_ip(<<a::8, b::8, c::8, d::8>>), do: {a, b, c, d}

  defp encode_role(:ingress), do: 0x01
  defp encode_role(:transit), do: 0x02
  defp encode_role(:service), do: 0x03
  defp encode_role(:all), do: 0xFF
  defp encode_role(_), do: 0xFF

  defp decode_role(0x01), do: :ingress
  defp decode_role(0x02), do: :transit
  defp decode_role(0x03), do: :service
  defp decode_role(0xFF), do: :all
  defp decode_role(_), do: :all
end
