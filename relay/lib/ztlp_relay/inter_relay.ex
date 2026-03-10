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
  @relay_hello       0x01
  @relay_hello_ack   0x02
  @relay_ping        0x03
  @relay_pong        0x04
  @relay_forward     0x05
  @relay_session_sync 0x06
  @relay_leave       0x07

  @type msg_type :: :relay_hello | :relay_hello_ack | :relay_ping | :relay_pong |
                    :relay_forward | :relay_session_sync | :relay_leave

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

    <<@relay_hello::8, info.node_id::binary-size(16), timestamp()::64,
      encode_ip(ip)::binary, port::16, role_byte::8, capabilities::32>>
  end

  @doc """
  Encode a RELAY_HELLO_ACK message.
  """
  @spec encode_hello_ack(relay_info()) :: binary()
  def encode_hello_ack(info) do
    {ip, port} = info.address
    role_byte = encode_role(info[:role] || :all)
    capabilities = info[:capabilities] || 0

    <<@relay_hello_ack::8, info.node_id::binary-size(16), timestamp()::64,
      encode_ip(ip)::binary, port::16, role_byte::8, capabilities::32>>
  end

  @doc """
  Encode a RELAY_PING message.
  """
  @spec encode_ping(binary()) :: binary()
  def encode_ping(sender_node_id) when byte_size(sender_node_id) == 16 do
    <<@relay_ping::8, sender_node_id::binary-size(16), timestamp()::64>>
  end

  @doc """
  Encode a RELAY_PONG message with metrics.
  """
  @spec encode_pong(binary(), pong_metrics()) :: binary()
  def encode_pong(sender_node_id, metrics) when byte_size(sender_node_id) == 16 do
    <<@relay_pong::8, sender_node_id::binary-size(16), timestamp()::64,
      metrics.active_sessions::32, metrics.max_sessions::32,
      metrics.uptime_seconds::32>>
  end

  @doc """
  Encode a RELAY_FORWARD message wrapping a ZTLP packet.

  The inner packet is included as-is after a 4-byte length prefix.
  """
  @spec encode_forward(binary(), binary()) :: binary()
  def encode_forward(sender_node_id, inner_packet)
      when byte_size(sender_node_id) == 16 and is_binary(inner_packet) do
    len = byte_size(inner_packet)

    <<@relay_forward::8, sender_node_id::binary-size(16), timestamp()::64,
      len::32, inner_packet::binary>>
  end

  @doc """
  Encode a RELAY_SESSION_SYNC message.
  """
  @spec encode_session_sync(binary(), session_sync()) :: binary()
  def encode_session_sync(sender_node_id, sync) when byte_size(sender_node_id) == 16 do
    {ip_a, port_a} = sync.peer_a
    {ip_b, port_b} = sync.peer_b

    <<@relay_session_sync::8, sender_node_id::binary-size(16), timestamp()::64,
      sync.session_id::binary-size(12),
      encode_ip(ip_a)::binary, port_a::16,
      encode_ip(ip_b)::binary, port_b::16>>
  end

  @doc """
  Encode a RELAY_LEAVE message.
  """
  @spec encode_leave(binary()) :: binary()
  def encode_leave(sender_node_id) when byte_size(sender_node_id) == 16 do
    <<@relay_leave::8, sender_node_id::binary-size(16), timestamp()::64>>
  end

  # Decoding

  @doc """
  Decode a raw inter-relay message binary.

  Returns `{:ok, {msg_type, sender_node_id, timestamp, payload_map}}`
  or `{:error, reason}`.
  """
  @spec decode(binary()) :: {:ok, {msg_type(), binary(), non_neg_integer(), map()}} | {:error, atom()}

  def decode(<<@relay_hello::8, sender::binary-size(16), ts::64,
               ip_bytes::binary-size(4), port::16, role_byte::8, capabilities::32>>) do
    {:ok, {:relay_hello, sender, ts, %{
      address: {decode_ip(ip_bytes), port},
      role: decode_role(role_byte),
      capabilities: capabilities
    }}}
  end

  def decode(<<@relay_hello_ack::8, sender::binary-size(16), ts::64,
               ip_bytes::binary-size(4), port::16, role_byte::8, capabilities::32>>) do
    {:ok, {:relay_hello_ack, sender, ts, %{
      address: {decode_ip(ip_bytes), port},
      role: decode_role(role_byte),
      capabilities: capabilities
    }}}
  end

  def decode(<<@relay_ping::8, sender::binary-size(16), ts::64>>) do
    {:ok, {:relay_ping, sender, ts, %{}}}
  end

  def decode(<<@relay_pong::8, sender::binary-size(16), ts::64,
               active::32, max::32, uptime::32>>) do
    {:ok, {:relay_pong, sender, ts, %{
      active_sessions: active,
      max_sessions: max,
      uptime_seconds: uptime
    }}}
  end

  def decode(<<@relay_forward::8, sender::binary-size(16), ts::64,
               len::32, inner::binary>>) do
    if byte_size(inner) == len do
      {:ok, {:relay_forward, sender, ts, %{inner_packet: inner}}}
    else
      {:error, :forward_length_mismatch}
    end
  end

  def decode(<<@relay_session_sync::8, sender::binary-size(16), ts::64,
               session_id::binary-size(12),
               ip_a_bytes::binary-size(4), port_a::16,
               ip_b_bytes::binary-size(4), port_b::16>>) do
    {:ok, {:relay_session_sync, sender, ts, %{
      session_id: session_id,
      peer_a: {decode_ip(ip_a_bytes), port_a},
      peer_b: {decode_ip(ip_b_bytes), port_b}
    }}}
  end

  def decode(<<@relay_leave::8, sender::binary-size(16), ts::64>>) do
    {:ok, {:relay_leave, sender, ts, %{}}}
  end

  def decode(<<type::8, _::binary>>) when type not in [@relay_hello, @relay_hello_ack,
    @relay_ping, @relay_pong, @relay_forward, @relay_session_sync, @relay_leave] do
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

  Returns the encoded RELAY_FORWARD binary.
  """
  @spec forward_packet(binary(), binary()) :: binary()
  def forward_packet(inner_packet, sender_node_id) do
    encode_forward(sender_node_id, inner_packet)
  end

  @doc """
  Unwrap a RELAY_FORWARD message, returning the inner ZTLP packet.

  Returns `{:ok, inner_packet}` or `{:error, reason}`.
  """
  @spec unwrap_forward(binary()) :: {:ok, binary()} | {:error, atom()}
  def unwrap_forward(data) do
    case decode(data) do
      {:ok, {:relay_forward, _sender, _ts, %{inner_packet: inner}}} ->
        {:ok, inner}

      {:ok, {other_type, _, _, _}} ->
        {:error, {:not_forward, other_type}}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Check if a raw binary is an inter-relay message (first byte is a known type).
  """
  @spec inter_relay_message?(binary()) :: boolean()
  def inter_relay_message?(<<type::8, _::binary>>)
      when type in [@relay_hello, @relay_hello_ack, @relay_ping, @relay_pong,
                    @relay_forward, @relay_session_sync, @relay_leave],
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
  defp encode_role(:all),     do: 0xFF
  defp encode_role(_),        do: 0xFF

  defp decode_role(0x01), do: :ingress
  defp decode_role(0x02), do: :transit
  defp decode_role(0x03), do: :service
  defp decode_role(0xFF), do: :all
  defp decode_role(_),    do: :all
end
