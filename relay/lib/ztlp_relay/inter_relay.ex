defmodule ZtlpRelay.InterRelay do
  @moduledoc """
  Inter-relay communication protocol over UDP.

  Relays communicate using a simple binary protocol for mesh operations:
  discovery (HELLO/HELLO_ACK), health probing (PING/PONG), packet
  forwarding (FORWARD), session synchronization (SESSION_SYNC),
  graceful departure (LEAVE), drain control, and peer exchange.

  All messages share a common header:
    <<msg_type::8, sender_node_id::binary-16, timestamp::64, ...payload>>

  When a signing key is provided, a 64-byte Ed25519 signature is appended
  after the payload. The signature covers all bytes preceding it.

  Message types:
    - 0x01 RELAY_HELLO — introduce self (node_id, address, role, capabilities)
    - 0x02 RELAY_HELLO_ACK — acknowledgment with own info
    - 0x03 RELAY_PING — probe for metrics
    - 0x04 RELAY_PONG — response with metrics
    - 0x05 RELAY_FORWARD — forward a wrapped ZTLP packet
    - 0x06 RELAY_SESSION_SYNC — sync session state
    - 0x07 RELAY_LEAVE — graceful departure
    - 0x08 RELAY_DRAIN — draining, stop sending new sessions
    - 0x09 RELAY_DRAIN_CANCEL — back to normal operation
    - 0x0A RELAY_PEER_EXCHANGE — share known peer list
  """

  require Logger

  # Ed25519 mesh message signing (uses OTP :crypto, no external deps)

  @doc """
  Sign a mesh message and append the 64-byte Ed25519 signature.
  If no signing key is provided, returns the message unchanged.
  """
  @spec sign_message(binary(), binary() | nil) :: binary()
  def sign_message(message_bytes, nil), do: message_bytes

  def sign_message(message_bytes, private_key) when is_binary(private_key) do
    signature = sign_mesh_message(message_bytes, private_key)
    <<message_bytes::binary, signature::binary>>
  end

  @doc """
  Verify a signed mesh message. Returns `{:ok, message_body}` or `{:error, :bad_signature}`.
  The last 64 bytes are the signature; everything before is the signed content.
  """
  @spec verify_signed_message(binary(), binary()) :: {:ok, binary()} | {:error, :bad_signature}
  def verify_signed_message(data, public_key) when byte_size(data) > 64 do
    body_len = byte_size(data) - 64
    <<body::binary-size(body_len), signature::binary-size(64)>> = data

    if verify_mesh_signature(body, signature, public_key) do
      {:ok, body}
    else
      {:error, :bad_signature}
    end
  end

  def verify_signed_message(_data, _public_key), do: {:error, :bad_signature}

  defp sign_mesh_message(message_bytes, private_key) do
    :crypto.sign(:eddsa, :none, message_bytes, [private_key, :ed25519])
  end

  defp verify_mesh_signature(message_bytes, signature, public_key) do
    :crypto.verify(:eddsa, :none, message_bytes, signature, [public_key, :ed25519])
  rescue
    _ -> false
  end

  @doc """
  Decode a raw inter-relay message with Ed25519 signature verification.
  Strips the last 64 bytes as signature, verifies, then decodes the body.

  Returns `{:ok, {msg_type, sender, timestamp, payload}}` or `{:error, reason}`.
  """
  @spec decode_with_auth(binary(), binary()) ::
          {:ok, {msg_type(), binary(), non_neg_integer(), map()}} | {:error, atom()}
  def decode_with_auth(data, public_key) do
    case verify_signed_message(data, public_key) do
      {:ok, body} -> decode(body)
      {:error, _} = err -> err
    end
  end

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
  @relay_peer_exchange 0x0A

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
          | :relay_peer_exchange

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
  @spec encode_hello(relay_info(), binary() | nil) :: binary()
  def encode_hello(info, signing_key \\ nil) do
    {ip, port} = info.address
    role_byte = encode_role(info[:role] || :all)
    capabilities = info[:capabilities] || 0

    msg =
      <<@relay_hello::8, info.node_id::binary-size(16), timestamp()::64,
        encode_addr_type(ip)::8, encode_ip(ip)::binary,
        port::16, role_byte::8, capabilities::32>>

    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_HELLO_ACK message.
  """
  @spec encode_hello_ack(relay_info(), binary() | nil) :: binary()
  def encode_hello_ack(info, signing_key \\ nil) do
    {ip, port} = info.address
    role_byte = encode_role(info[:role] || :all)
    capabilities = info[:capabilities] || 0

    msg =
      <<@relay_hello_ack::8, info.node_id::binary-size(16), timestamp()::64,
        encode_addr_type(ip)::8, encode_ip(ip)::binary,
        port::16, role_byte::8, capabilities::32>>

    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_PING message with an optional sequence number.
  """
  @spec encode_ping(binary(), non_neg_integer(), binary() | nil) :: binary()
  def encode_ping(sender_node_id, seq \\ 0, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    msg = <<@relay_ping::8, sender_node_id::binary-size(16), timestamp()::64, seq::32>>
    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_PONG message with metrics and echo sequence number.
  """
  @spec encode_pong(binary(), pong_metrics(), non_neg_integer(), binary() | nil) :: binary()
  def encode_pong(sender_node_id, metrics, echo_seq \\ 0, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    msg =
      <<@relay_pong::8, sender_node_id::binary-size(16), timestamp()::64,
        metrics.active_sessions::32, metrics.max_sessions::32, metrics.uptime_seconds::32,
        echo_seq::32>>

    sign_message(msg, signing_key)
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
    signing_key = Keyword.get(opts, :signing_key, nil)
    path_len = length(path)

    path_binary =
      Enum.reduce(path, <<>>, fn nid, acc -> <<acc::binary, nid::binary-size(16)>> end)

    len = byte_size(inner_packet)

    msg =
      <<@relay_forward::8, sender_node_id::binary-size(16), timestamp()::64, ttl::8, path_len::8,
        path_binary::binary, len::32, inner_packet::binary>>

    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_SESSION_SYNC message.
  """
  @spec encode_session_sync(binary(), session_sync(), binary() | nil) :: binary()
  def encode_session_sync(sender_node_id, sync, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    {ip_a, port_a} = sync.peer_a
    {ip_b, port_b} = sync.peer_b

    msg =
      <<@relay_session_sync::8, sender_node_id::binary-size(16), timestamp()::64,
        sync.session_id::binary-size(12),
        encode_addr_type(ip_a)::8, encode_ip(ip_a)::binary, port_a::16,
        encode_addr_type(ip_b)::8, encode_ip(ip_b)::binary, port_b::16>>

    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_LEAVE message.
  """
  @spec encode_leave(binary(), binary() | nil) :: binary()
  def encode_leave(sender_node_id, signing_key \\ nil) when byte_size(sender_node_id) == 16 do
    msg = <<@relay_leave::8, sender_node_id::binary-size(16), timestamp()::64>>
    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_DRAIN message (type 0x08).
  Notifies mesh peers this relay is draining and should not receive new sessions.
  """
  @spec encode_drain(binary(), non_neg_integer(), binary() | nil) :: binary()
  def encode_drain(sender_node_id, timeout_ms, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    msg = <<@relay_drain::8, sender_node_id::binary-size(16), timestamp()::64, timeout_ms::32>>
    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_DRAIN_CANCEL message (type 0x09).
  Notifies mesh peers this relay is back to normal operation.
  """
  @spec encode_drain_cancel(binary(), binary() | nil) :: binary()
  def encode_drain_cancel(sender_node_id, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    msg = <<@relay_drain_cancel::8, sender_node_id::binary-size(16), timestamp()::64>>
    sign_message(msg, signing_key)
  end

  @doc """
  Encode a RELAY_PEER_EXCHANGE message (type 0x0A).
  Shares a list of known peers with their addresses.

  Each peer entry: <<node_id::binary-16, addr_type::8, ip::binary, port::16>>
  where addr_type is 0x04 (IPv4, 4 bytes) or 0x06 (IPv6, 16 bytes).
  """
  @spec encode_peer_exchange(binary(), [relay_info()], binary() | nil) :: binary()
  def encode_peer_exchange(sender_node_id, peers, signing_key \\ nil)
      when byte_size(sender_node_id) == 16 do
    peer_count = length(peers)

    peer_binary =
      Enum.reduce(peers, <<>>, fn peer, acc ->
        {ip, port} = peer.address

        <<acc::binary, peer.node_id::binary-size(16),
          encode_addr_type(ip)::8, encode_ip(ip)::binary, port::16>>
      end)

    msg =
      <<@relay_peer_exchange::8, sender_node_id::binary-size(16), timestamp()::64,
        peer_count::16, peer_binary::binary>>

    sign_message(msg, signing_key)
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

  # RELAY_HELLO with address type byte — IPv4
  def decode(
        <<@relay_hello::8, sender::binary-size(16), ts::64, 0x04::8,
          ip_bytes::binary-size(4), port::16, role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello, sender, ts,
      %{
        address: {decode_ip(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  # RELAY_HELLO with address type byte — IPv6
  def decode(
        <<@relay_hello::8, sender::binary-size(16), ts::64, 0x06::8,
          ip_bytes::binary-size(16), port::16, role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello, sender, ts,
      %{
        address: {decode_ipv6(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  # Legacy RELAY_HELLO without address type byte (4-byte IPv4 only)
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

  # RELAY_HELLO_ACK with address type byte — IPv4
  def decode(
        <<@relay_hello_ack::8, sender::binary-size(16), ts::64, 0x04::8,
          ip_bytes::binary-size(4), port::16, role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello_ack, sender, ts,
      %{
        address: {decode_ip(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  # RELAY_HELLO_ACK with address type byte — IPv6
  def decode(
        <<@relay_hello_ack::8, sender::binary-size(16), ts::64, 0x06::8,
          ip_bytes::binary-size(16), port::16, role_byte::8, capabilities::32>>
      ) do
    {:ok,
     {:relay_hello_ack, sender, ts,
      %{
        address: {decode_ipv6(ip_bytes), port},
        role: decode_role(role_byte),
        capabilities: capabilities
      }}}
  end

  # Legacy RELAY_HELLO_ACK without address type byte (4-byte IPv4 only)
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

  # RELAY_SESSION_SYNC with address type bytes
  def decode(
        <<@relay_session_sync::8, sender::binary-size(16), ts::64, session_id::binary-size(12),
          addr_type_a::8, rest_sync::binary>>
      ) do
    case decode_addr_from_binary(addr_type_a, rest_sync) do
      {:ok, ip_a, <<port_a::16, addr_type_b::8, rest_b::binary>>} ->
        case decode_addr_from_binary(addr_type_b, rest_b) do
          {:ok, ip_b, <<port_b::16>>} ->
            {:ok,
             {:relay_session_sync, sender, ts,
              %{
                session_id: session_id,
                peer_a: {ip_a, port_a},
                peer_b: {ip_b, port_b}
              }}}

          {:ok, ip_b, <<port_b::16, _::binary>>} ->
            {:ok,
             {:relay_session_sync, sender, ts,
              %{
                session_id: session_id,
                peer_a: {ip_a, port_a},
                peer_b: {ip_b, port_b}
              }}}

          _ ->
            {:error, :malformed_session_sync}
        end

      _ ->
        # Fallback: try legacy 4-byte IPv4 format (no addr type byte)
        decode_session_sync_legacy(sender, ts, session_id, addr_type_a, rest_sync)
    end
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

  # RELAY_PEER_EXCHANGE
  def decode(
        <<@relay_peer_exchange::8, sender::binary-size(16), ts::64, peer_count::16,
          rest::binary>>
      ) do
    case decode_peer_list(rest, peer_count, []) do
      {:ok, peers} ->
        {:ok, {:relay_peer_exchange, sender, ts, %{peers: peers}}}

      {:error, _} = err ->
        err
    end
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
             @relay_drain_cancel,
             @relay_peer_exchange
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
             @relay_leave,
             @relay_drain,
             @relay_drain_cancel,
             @relay_peer_exchange
           ],
      do: true

  def inter_relay_message?(_), do: false

  # Helpers

  defp timestamp do
    System.system_time(:millisecond)
  end

  # IPv4 encoding/decoding
  defp encode_ip({a, b, c, d}), do: <<a::8, b::8, c::8, d::8>>

  # IPv6 encoding
  defp encode_ip({a, b, c, d, e, f, g, h}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

  defp decode_ip(<<a::8, b::8, c::8, d::8>>), do: {a, b, c, d}

  defp decode_ipv6(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>),
    do: {a, b, c, d, e, f, g, h}

  # Address type byte encoding
  defp encode_addr_type({_, _, _, _}), do: 0x04
  defp encode_addr_type({_, _, _, _, _, _, _, _}), do: 0x06

  # Decode address from binary given type byte
  defp decode_addr_from_binary(0x04, <<ip_bytes::binary-size(4), rest::binary>>) do
    {:ok, decode_ip(ip_bytes), rest}
  end

  defp decode_addr_from_binary(0x06, <<ip_bytes::binary-size(16), rest::binary>>) do
    {:ok, decode_ipv6(ip_bytes), rest}
  end

  defp decode_addr_from_binary(_, _), do: {:error, :invalid_addr_type}

  # Legacy SESSION_SYNC decode fallback (no addr type byte, raw IPv4)
  defp decode_session_sync_legacy(sender, ts, session_id, first_byte, rest) do
    # Reconstruct: first_byte was consumed as addr_type, but it's actually the
    # first octet of an IPv4 address in the legacy format
    case <<first_byte::8, rest::binary>> do
      <<ip_a_bytes::binary-size(4), port_a::16, ip_b_bytes::binary-size(4), port_b::16>> ->
        {:ok,
         {:relay_session_sync, sender, ts,
          %{
            session_id: session_id,
            peer_a: {decode_ip(ip_a_bytes), port_a},
            peer_b: {decode_ip(ip_b_bytes), port_b}
          }}}

      _ ->
        {:error, :malformed_session_sync}
    end
  end

  # Decode a list of peers from RELAY_PEER_EXCHANGE
  defp decode_peer_list(_rest, 0, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_peer_list(
         <<node_id::binary-size(16), addr_type::8, rest::binary>>,
         remaining,
         acc
       )
       when remaining > 0 do
    case decode_addr_from_binary(addr_type, rest) do
      {:ok, ip, <<port::16, rest2::binary>>} ->
        peer = %{node_id: node_id, address: {ip, port}}
        decode_peer_list(rest2, remaining - 1, [peer | acc])

      _ ->
        {:error, :malformed_peer_exchange}
    end
  end

  defp decode_peer_list(_, _, _), do: {:error, :malformed_peer_exchange}

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
