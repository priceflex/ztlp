defmodule ZtlpGateway.Packet do
  @moduledoc """
  ZTLP packet parsing and serialization.

  All ZTLP packets share a common header prefix:

      Byte 0-1: Magic (0x5A37 — 'Z7')
      Byte 2-3: Version (4 bits) + HdrLen (12 bits)

  The HdrLen field discriminates packet types:
  - **HdrLen = 12** → Data packet (46-byte header)
  - **HdrLen = 24** → Handshake packet (96-byte header)

  ## Data Packet Header (46 bytes)

      Offset  Size  Field
      ------  ----  -----
      0       2     Magic (0x5A37)
      2       2     Version (4b) + HdrLen=12 (12b)
      4       2     Flags
      6       12    SessionID (96-bit)
      18      8     PacketSeq (64-bit big-endian)
      26      16    HeaderAuthTag (128-bit AEAD tag)
      42      2     ExtLen
      44      2     PayloadLen

  ## Handshake Packet Header (96 bytes)

      Offset  Size  Field
      ------  ----  -----
      0       2     Magic (0x5A37)
      2       2     Version (4b) + HdrLen=24 (12b)
      4       2     Flags
      6       1     MsgType
      7       2     CryptoSuite
      9       2     KeyID
      11      12    SessionID (96-bit)
      23      8     PacketSeq (64-bit)
      31      8     Timestamp (64-bit)
      39      16    SrcNodeID (128-bit)
      55      16    DstSvcID (128-bit)
      71      4     PolicyTag (32-bit)
      75      2     ExtLen
      77      2     PayloadLen
      79      1     Reserved
      80      16    HeaderAuthTag (128-bit)

  ## Message Types

  - 0 — DATA
  - 1 — HELLO (session initiation)
  - 2 — HELLO_ACK (session response)
  - 3 — REKEY
  - 4 — CLOSE
  - 5 — ERROR
  - 6 — PING
  - 7 — PONG
  - 8 — MIGRATE
  """

  # ZTLP magic bytes: 'Z7' in ASCII = 0x5A37
  @magic 0x5A37

  # HdrLen values (in 4-byte words)
  @data_hdr_len 12
  @handshake_hdr_len 24

  # Current protocol version
  @version 1

  # Header sizes in bytes
  @data_header_size 46
  @handshake_header_size 96

  # Message types
  @msg_data 0
  @msg_hello 1
  @msg_hello_ack 2
  @msg_rekey 3
  @msg_close 4
  @msg_error 5
  @msg_ping 6
  @msg_pong 7
  @msg_migrate 8

  # Zero SessionID (used for HELLO messages)
  @zero_session_id <<0::96>>

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type session_id :: <<_::96>>
  @type msg_type :: :data | :hello | :hello_ack | :rekey | :close | :error | :ping | :pong | :migrate

  @type data_packet :: %{
          type: :data_compact,
          magic: non_neg_integer(),
          version: non_neg_integer(),
          hdr_len: non_neg_integer(),
          flags: non_neg_integer(),
          session_id: session_id(),
          packet_seq: non_neg_integer(),
          header_auth_tag: binary(),
          ext_len: non_neg_integer(),
          payload_len: non_neg_integer(),
          payload: binary()
        }

  @type handshake_packet :: %{
          type: :handshake,
          magic: non_neg_integer(),
          version: non_neg_integer(),
          hdr_len: non_neg_integer(),
          flags: non_neg_integer(),
          msg_type: msg_type(),
          crypto_suite: non_neg_integer(),
          key_id: non_neg_integer(),
          session_id: session_id(),
          packet_seq: non_neg_integer(),
          timestamp: non_neg_integer(),
          src_node_id: binary(),
          dst_svc_id: binary(),
          policy_tag: non_neg_integer(),
          ext_len: non_neg_integer(),
          payload_len: non_neg_integer(),
          header_auth_tag: binary(),
          payload: binary()
        }

  @type packet :: data_packet() | handshake_packet()

  # ---------------------------------------------------------------------------
  # Fast extractors (used by the pipeline for cheap checks)
  # ---------------------------------------------------------------------------

  @doc """
  Check if a binary starts with the ZTLP magic bytes (0x5A37).

  This is Layer 1 of the admission pipeline — the cheapest possible
  check, just two byte comparisons.
  """
  @spec valid_magic?(binary()) :: boolean()
  def valid_magic?(<<@magic::16, _rest::binary>>), do: true
  def valid_magic?(_), do: false

  @doc """
  Extract the SessionID from a raw packet.

  Returns `{:ok, session_id}` or `:error` if the packet is too short.
  Works for both data and handshake packets.
  """
  @spec extract_session_id(binary()) :: {:ok, session_id()} | {:error, atom()}
  def extract_session_id(
        <<@magic::16, @version::4, @handshake_hdr_len::12, _flags::16, _msg_type::8,
          _crypto_suite::16, _key_id::16, session_id::binary-size(12), _::binary>>
      ) do
    {:ok, session_id}
  end

  def extract_session_id(
        <<@magic::16, @version::4, @data_hdr_len::12, _flags::16, session_id::binary-size(12),
          _::binary>>
      ) do
    {:ok, session_id}
  end

  def extract_session_id(_), do: {:error, :cannot_extract_session_id}

  @doc """
  Extract the service name from a handshake packet's dst_svc_id field.
  Returns the service name as a trimmed UTF-8 string (null bytes stripped).
  """
  def extract_service_name(
        <<@magic::16, @version::4, @handshake_hdr_len::12, _flags::16, _msg_type::8,
          _crypto_suite::16, _key_id::16, _session_id::binary-size(12),
          _packet_seq::64, _timestamp::64, _src_node_id::binary-size(16),
          dst_svc_id::binary-size(16), _::binary>>
      ) do
    # Strip trailing null bytes and decode as UTF-8
    name = dst_svc_id |> :binary.replace(<<0>>, <<>>, [:global]) |> String.trim()
    if name == "", do: "default", else: name
  end

  def extract_service_name(_), do: "default"

  @doc """
  Extract the HdrLen field to determine packet type.

  Returns `:data` (HdrLen=12), `:handshake` (HdrLen=24), or `:unknown`.
  """
  @spec packet_type(binary()) :: :data | :handshake | :unknown
  def packet_type(<<@magic::16, _version::4, hdr_len::12, _rest::binary>>) do
    case hdr_len do
      @data_hdr_len -> :data
      @handshake_hdr_len -> :handshake
      _ -> :unknown
    end
  end

  def packet_type(_), do: :unknown

  @doc """
  Check if a packet is a HELLO (handshake header with msg_type HELLO).
  """
  @spec hello?(binary()) :: boolean()
  def hello?(
        <<@magic::16, @version::4, @handshake_hdr_len::12, _flags::16, @msg_hello::8,
          _::binary>>
      ),
      do: true

  def hello?(_), do: false

  @doc """
  Check if a raw packet is a HELLO_ACK message.
  """
  @spec hello_ack?(binary()) :: boolean()
  def hello_ack?(
        <<@magic::16, @version::4, @handshake_hdr_len::12, _flags::16, @msg_hello_ack::8,
          _::binary>>
      ),
      do: true

  def hello_ack?(_), do: false

  @doc """
  Check if a raw packet is a handshake/control message (not compact data).
  """
  @spec handshake?(binary()) :: boolean()
  def handshake?(<<@magic::16, _version::4, @handshake_hdr_len::12, _::binary>>), do: true
  def handshake?(_), do: false

  # ---------------------------------------------------------------------------
  # Parsing
  # ---------------------------------------------------------------------------

  @doc """
  Parse a raw binary into a structured packet map.

  Returns `{:ok, packet}` or `{:error, reason}`.
  Dispatches to data or handshake parsing based on the HdrLen field.
  """
  @spec parse(binary()) :: {:ok, packet()} | {:error, atom() | String.t()}
  def parse(
        <<@magic::16, @version::4, @handshake_hdr_len::12, flags::16, msg_type_byte::8,
          crypto_suite::16, key_id::16, session_id::binary-size(12), packet_seq::64,
          timestamp::64, src_node_id::binary-size(16), dst_svc_id::binary-size(16),
          policy_tag::32, ext_len::16, payload_len::16, _reserved::8,
          header_auth_tag::binary-size(16), payload::binary>>
      ) do
    case decode_msg_type(msg_type_byte) do
      {:ok, msg_type} ->
        {:ok,
         %{
           type: :handshake,
           magic: @magic,
           version: @version,
           hdr_len: @handshake_hdr_len,
           flags: flags,
           msg_type: msg_type,
           crypto_suite: crypto_suite,
           key_id: key_id,
           session_id: session_id,
           packet_seq: packet_seq,
           timestamp: timestamp,
           src_node_id: src_node_id,
           dst_svc_id: dst_svc_id,
           policy_tag: policy_tag,
           ext_len: ext_len,
           payload_len: payload_len,
           header_auth_tag: header_auth_tag,
           payload: payload
         }}

      {:error, _} = err ->
        err
    end
  end

  def parse(
        <<@magic::16, @version::4, @data_hdr_len::12, flags::16, session_id::binary-size(12),
          packet_seq::64, header_auth_tag::binary-size(16), ext_len::16, payload_len::16,
          payload::binary>>
      ) do
    {:ok,
     %{
       type: :data_compact,
       magic: @magic,
       version: @version,
       hdr_len: @data_hdr_len,
       flags: flags,
       session_id: session_id,
       packet_seq: packet_seq,
       header_auth_tag: header_auth_tag,
       ext_len: ext_len,
       payload_len: payload_len,
       payload: payload
     }}
  end

  # Bad magic
  def parse(<<magic::16, _::binary>>) when magic != @magic do
    {:error, :invalid_magic}
  end

  # Bad version
  def parse(<<@magic::16, version::4, _::12, _::binary>>) when version != @version do
    {:error, :unsupported_version}
  end

  # Unknown HdrLen
  def parse(<<@magic::16, @version::4, hdr_len::12, _::binary>>)
      when hdr_len != @handshake_hdr_len and hdr_len != @data_hdr_len do
    {:error, :unknown_header_type}
  end

  # Too short
  def parse(_data) do
    {:error, :buffer_too_short}
  end

  # ---------------------------------------------------------------------------
  # Serialization
  # ---------------------------------------------------------------------------

  @doc """
  Serialize a handshake packet map back to binary.
  """
  @spec serialize_handshake(handshake_packet()) :: binary()
  def serialize_handshake(pkt) do
    msg_type_byte = encode_msg_type(pkt.msg_type)

    header = <<
      @magic::16,
      @version::4,
      @handshake_hdr_len::12,
      pkt.flags::16,
      msg_type_byte::8,
      pkt.crypto_suite::16,
      pkt.key_id::16,
      pkt.session_id::binary-size(12),
      pkt.packet_seq::64,
      pkt.timestamp::64,
      pkt.src_node_id::binary-size(16),
      pkt.dst_svc_id::binary-size(16),
      pkt.policy_tag::32,
      pkt.ext_len::16,
      pkt.payload_len::16,
      0::8,
      pkt.header_auth_tag::binary-size(16)
    >>

    <<header::binary, pkt.payload::binary>>
  end

  @doc """
  Serialize a compact data packet map back to binary.
  """
  @spec serialize_data(data_packet()) :: binary()
  def serialize_data(pkt) do
    header = <<
      @magic::16,
      @version::4,
      @data_hdr_len::12,
      pkt.flags::16,
      pkt.session_id::binary-size(12),
      pkt.packet_seq::64,
      pkt.header_auth_tag::binary-size(16),
      Map.get(pkt, :ext_len, 0)::16,
      Map.get(pkt, :payload_len, 0)::16
    >>

    <<header::binary, pkt.payload::binary>>
  end

  @doc """
  Compute the ZTLP header auth tag for a serialized data packet.
  Uses ChaCha20-Poly1305 in MAC-only mode (encrypt empty plaintext with header AAD).
  The AAD is bytes [0..26) ++ bytes [42..46) (skipping the auth tag field).
  Returns the 16-byte Poly1305 tag.
  """
  @spec compute_data_auth_tag(binary(), binary()) :: binary()
  def compute_data_auth_tag(key, serialized_packet) when byte_size(key) == 32 do
    # AAD = pre-tag bytes [0..26) + post-tag bytes [42..46)
    pre_tag = binary_part(serialized_packet, 0, 26)
    post_tag = binary_part(serialized_packet, 42, 4)
    aad = pre_tag <> post_tag
    nonce = <<0::96>>

    # Encrypt empty plaintext with AAD — the tag IS the auth tag
    {<<>>, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, <<>>, aad, true)
    tag
  end

  @doc """
  Serialize a data packet with a proper header auth tag computed from the given key.
  """
  @spec serialize_data_with_auth(data_packet(), binary()) :: binary()
  def serialize_data_with_auth(pkt, key) do
    # First serialize with placeholder auth tag
    pkt = %{pkt | header_auth_tag: <<0::128>>}
    raw = serialize_data(pkt)

    # Compute the real auth tag
    auth_tag = compute_data_auth_tag(key, raw)

    # Replace the placeholder (bytes 26..42) with the real tag
    <<pre::binary-size(26), _::binary-size(16), post::binary>> = raw
    <<pre::binary, auth_tag::binary, post::binary>>
  end

  @doc """
  Serialize any parsed packet (dispatches based on `:type` key).
  """
  @spec serialize(packet()) :: binary()
  def serialize(%{type: :handshake} = pkt), do: serialize_handshake(pkt)
  def serialize(%{type: :data_compact} = pkt), do: serialize_data(pkt)

  @doc """
  Build a handshake packet map with sensible defaults.
  """
  @spec build_handshake(msg_type(), binary(), keyword()) :: handshake_packet()
  def build_handshake(msg_type, session_id, opts \\ []) do
    %{
      type: :handshake,
      magic: @magic,
      version: @version,
      hdr_len: @handshake_hdr_len,
      flags: Keyword.get(opts, :flags, 0),
      msg_type: msg_type,
      crypto_suite: Keyword.get(opts, :crypto_suite, 0x0001),
      key_id: Keyword.get(opts, :key_id, 0),
      session_id: session_id,
      packet_seq: Keyword.get(opts, :packet_seq, 0),
      timestamp: Keyword.get(opts, :timestamp, System.system_time(:millisecond)),
      src_node_id: Keyword.get(opts, :src_node_id, <<0::128>>),
      dst_svc_id: Keyword.get(opts, :dst_svc_id, <<0::128>>),
      policy_tag: Keyword.get(opts, :policy_tag, 0),
      ext_len: Keyword.get(opts, :ext_len, 0),
      payload_len: Keyword.get(opts, :payload_len, 0),
      header_auth_tag: Keyword.get(opts, :header_auth_tag, <<0::128>>),
      payload: Keyword.get(opts, :payload, <<>>)
    }
  end

  @doc """
  Build a compact data packet map with sensible defaults.
  """
  @spec build_data(binary(), non_neg_integer(), keyword()) :: data_packet()
  def build_data(session_id, packet_seq, opts \\ []) do
    %{
      type: :data_compact,
      magic: @magic,
      version: @version,
      hdr_len: @data_hdr_len,
      flags: Keyword.get(opts, :flags, 0),
      session_id: session_id,
      packet_seq: packet_seq,
      header_auth_tag: Keyword.get(opts, :header_auth_tag, <<0::128>>),
      ext_len: Keyword.get(opts, :ext_len, 0),
      payload_len: Keyword.get(opts, :payload_len, 0),
      payload: Keyword.get(opts, :payload, <<>>)
    }
  end

  @doc """
  Build a HELLO packet.
  """
  @spec build_hello(binary()) :: binary()
  def build_hello(payload) do
    pkt = build_handshake(:hello, @zero_session_id, payload: payload)
    serialize_handshake(pkt)
  end

  @doc """
  Build a HELLO_ACK packet.
  """
  @spec build_hello_ack(session_id(), binary()) :: binary()
  def build_hello_ack(session_id, payload) do
    pkt = build_handshake(:hello_ack, session_id, payload: payload)
    serialize_handshake(pkt)
  end

  @doc """
  Extract the AAD (Additional Authenticated Data) portion of a raw packet.

  This is the header bytes WITHOUT the HeaderAuthTag (last 16 bytes of the header).
  """
  @spec extract_aad(binary()) :: {:ok, binary()} | {:error, atom()}
  def extract_aad(<<@magic::16, @version::4, @handshake_hdr_len::12, _::binary>> = data)
      when byte_size(data) >= @handshake_header_size do
    {:ok, binary_part(data, 0, @handshake_header_size - 16)}
  end

  def extract_aad(<<@magic::16, @version::4, @data_hdr_len::12, _::binary>> = data)
      when byte_size(data) >= @data_header_size do
    {:ok, binary_part(data, 0, @data_header_size - 16)}
  end

  def extract_aad(_), do: {:error, :cannot_extract_aad}

  @doc """
  Extract the HeaderAuthTag from a raw packet.
  """
  @spec extract_auth_tag(binary()) :: {:ok, binary()} | {:error, atom()}
  def extract_auth_tag(<<@magic::16, @version::4, @handshake_hdr_len::12, _::binary>> = data)
      when byte_size(data) >= @handshake_header_size do
    {:ok, binary_part(data, @handshake_header_size - 16, 16)}
  end

  def extract_auth_tag(<<@magic::16, @version::4, @data_hdr_len::12, _::binary>> = data)
      when byte_size(data) >= @data_header_size do
    {:ok, binary_part(data, @data_header_size - 16, 16)}
  end

  def extract_auth_tag(_), do: {:error, :cannot_extract_auth_tag}

  # ---------------------------------------------------------------------------
  # Constants (exposed for other modules)
  # ---------------------------------------------------------------------------

  @doc "ZTLP magic value (0x5A37)."
  @spec magic() :: 0x5A37
  def magic, do: @magic

  @doc "Zero SessionID (12 bytes of zeros)."
  @spec zero_session_id() :: session_id()
  def zero_session_id, do: @zero_session_id

  @doc "Data header size in bytes."
  @spec data_header_size() :: 46
  def data_header_size, do: @data_header_size

  @doc "Handshake header size in bytes."
  @spec handshake_header_size() :: 96
  def handshake_header_size, do: @handshake_header_size

  # ---------------------------------------------------------------------------
  # Message type encoding/decoding
  # ---------------------------------------------------------------------------

  @spec decode_msg_type(non_neg_integer()) :: {:ok, msg_type()} | {:error, :invalid_msg_type}
  defp decode_msg_type(@msg_data), do: {:ok, :data}
  defp decode_msg_type(@msg_hello), do: {:ok, :hello}
  defp decode_msg_type(@msg_hello_ack), do: {:ok, :hello_ack}
  defp decode_msg_type(@msg_rekey), do: {:ok, :rekey}
  defp decode_msg_type(@msg_close), do: {:ok, :close}
  defp decode_msg_type(@msg_error), do: {:ok, :error}
  defp decode_msg_type(@msg_ping), do: {:ok, :ping}
  defp decode_msg_type(@msg_pong), do: {:ok, :pong}
  defp decode_msg_type(@msg_migrate), do: {:ok, :migrate}
  defp decode_msg_type(_), do: {:error, :invalid_msg_type}

  @doc false
  @spec encode_msg_type(msg_type()) :: non_neg_integer()
  def encode_msg_type(:data), do: @msg_data
  def encode_msg_type(:hello), do: @msg_hello
  def encode_msg_type(:hello_ack), do: @msg_hello_ack
  def encode_msg_type(:rekey), do: @msg_rekey
  def encode_msg_type(:close), do: @msg_close
  def encode_msg_type(:error), do: @msg_error
  def encode_msg_type(:ping), do: @msg_ping
  def encode_msg_type(:pong), do: @msg_pong
  def encode_msg_type(:migrate), do: @msg_migrate
end
