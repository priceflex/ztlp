defmodule ZtlpGateway.Packet do
  @moduledoc """
  ZTLP packet parsing and serialization.

  All ZTLP packets share a common header prefix:

      Byte 0-1: Magic (0x5A37 — 'Z7')
      Byte 2-3: Version (4 bits) + HdrLen (12 bits)

  The HdrLen field discriminates packet types:
  - **HdrLen = 11** → Data packet (42-byte header)
  - **HdrLen = 24** → Handshake packet (95-byte header)

  ## Data Packet Header (42 bytes)

      Offset  Size  Field
      ------  ----  -----
      0       2     Magic (0x5A37)
      2       2     Version (4b) + HdrLen=11 (12b)
      4       16    SessionID (128-bit)
      20      8     SequenceNumber (64-bit big-endian)
      28      1     Flags
      29      1     PayloadType
      30      12    HeaderAuthTag (96-bit truncated AEAD tag)

  ## Handshake Packet Header (95 bytes)

      Offset  Size  Field
      ------  ----  -----
      0       2     Magic (0x5A37)
      2       2     Version (4b) + HdrLen=24 (12b)
      4       16    SessionID (128-bit, zero for HELLO)
      20      1     MsgType
      21      2     PayloadLength (16-bit)
      23      8     Reserved
      31      64    HandshakePayloadAuthTag (512-bit)

  ## Message Types

  - 0x01 — HELLO (session initiation, SessionID = 0)
  - 0x02 — HELLO_ACK (session response)
  - 0x03 — HANDSHAKE (Noise_XX message exchange)
  - 0x10 — DATA (encrypted application data)
  """

  # ZTLP magic bytes: 'Z7' in ASCII = 0x5A37
  @magic <<0x5A, 0x37>>

  # HdrLen values (in 4-byte words)
  @hdr_len_data 11       # 11 words → data header
  @hdr_len_handshake 24  # 24 words → handshake header

  # Current protocol version
  @version 1

  # Header sizes in bytes
  @data_header_size 42
  @handshake_header_size 95

  # Message types
  @msg_hello 0x01
  @msg_hello_ack 0x02
  @msg_handshake 0x03
  @msg_data 0x10

  # Zero SessionID (used for HELLO messages)
  @zero_session_id <<0::128>>

  # ---------------------------------------------------------------------------
  # Types
  # ---------------------------------------------------------------------------

  @type session_id :: <<_::128>>
  @type msg_type :: :hello | :hello_ack | :handshake | :data
  @type flags :: non_neg_integer()

  @type data_packet :: %{
    type: :data,
    session_id: session_id(),
    sequence: non_neg_integer(),
    flags: flags(),
    payload_type: non_neg_integer(),
    header_auth_tag: binary(),
    payload: binary()
  }

  @type handshake_packet :: %{
    type: :handshake,
    session_id: session_id(),
    msg_type: msg_type(),
    payload_length: non_neg_integer(),
    auth_tag: binary(),
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
  def valid_magic?(<<0x5A, 0x37, _rest::binary>>), do: true
  def valid_magic?(_), do: false

  @doc """
  Extract the SessionID from a raw packet (bytes 4-19).

  Returns `{:ok, session_id}` or `:error` if the packet is too short.
  Works for both data and handshake packets since SessionID is at the
  same offset in both header types.
  """
  @spec extract_session_id(binary()) :: {:ok, session_id()} | :error
  def extract_session_id(<<_magic::binary-size(2), _vh::binary-size(2),
                           session_id::binary-size(16), _rest::binary>>) do
    {:ok, session_id}
  end

  def extract_session_id(_), do: :error

  @doc """
  Extract the HdrLen field to determine packet type.

  Returns `:data` (HdrLen=11), `:handshake` (HdrLen=24), or `:unknown`.
  """
  @spec packet_type(binary()) :: :data | :handshake | :unknown
  def packet_type(<<_magic::binary-size(2), _version::4, hdr_len::12, _rest::binary>>) do
    case hdr_len do
      @hdr_len_data -> :data
      @hdr_len_handshake -> :handshake
      _ -> :unknown
    end
  end

  def packet_type(_), do: :unknown

  @doc """
  Check if a packet is a HELLO (zero SessionID + handshake header).
  HELLO packets initiate new sessions and must be allowed through
  the SessionID check in Layer 2.
  """
  @spec hello?(binary()) :: boolean()
  def hello?(<<0x5A, 0x37, _v::4, @hdr_len_handshake::12,
               0::128, @msg_hello, _rest::binary>>), do: true
  def hello?(_), do: false

  # ---------------------------------------------------------------------------
  # Parsing
  # ---------------------------------------------------------------------------

  @doc """
  Parse a raw binary into a structured packet map.

  Returns `{:ok, packet}` or `{:error, reason}`.
  Dispatches to data or handshake parsing based on the HdrLen field.
  """
  @spec parse(binary()) :: {:ok, packet()} | {:error, atom()}
  def parse(<<0x5A, 0x37, _version::4, hdr_len::12, rest::binary>> = _raw) do
    case hdr_len do
      @hdr_len_data -> parse_data(rest)
      @hdr_len_handshake -> parse_handshake(rest)
      _ -> {:error, :unknown_hdr_len}
    end
  end

  def parse(<<0x5A, 0x37, _::binary>>), do: {:error, :truncated}
  def parse(_), do: {:error, :bad_magic}

  # ---------------------------------------------------------------------------
  # Serialization
  # ---------------------------------------------------------------------------

  @doc """
  Serialize a data packet to wire format.

  ## Parameters
  - `session_id` — 16-byte SessionID
  - `sequence` — 64-bit sequence number
  - `flags` — 8-bit flags byte
  - `payload_type` — 8-bit payload type
  - `header_auth_tag` — 12-byte header authentication tag
  - `payload` — encrypted payload bytes
  """
  @spec serialize_data(session_id(), non_neg_integer(), flags(),
                        non_neg_integer(), binary(), binary()) :: binary()
  def serialize_data(session_id, sequence, flags, payload_type, header_auth_tag, payload)
      when byte_size(session_id) == 16 and byte_size(header_auth_tag) == 12 do
    <<@magic::binary,
      @version::4, @hdr_len_data::12,
      session_id::binary-size(16),
      sequence::64,
      flags::8,
      payload_type::8,
      header_auth_tag::binary-size(12),
      payload::binary>>
  end

  @doc """
  Serialize a handshake packet to wire format.

  ## Parameters
  - `session_id` — 16-byte SessionID (zero for HELLO)
  - `msg_type` — message type atom (:hello, :hello_ack, :handshake)
  - `auth_tag` — 64-byte handshake auth tag (or zeros)
  - `payload` — handshake payload (Noise message bytes)
  """
  @spec serialize_handshake(session_id(), msg_type(), binary(), binary()) :: binary()
  def serialize_handshake(session_id, msg_type, auth_tag, payload)
      when byte_size(session_id) == 16 and byte_size(auth_tag) == 64 do
    mt = msg_type_to_byte(msg_type)
    payload_len = byte_size(payload)

    <<@magic::binary,
      @version::4, @hdr_len_handshake::12,
      session_id::binary-size(16),
      mt::8,
      payload_len::16,
      0::64,
      auth_tag::binary-size(64),
      payload::binary>>
  end

  @doc """
  Build a HELLO packet (zero SessionID, no auth tag).
  """
  @spec build_hello(binary()) :: binary()
  def build_hello(payload) do
    serialize_handshake(@zero_session_id, :hello, <<0::512>>, payload)
  end

  @doc """
  Build a HELLO_ACK packet.
  """
  @spec build_hello_ack(session_id(), binary()) :: binary()
  def build_hello_ack(session_id, payload) do
    serialize_handshake(session_id, :hello_ack, <<0::512>>, payload)
  end

  @doc """
  Build a DATA packet with a given header auth tag.
  """
  @spec build_data(session_id(), non_neg_integer(), binary(), binary()) :: binary()
  def build_data(session_id, sequence, header_auth_tag, payload) do
    serialize_data(session_id, sequence, 0, 0, header_auth_tag, payload)
  end

  # ---------------------------------------------------------------------------
  # Constants (exposed for other modules)
  # ---------------------------------------------------------------------------

  @doc "ZTLP magic bytes (0x5A37)."
  @spec magic() :: binary()
  def magic, do: @magic

  @doc "Zero SessionID (16 bytes of zeros)."
  @spec zero_session_id() :: session_id()
  def zero_session_id, do: @zero_session_id

  @doc "Data header size in bytes."
  @spec data_header_size() :: 42
  def data_header_size, do: @data_header_size

  @doc "Handshake header size in bytes."
  @spec handshake_header_size() :: 95
  def handshake_header_size, do: @handshake_header_size

  # ---------------------------------------------------------------------------
  # Internal parsing
  # ---------------------------------------------------------------------------

  defp parse_data(<<session_id::binary-size(16), sequence::64,
                    flags::8, payload_type::8,
                    header_auth_tag::binary-size(12),
                    payload::binary>>) do
    {:ok, %{
      type: :data,
      session_id: session_id,
      sequence: sequence,
      flags: flags,
      payload_type: payload_type,
      header_auth_tag: header_auth_tag,
      payload: payload
    }}
  end

  defp parse_data(_), do: {:error, :truncated_data}

  defp parse_handshake(<<session_id::binary-size(16), msg_type_byte::8,
                         payload_length::16, _reserved::64,
                         auth_tag::binary-size(64),
                         payload::binary>>) do
    mt = byte_to_msg_type(msg_type_byte)

    {:ok, %{
      type: :handshake,
      session_id: session_id,
      msg_type: mt,
      payload_length: payload_length,
      auth_tag: auth_tag,
      payload: payload
    }}
  end

  defp parse_handshake(_), do: {:error, :truncated_handshake}

  # ---------------------------------------------------------------------------
  # Message type encoding
  # ---------------------------------------------------------------------------

  defp msg_type_to_byte(:hello), do: @msg_hello
  defp msg_type_to_byte(:hello_ack), do: @msg_hello_ack
  defp msg_type_to_byte(:handshake), do: @msg_handshake
  defp msg_type_to_byte(:data), do: @msg_data

  defp byte_to_msg_type(@msg_hello), do: :hello
  defp byte_to_msg_type(@msg_hello_ack), do: :hello_ack
  defp byte_to_msg_type(@msg_handshake), do: :handshake
  defp byte_to_msg_type(@msg_data), do: :data
  defp byte_to_msg_type(_), do: :unknown
end
