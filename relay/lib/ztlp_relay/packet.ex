defmodule ZtlpRelay.Packet do
  @moduledoc """
  ZTLP packet parsing and serialization using Elixir binary pattern matching.

  Implements the exact bit-level layout from the ZTLP spec:

  **Handshake Header (95 bytes):**

      <<magic::16, ver::4, hdr_len::12, flags::16, msg_type::8,
        crypto_suite::16, key_id::16, session_id::binary-size(12),
        packet_seq::64, timestamp::64, src_node_id::binary-size(16),
        dst_svc_id::binary-size(16), policy_tag::32, ext_len::16,
        payload_len::16, header_auth_tag::binary-size(16)>>

  **Compact Data Header (42 bytes):**

      <<magic::16, ver::4, hdr_len::12, flags::16,
        session_id::binary-size(12), packet_seq::64,
        header_auth_tag::binary-size(16)>>

  Packet type discrimination uses the HdrLen field:
  - HdrLen = 24 → Handshake header (95 bytes)
  - HdrLen = 11 → Compact data header (42 bytes)
  """

  @magic 0x5A37
  @version 1
  @handshake_header_size 95
  @data_header_size 42
  @handshake_hdr_len 24
  @data_hdr_len 11

  # Message types
  @msg_data 0
  @msg_hello 1
  @msg_hello_ack 2
  @msg_rekey 3
  @msg_close 4
  @msg_error 5
  @msg_ping 6
  @msg_pong 7

  @type session_id :: <<_::96>>
  @type msg_type :: :data | :hello | :hello_ack | :rekey | :close | :error | :ping | :pong

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

  @type data_packet :: %{
          type: :data_compact,
          magic: non_neg_integer(),
          version: non_neg_integer(),
          hdr_len: non_neg_integer(),
          flags: non_neg_integer(),
          session_id: session_id(),
          packet_seq: non_neg_integer(),
          header_auth_tag: binary(),
          payload: binary()
        }

  @type parsed_packet :: handshake_packet() | data_packet()

  @doc """
  Returns the ZTLP magic value.
  """
  @spec magic() :: 0x5A37
  def magic, do: @magic

  @doc """
  Returns the handshake header size in bytes.
  """
  @spec handshake_header_size() :: 95
  def handshake_header_size, do: @handshake_header_size

  @doc """
  Returns the compact data header size in bytes.
  """
  @spec data_header_size() :: 42
  def data_header_size, do: @data_header_size

  @doc """
  Parse a raw binary packet into a structured map.

  Uses the HdrLen field to discriminate between handshake and data headers:
  - HdrLen = 24 → Handshake header (95 bytes)
  - HdrLen = 11 → Compact data header (42 bytes)

  Returns `{:ok, parsed_packet}` or `{:error, reason}`.
  """
  @spec parse(binary()) :: {:ok, parsed_packet()} | {:error, atom() | String.t()}
  def parse(
        <<@magic::16, @version::4, @handshake_hdr_len::12, flags::16, msg_type_byte::8,
          crypto_suite::16, key_id::16, session_id::binary-size(12), packet_seq::64,
          timestamp::64, src_node_id::binary-size(16), dst_svc_id::binary-size(16),
          policy_tag::32, ext_len::16, payload_len::16, header_auth_tag::binary-size(16),
          payload::binary>>
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
          packet_seq::64, header_auth_tag::binary-size(16), payload::binary>>
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
      pkt.header_auth_tag::binary-size(16)
    >>

    <<header::binary, pkt.payload::binary>>
  end

  @doc """
  Serialize any parsed packet (dispatches based on `:type` key).
  """
  @spec serialize(parsed_packet()) :: binary()
  def serialize(%{type: :handshake} = pkt), do: serialize_handshake(pkt)
  def serialize(%{type: :data_compact} = pkt), do: serialize_data(pkt)

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

  @doc """
  Extract the session_id from a raw binary packet without full parsing.

  Fast path for pipeline Layer 2.
  """
  @spec extract_session_id(binary()) :: {:ok, binary()} | {:error, atom()}
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
  Check if a raw packet has the correct ZTLP magic (fast Layer 1 check).
  """
  @spec valid_magic?(binary()) :: boolean()
  def valid_magic?(<<@magic::16, _::binary>>), do: true
  def valid_magic?(_), do: false

  @doc """
  Check if a raw packet is a handshake HELLO message.
  """
  @spec hello?(binary()) :: boolean()
  def hello?(
        <<@magic::16, @version::4, @handshake_hdr_len::12, _flags::16, @msg_hello::8, _::binary>>
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
      payload: Keyword.get(opts, :payload, <<>>)
    }
  end

  # Message type encoding/decoding

  @spec decode_msg_type(non_neg_integer()) :: {:ok, msg_type()} | {:error, :invalid_msg_type}
  defp decode_msg_type(@msg_data), do: {:ok, :data}
  defp decode_msg_type(@msg_hello), do: {:ok, :hello}
  defp decode_msg_type(@msg_hello_ack), do: {:ok, :hello_ack}
  defp decode_msg_type(@msg_rekey), do: {:ok, :rekey}
  defp decode_msg_type(@msg_close), do: {:ok, :close}
  defp decode_msg_type(@msg_error), do: {:ok, :error}
  defp decode_msg_type(@msg_ping), do: {:ok, :ping}
  defp decode_msg_type(@msg_pong), do: {:ok, :pong}
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
end
