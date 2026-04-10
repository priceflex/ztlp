defmodule ZtlpRelay.VipFrame do
  @moduledoc """
  VIP tunnel mux frame parsing and serialization.

  For iOS relay-side VIP mode, the relay decrypts tunnel payloads from the
  Network Extension and parses mux frames to extract service routing metadata
  and TCP connection data.

  ## Wire Format (inside decrypted ZTLP data packet payload)

      <<connection_id::16, flags::8, payload::binary>>

  Frame types (encoded in flags):

  | Flag    | Value | Purpose                                        |
  |---------|-------|------------------------------------------------|
  | SYN     | 0x01  | New TCP connection request                     |
  | DATA    | 0x02  | TCP payload data (on established connection)   |
  | FIN     | 0x04  | Graceful connection close                      |
  | RST     | 0x08  | Connection reset                               |

  The service name is derived from the ZTLP packet's `dst_svc_id` field
  (16 bytes), which is a trusted mux metadata field.  Routing MUST be
  based on this field, not on application-layer hints like HTTP Host headers.
  """

  @type flags :: non_neg_integer()
  @type frame_type :: :syn | :data | :fin | :rst
  @type parsed_frame :: %{
          connection_id: non_neg_integer(),
          frame_type: frame_type(),
          flags: flags(),
          payload: binary()
        }

  @flag_syn 0x01
  @flag_data 0x02
  @flag_fin 0x04
  @flag_rst 0x08

  # Minimum frame size: connection_id(2) + flags(1) = 3 bytes
  @min_frame_size 3

  @doc """
  Parse a raw VIP data payload into a structured frame.

  Returns `{:ok, parsed_frame}` or `{:error, reason}`.
  """
  @spec parse(binary()) :: {:ok, parsed_frame()} | {:error, atom()}
  def parse(<<cid::16, flags::8, payload::binary>>)
      when byte_size(payload) + 3 >= @min_frame_size do
    frame_type = classify_flags(flags)

    {:ok,
     %{
       connection_id: cid,
       frame_type: frame_type,
       flags: flags,
       payload: payload
     }}
  end

  def parse(<<>>) when true, do: {:error, :frame_too_short}

  def parse(_bad) do
    {:error, :frame_too_short}
  end

  @doc """
  Encode a VIP frame to binary.

  Accepts either a raw flags value or an atom frame type.
  """
  @spec encode(non_neg_integer(), flags() | frame_type(), binary()) :: binary()
  def encode(connection_id, flags, payload)
      when is_integer(connection_id) and is_integer(flags) do
    <<connection_id::16, flags::8, payload::binary>>
  end

  def encode(connection_id, :syn, payload),
    do: <<connection_id::16, @flag_syn::8, payload::binary>>

  def encode(connection_id, :data, payload),
    do: <<connection_id::16, @flag_data::8, payload::binary>>

  def encode(connection_id, :fin, payload),
    do: <<connection_id::16, @flag_fin::8, payload::binary>>

  def encode(connection_id, :rst, payload),
    do: <<connection_id::16, @flag_rst::8, payload::binary>>

  @doc """
  Classify flags into a primary frame type.

  When multiple flags are set, returns the most specific type:
  RST > FIN > SYN > DATA
  """
  @spec classify_flags(flags()) :: frame_type()
  def classify_flags(flags) do
    cond do
      Bitwise.band(flags, @flag_rst) != 0 -> :rst
      Bitwise.band(flags, @flag_fin) != 0 -> :fin
      Bitwise.band(flags, @flag_syn) != 0 -> :syn
      true -> :data
    end
  end

  @doc """
  Returns the minimum frame size in bytes.
  """
  @spec min_frame_size() :: integer()
  def min_frame_size, do: @min_frame_size
end
