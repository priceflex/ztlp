defmodule ZtlpGateway.Quic.Frame do
  @moduledoc """
  L2 magic framing for ZTLP-over-QUIC streams.

  Byte-exact contract with the Rust client (`proto/src/quic_transport.rs`,
  `noise_stream::read_ztlp_frame` / `write_ztlp_frame`):

      +------+-------------+--------------+
      | 0x5A | len u16 BE  | payload[len] |
      +------+-------------+--------------+

  * `0x5A` (`'Z'`) is `STREAM0_MAGIC_V1`. Same byte on the handshake control
    stream and on every data stream.
  * No version byte, counter, or MAC — confidentiality/integrity come from
    QUIC TLS 1.3; Noise_XX on stream 0 is client authentication only.
  * Frames may straddle QUIC STREAM frames, so `decode/1` works on a
    reassembly buffer and returns `{:more, buf}` until a full frame is there.
  * Data-frame boundaries carry no meaning: concatenate payloads to rebuild
    the TCP byte stream.

  Pure functions only; no processes, no I/O.
  """

  @magic 0x5A
  @len_bits 16
  @max_wire_len 0xFFFF
  @max_frame_size 65_536

  @type decode_result ::
          {:ok, payload :: binary(), rest :: binary()}
          | {:more, binary()}
          | {:error, :bad_magic | :too_large}

  @doc "The stream magic byte (`STREAM0_MAGIC_V1`)."
  @spec magic() :: 0x5A
  def magic, do: @magic

  @doc "Maximum frame payload size shared with the Rust side."
  @spec max_frame_size() :: pos_integer()
  def max_frame_size, do: @max_frame_size

  @doc """
  Encode a payload into a single frame.

  Rejects payloads the u16 length field cannot represent (`> 65535`) with
  `{:error, :too_large}` rather than silently truncating the length (the
  Rust writer's `as u16` cast would emit a corrupt frame for exactly 65536).
  """
  @spec encode(binary()) :: binary() | {:error, :too_large}
  def encode(payload) when is_binary(payload) and byte_size(payload) <= @max_wire_len do
    <<@magic, byte_size(payload)::size(@len_bits)-big, payload::binary>>
  end

  def encode(payload) when is_binary(payload), do: {:error, :too_large}

  @doc """
  Decode the first complete frame at the head of `buf`.

  Returns `{:ok, payload, rest}` with any trailing bytes left untouched for
  the next call, `{:more, buf}` when the buffer holds only a partial frame
  (including an empty buffer), `{:error, :bad_magic}` as soon as the first
  byte is not the magic byte, or `{:error, :too_large}` if the declared
  length exceeds `max_frame_size/0`.
  """
  @spec decode(binary()) :: decode_result()
  def decode(<<>>), do: {:more, <<>>}

  def decode(<<@magic, len::size(@len_bits)-big, rest::binary>> = buf) do
    cond do
      len > @max_frame_size -> {:error, :too_large}
      byte_size(rest) < len -> {:more, buf}
      true ->
        <<payload::binary-size(len), tail::binary>> = rest
        {:ok, payload, tail}
    end
  end

  def decode(<<@magic, _::binary>> = buf), do: {:more, buf}

  def decode(<<_other, _::binary>>), do: {:error, :bad_magic}
end
