defmodule ZtlpGateway.Quic.FrameTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Task Q2 (ztlp-cloud-demo-plan.md, Session 3): L2 magic framing used on
  EVERY QUIC stream between the Rust client (`proto/src/quic_transport.rs`,
  `read_ztlp_frame`/`write_ztlp_frame`) and this gateway:

      +------+-------------+--------------+
      | 0x5A | len u16 BE  | payload[len] |
      +------+-------------+--------------+

  Constants are read from the Rust-generated fixture
  `test/fixtures/quic_handshake_vector.json` (Task Q0) so a Rust-side
  format change that regenerates the fixture fails here too.
  """

  alias ZtlpGateway.Quic.Frame

  @fixture Path.expand("../../fixtures/quic_handshake_vector.json", __DIR__)
  @external_resource @fixture

  fixture = File.read!(@fixture)

  # Minimal extraction — the gateway has no JSON dep and OTP 26 has no :json.
  fetch_int = fn key ->
    [_, v] = Regex.run(~r/"#{key}":\s*(\d+)/, fixture)
    String.to_integer(v)
  end

  [_, magic_hex] = Regex.run(~r/"stream0_magic_v1":\s*"0x([0-9A-Fa-f]+)"/, fixture)
  [_, endianness] = Regex.run(~r/"length_field_endianness":\s*"(\w+)"/, fixture)

  @magic String.to_integer(magic_hex, 16)
  @magic_bytes fetch_int.("magic_byte")
  @len_bytes fetch_int.("length_field_bytes")
  @max_frame fetch_int.("max_frame_size")
  @endianness endianness

  test "fixture contract matches what this module is built for" do
    assert @magic == 0x5A
    assert @magic_bytes == 1
    assert @len_bytes == 2
    assert @endianness == "big"
    assert @max_frame == 65_536
    assert Frame.magic() == @magic
    assert Frame.max_frame_size() == @max_frame
  end

  test "encode produces magic || u16 big-endian length || payload" do
    payload = "hello"
    len_bits = @len_bytes * 8
    assert Frame.encode(payload) == <<@magic, byte_size(payload)::size(len_bits)-big, payload::binary>>
  end

  test "encode/decode round-trip yields the payload and no leftover bytes" do
    payload = :crypto.strong_rand_bytes(1_000)
    assert {:ok, ^payload, <<>>} = Frame.decode(Frame.encode(payload))
  end

  test "zero-length payload round-trips cleanly" do
    assert Frame.encode(<<>>) == <<@magic, 0, 0>>
    assert {:ok, <<>>, <<>>} = Frame.decode(<<@magic, 0, 0>>)
  end

  test "decode returns {:more, buf} for an empty buffer and for a partial frame" do
    assert {:more, <<>>} = Frame.decode(<<>>)

    encoded = Frame.encode("partial")

    for cut <- 1..(byte_size(encoded) - 1) do
      <<head::binary-size(cut), _::binary>> = encoded
      assert {:more, ^head} = Frame.decode(head), "cut at #{cut} should be :more"
    end
  end

  test "decode reassembles a frame fed one byte at a time" do
    payload = :crypto.strong_rand_bytes(300)
    encoded = Frame.encode(payload)

    {result, _} =
      encoded
      |> :binary.bin_to_list()
      |> Enum.reduce({nil, <<>>}, fn
        _b, {{:ok, _, _} = done, buf} ->
          {done, buf}

        b, {nil, buf} ->
          buf = buf <> <<b>>

          case Frame.decode(buf) do
            {:more, ^buf} -> {nil, buf}
            {:ok, _, _} = ok -> {ok, <<>>}
          end
      end)

    assert {:ok, ^payload, <<>>} = result
  end

  test "decode returns the first frame and leaves the rest of the buffer intact" do
    a = Frame.encode("first")
    b = Frame.encode("second")
    <<b_head::binary-size(2), _::binary>> = b
    buf = a <> b <> b_head

    assert {:ok, "first", rest} = Frame.decode(buf)
    assert rest == b <> b_head
    assert {:ok, "second", ^b_head} = Frame.decode(rest)
    assert {:more, ^b_head} = Frame.decode(b_head)
  end

  test "decode rejects a wrong magic byte" do
    assert {:error, :bad_magic} = Frame.decode(<<0x37, 0, 1, ?x>>)
    # Legacy raw-UDP magic 0x5A37 starts with the right byte, then length would
    # be parsed — but a lone wrong first byte must be rejected immediately,
    # even before the length field is complete.
    assert {:error, :bad_magic} = Frame.decode(<<0x00>>)
  end

  test "decode rejects a declared length above max_frame_size" do
    # u16 max is 65535 < 65536, so a wire frame can never exceed the limit;
    # pin the boundary: the largest encodable length must be accepted.
    len_bits = @len_bytes * 8
    max_wire_len = Integer.pow(2, len_bits) - 1
    assert max_wire_len < @max_frame
    payload = :binary.copy(<<0>>, max_wire_len)
    assert {:ok, ^payload, <<>>} = Frame.decode(<<@magic, max_wire_len::size(len_bits)-big, payload::binary>>)
  end

  test "encode rejects a payload larger than the u16 length field can carry" do
    len_bits = @len_bytes * 8
    too_big = :binary.copy(<<0>>, Integer.pow(2, len_bits))
    assert {:error, :too_large} = Frame.encode(too_big)
  end

  test "encode rejects a payload over max_frame_size" do
    assert {:error, :too_large} = Frame.encode(:binary.copy(<<0>>, @max_frame + 1))
  end
end
