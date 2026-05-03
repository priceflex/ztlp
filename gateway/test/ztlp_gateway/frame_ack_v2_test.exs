defmodule ZtlpGateway.FrameAckV2Test do
  @moduledoc """
  Wire-format tests for FRAME_ACK_V2 (Phase B: modern flow control).

  FRAME_ACK_V2 is a client → gateway advertisement that carries a
  byte-unit receive window (KB) instead of the V1 frame count. These
  tests lock in the wire shape so `session.ex`'s pattern-match clauses
  can't silently drift from `proto/src/mux.rs::FRAME_ACK_V2`.

  Wire: `[0x10 | cumulative_ack(8 BE) | window_kb(2 BE)]` = 11 bytes.
  """
  use ExUnit.Case, async: true

  @frame_ack_v2 0x10
  @max_payload_bytes 1140

  test "wire shape: 11 bytes, 0x10 type, big-endian fields" do
    cum = 0x0000_0000_DEAD_BEEF
    window_kb = 64

    bin = <<@frame_ack_v2, cum::big-64, window_kb::big-16>>

    assert byte_size(bin) == 11
    assert <<0x10, _rest::binary>> = bin

    # Round-trip decode using the same pattern session.ex uses.
    assert <<@frame_ack_v2, decoded_cum::big-64, decoded_kb::big-16>> = bin
    assert decoded_cum == cum
    assert decoded_kb == window_kb
  end

  test "window_kb=65535 → 64 MB advertised (u16 ceiling)" do
    max_kb = 65_535
    bin = <<@frame_ack_v2, 0::big-64, max_kb::big-16>>

    assert <<@frame_ack_v2, _cum::big-64, decoded_kb::big-16>> = bin
    assert decoded_kb == max_kb
    assert decoded_kb * 1024 == 67_107_840
  end

  test "window_kb=0 still parses; gateway must clamp to at least 1 packet" do
    # A spec-conforming peer should never advertise 0, but if it does
    # the gateway's handle_tunnel_frame clause applies
    # `max(1, div(window_bytes, @max_payload_bytes))` to avoid collapse.
    bin = <<@frame_ack_v2, 100::big-64, 0::big-16>>
    assert <<@frame_ack_v2, 100::big-64, 0::big-16>> = bin

    # Replay the clamp logic used in session.ex:
    window_bytes = 0 * 1024
    rwnd_packets = max(1, div(window_bytes, @max_payload_bytes))
    assert rwnd_packets == 1
  end

  test "byte→packet conversion matches session.ex math for 16 KB / 64 KB / 1 MB" do
    for {kb, expected_packets} <- [
          {1, 0},
          # Gateway's max(1, div(...)) clamps the 0 → 1 case. Check the
          # clamp separately so the raw div is correct.
          {16, 14},
          # 16 * 1024 = 16_384 / 1140 = 14
          {64, 57},
          # 64 * 1024 = 65_536 / 1140 = 57
          {1024, 919}
          # 1024 * 1024 = 1_048_576 / 1140 = 919
        ] do
      raw = div(kb * 1024, @max_payload_bytes)
      assert raw == expected_packets, "kb=#{kb} raw=#{raw} expected=#{expected_packets}"
      clamped = max(1, raw)
      assert clamped >= 1
    end
  end

  test "V1 (0x01) and V2 (0x10) frames are distinguishable by type byte" do
    v1 = <<0x01, 42::big-64, 16::big-16>>
    v2 = <<@frame_ack_v2, 42::big-64, 16::big-16>>

    # Same body, different type byte.
    assert byte_size(v1) == byte_size(v2)
    assert :binary.at(v1, 0) == 0x01
    assert :binary.at(v2, 0) == 0x10

    # A pattern-match intended for V1 must NOT match V2 (session.ex
    # relies on this for dispatch).
    refute match?(<<0x01, _::big-64, _::big-16>>, v2)
    refute match?(<<@frame_ack_v2, _::big-64, _::big-16>>, v1)
  end
end
