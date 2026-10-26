# frozen_string_literal: true

require "test_helper"

# Golden vectors from BUILD_LOOP.md §4 Slice 4 (verified 2026-10-21 against an
# independent Python encoder). These pin the deterministic RFC 8949 §4.2.1
# shape: text keys sorted by (byte_size, bytes) of the ENCODED key.
#
# The golden vectors are hex strings; `hex("a1616101")` converts them to the
# raw ASCII-8BIT bytes for byte-exact comparison.
class ZtlpCborTest < ActiveSupport::TestCase
  def hex(str)
    str.scan(/../).map { |p| p.to_i(16) }.pack("C*")
  end

  def enc(value)
    Ztlp::Cbor.encode(value)
  end

  test "single-key map of a small uint" do
    assert_equal hex("a1616101"), enc({ "a" => 1 })
  end

  test "keys sorted by (length, bytes): 'role' before 'public_key'" do
    expected = hex("a264726f6c6564757365726a7075626c69635f6b6579626162")
    assert_equal expected, enc({ "role" => "user", "public_key" => "ab" })
  end

  test "empty array value" do
    assert_equal hex("a1676465766963657380"), enc({ "devices" => [] })
  end

  test "booleans" do
    assert_equal hex("f5"), enc(true)
    assert_equal hex("f4"), enc(false)
  end

  test "uint 1000 uses the 2-byte form" do
    assert_equal hex("1903e8"), enc(1000)
  end

  test "uint boundary: 23 inline, 24 one-byte" do
    assert_equal hex("17"), enc(23)
    assert_equal hex("1818"), enc(24)
  end

  test "text string with a space is major type 3" do
    assert_equal hex("624120"), enc("A ")
  end

  test "byte string is major type 2 and distinct from text" do
    # "A " is valid UTF-8, so the encoder (like String.valid? in cbor.ex)
    # encodes it as TEXT (0x62), not bytes. Use a genuinely invalid UTF-8
    # sequence to exercise the byte-string (0x42) path.
    assert_equal hex("42c328"), enc("\xC3\x28".b)
  end

  test "nested map and array" do
    data = { "outer" => { "b" => 2, "a" => 1 }, "list" => [ 1, 2 ] }
    # "dlist" (header 0x64) < "eouter" (header 0x65): shorter encoded key first
    assert_equal hex("a2646c697374820102656f75746572a2616101616202"), enc(data)
  end

  test "encoding is deterministic (order of insertion irrelevant)" do
    assert_equal enc({ "b" => 2, "a" => 1 }), enc({ "a" => 1, "b" => 2 })
  end

  test "symbol keys encode as text (Elixir-map parity)" do
    assert_equal enc({ "a" => 1 }), enc({ a: 1 })
  end

  # ── decode (slice 4b: the NS record-data subset) ────────────────
  # Round-trips pin the decoder against the encoder; the uint vector
  # pins 24/25/26-extended integers, which `do_decode` once decoded as
  # the literal info byte (24/25/26) — a 1000 would come back as 24.

  test "decode round-trips a flat map of uint, text, bool, bytes, arrays" do
    data = {
      "node_id" => "abc123", "public_key" => "ab", "owner" => "steve.test.ztlp",
      "level" => 4, "ok" => true, "no" => false,
      "raw" => "\xC3\x28".b, "list" => [ 1, 2, "x" ],
      "nested" => { "b" => 2, "a" => 1 }
    }
    assert_equal data, Ztlp::Cbor.decode(enc(data))
  end

  test "decode handles extended uints (24, 300, 70000, 65536) exactly" do
    # NOTE: values >= 2**32 need the 8-byte (info 27) CBOR form, which the
    # minimal encoder does not yet emit. 65536 is the smallest value that
    # needs the 4-byte (info 26) form.
    [ 24, 300, 70_000, 65_536, 0xFFFF_FFFF ].each do |n|
      assert_equal n, Ztlp::Cbor.decode(Ztlp::Cbor.encode(n)), "uint #{n}"
    end
  end

  test "decode raises on unsupported CBOR items" do
    # 0xF9 is a half-precision float header — outside the NS record-data
    # subset the panel decodes.
    err = assert_raises(ArgumentError) { Ztlp::Cbor.decode("\xF9\x00\x00".b) }
    assert_match(/unsupported CBOR item/, err.message)
  end

  test "decode rejects a negative integer (major 1)" do
    assert_raises(ArgumentError) { Ztlp::Cbor.decode("\x20".b) }
  end
end
