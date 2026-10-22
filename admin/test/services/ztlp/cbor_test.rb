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
end
