# frozen_string_literal: true

require "test_helper"
require "base64"

# Slice 10a: the v1 binary enrollment token minter.
#
# Wire format (spec F8; verified byte-for-byte against the two sources of
# truth — proto/src/enrollment.rs serialize_without_mac and
# ns/lib/ztlp_ns/enrollment.ex parse_token, read from /home/trs/ztlp HEAD):
#
#   version::8 (0x01)
#   flags::8 (bit 0 = has gateway, bit 1 = has callback)
#   zone_len::16 zone
#   ns_len::16 ns_addr
#   relay_count::8 [relay_len::16 relay]*relay_count
#   [gw_len::16 gw]                       if flag 0x01
#   [cb_len::16 callback]                 if flag 0x02
#   max_uses::16
#   expires_at::64 (unix)
#   nonce::16
#   mac::32 (HMAC-BLAKE2s-256 over everything above, keyed with the
#            32-byte zone enrollment secret)
#
# The MAC is cross-checked live against the NS implementation: a running
# ztlp-ns:v0.35.20 container evaluated hmac_blake2s/2 (ns/lib/ztlp_ns/
# enrollment.ex, ipad/opad over the 64-byte zero-padded key) on
# key = 32 x 0x42, data = "hello world" and produced
# 0128d0eb05c551a625495a3a946b57329aea31a6fc8845e1e54768dd3526e8c0 —
# byte-identical to Ruby's OpenSSL::HMAC (same vector, same test). So the
# minter may delegate to OpenSSL::HMAC with OpenSSL::Digest "BLAKE2s256".
# (2026-10-23, ztlp-admin-directory-build-loop.)
class TokenMinterTest < ActiveSupport::TestCase
  # Fixed vector from the live NS cross-check above.
  GOLDEN_VECTOR_MAC = "0128d0eb05c551a625495a3a946b57329aea31a6fc8845e1e54768dd3526e8c0".freeze

  # 32-byte enrollment secret (64 hex), test-only, never a real secret.
  SECRET_HEX = "ab" * 32

  # The `nonce:` kwarg is a 16-byte BINARY string (the token's nonce field is
  # 16 raw bytes, F8) — the "01" * 16 form is 32 ASCII bytes.
  NONCE16 = [ "01" * 16 ].pack("H*")

  # 32-byte enrollment secret as RAW bytes (the MAC key is the 32-byte
  # enrollment secret itself, not its hex encoding).
  SECRET_RAW = [ SECRET_HEX ].pack("H*")

  def zone
    @zone ||= begin
      z = Zone.where(name: "minter.test.ztlp").first_or_create!(ns_addr: "127.0.0.1:23096")
      z.enrollment_secret_ct = SECRET_HEX
      z.relay_addrs = %w[10.0.0.9:23095]
      z.save!
      z
    end
  end

  teardown do
    Zone.where(name: "minter.test.ztlp").delete_all
  end

  # --------------------------------------------------------------- hmac

  test "hmac_blake2s matches the NS implementation on the live-cross-checked vector" do
    mac = Ztlp::Blake2sHmac.mac("\x42".b * 32, "hello world".b)
    assert_equal GOLDEN_VECTOR_MAC, mac.unpack1("H*")
  end

  test "hmac_blake2s keys a 32-byte secret (the NS enrollment-secret shape)" do
    mac = Ztlp::Blake2sHmac.mac(SECRET_RAW, "data")
    assert_equal 32, mac.bytesize
    assert_equal mac, Ztlp::Blake2sHmac.mac(SECRET_RAW, "data"), "deterministic"
  end

  # --------------------------------------------------------------- mint

  test "mint returns a v1 binary token with the exact F8 wire layout" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: Time.current.to_i + 3_600, nonce: NONCE16)

    assert_equal 0x01, bin.getbyte(0), "version byte"
    assert_equal 0x00, bin.getbyte(1), "flags (no gateway, no callback yet)"

    pos = 2
    zlen = bin.byteslice(pos, 2).unpack1("n"); pos += 2
    assert_equal "minter.test.ztlp", bin.byteslice(pos, zlen); pos += zlen
    nlen = bin.byteslice(pos, 2).unpack1("n"); pos += 2
    assert_equal "127.0.0.1:23096", bin.byteslice(pos, nlen); pos += nlen
    rc = bin.getbyte(pos); pos += 1
    assert_equal 1, rc, "one relay address"
    rlen = bin.byteslice(pos, 2).unpack1("n"); pos += 2
    assert_equal "10.0.0.9:23095", bin.byteslice(pos, rlen); pos += rlen
    mu = bin.byteslice(pos, 2).unpack1("n"); pos += 2
    assert_equal 1, mu, "max_uses = 1 (current tokens are single-use)"
    exp = bin.byteslice(pos, 8).unpack1("Q>"); pos += 8
    assert_operator exp, :>, Time.current.to_i
    assert_equal NONCE16, bin.byteslice(pos, 16), "nonce"
    pos += 16
    assert_equal 32, bin.bytesize - pos, "MAC is the final 32 bytes"
  end

  test "mint MAC verifies against the enrollment secret (NS parse_token shape)" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1_900_000_000, nonce: NONCE16)
    data, mac = bin.byteslice(0, bin.bytesize - 32), bin.byteslice(bin.bytesize - 32, 32)
    assert_equal mac, Ztlp::Blake2sHmac.mac(SECRET_RAW, data), "MAC must be HMAC over all preceding bytes"
  end

  test "mint with a different secret produces a different MAC (wrong secret fails verification)" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1_900_000_000, nonce: NONCE16)
    data, mac = bin.byteslice(0, bin.bytesize - 32), bin.byteslice(bin.bytesize - 32, 32)
    refute_equal mac, Ztlp::Blake2sHmac.mac("cd" * 32, data)
  end

  test "mint requires a 64-hex enrollment secret" do
    z = Zone.where(name: "nosecret.test.ztlp").first_or_create!(ns_addr: "127.0.0.1:23096")
    assert_raises(Ztlp::TokenMinter::EnrollmentSecretMissing) do
      Ztlp::TokenMinter.mint(z, expires_at: 1_900_000_000)
    end
  ensure
    Zone.where(name: "nosecret.test.ztlp").delete_all
  end

  # ---------------------------------------------------------------- uri

  # The Rust CLI reads the URI via std::str::trim (Rust chars, Unicode-aware)
  # before base64url-decoding (proto/src/enrollment.rs from_base64url) —
  # ASCII-only trimming here would mangle a non-ASCII URI prefix the Rust
  # side would have accepted. Match the consumer, not a guess.
  test "to_uri is ztlp://enroll/<base64url> and round-trips the binary" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1_900_000_000, nonce: NONCE16)
    uri = Ztlp::TokenMinter.to_uri(bin)
    assert uri.start_with?("ztlp://enroll/"), uri
    b64 = uri.delete_prefix("ztlp://enroll/").strip
    assert b64.match?(/\A[A-Za-z0-9_-]*\z/), "base64url alphabet only (no - + or = padding)"
    assert_equal bin, Ztlp::TokenMinter.from_uri(uri), "from_uri round-trips the exact binary"
  end

  test "from_uri accepts a bare base64url string and rejects garbage" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1_900_000_000, nonce: NONCE16)
    b64 = Ztlp::TokenMinter.to_uri(bin).delete_prefix("ztlp://enroll/").strip
    assert_equal bin, Ztlp::TokenMinter.from_uri(b64)
    assert_raises(ArgumentError) { Ztlp::TokenMinter.from_uri("!!!notbase64###") }
  end
end
