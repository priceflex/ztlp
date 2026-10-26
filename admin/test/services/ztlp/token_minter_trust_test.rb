# frozen_string_literal: true

require "test_helper"

# Complete enrollment tokens (docs/admin-panel/PLAN-enrollment-token-trust.md): the relay
# registration secret (flag 0x08) and the home name server's public key (flag 0x10) ride INSIDE the
# token, covered by the MAC, exactly as proto/src/enrollment.rs serializes them.
class TokenMinterTrustTest < ActiveSupport::TestCase
  # The cross-language vector the Rust and NS test suites share. A format change on either side
  # changes this file, so the panel test fails with them instead of minting tokens they reject.
  VECTOR_PATH = Rails.root.join("..", "proto", "tests", "fixtures", "enrollment_token_all_flags.hex")

  def zone(name: "trs.ztlp", ns: "127.0.0.1:23096", relays: [ "127.0.0.1:23095" ], secret_hex: "07" * 32)
    Zone.new(name: name, ns_addr: ns, relay_addrs: relays, enrollment_secret_ct: secret_hex)
  end

  test "a token with every flag is byte-identical to the shared Rust/NS vector" do
    skip "proto fixture not present (admin-only checkout)" unless File.exist?(VECTOR_PATH)

    bin = Ztlp::TokenMinter.mint(zone, expires_at: 0, max_uses: 0, nonce: "\x5a".b * 16,
                                       gateway_addr: "127.0.0.1:23097",
                                       callback_url: "https://example.invalid/cb",
                                       relay_secret: "cd" * 32, ns_key_hex: "42" * 32)
    assert_equal File.read(VECTOR_PATH).strip, bin.unpack1("H*")
    assert_equal 0x01 | 0x02 | 0x08 | 0x10, bin.getbyte(1)
  end

  test "without relay secret and NS key the token is byte-identical to the old format" do
    args = { expires_at: 1_800_000_000, nonce: "\x01".b * 16, callback_url: "https://p.example/cb" }
    old = Ztlp::TokenMinter.mint(zone, **args)
    assert_equal old, Ztlp::TokenMinter.mint(zone, **args, relay_secret: nil, ns_key_hex: nil)
    assert_equal old, Ztlp::TokenMinter.mint(zone, **args, relay_secret: "", ns_key_hex: " ")
    assert_equal 0x02, old.getbyte(1)
  end

  test "parse reads back every field and verifies the MAC" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1_800_000_000, callback_url: "https://p.example/cb",
                                       relay_secret: "Rk3-relay-secret", ns_key_hex: "AB" * 32)
    t = Ztlp::TokenMinter.parse(bin)
    assert_equal "trs.ztlp", t[:zone]
    assert_equal "127.0.0.1:23096", t[:ns_addr]
    assert_equal [ "127.0.0.1:23095" ], t[:relay_addrs]
    assert_equal "https://p.example/cb", t[:callback_url]
    assert_equal "Rk3-relay-secret", t[:relay_secret]
    assert_equal "ab" * 32, t[:ns_key_hex], "the key is normalized to lowercase hex"
    assert_equal 1, t[:max_uses]
    assert_equal 1_800_000_000, t[:expires_at]
    assert Ztlp::TokenMinter.valid_mac?(bin, [ "07" * 32 ].pack("H*"))
    refute Ztlp::TokenMinter.valid_mac?(bin, [ "08" * 32 ].pack("H*"))
  end

  test "the relay secret is trimmed like the Rust minter does" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1, relay_secret: "  s3cret\n")
    assert_equal "s3cret", Ztlp::TokenMinter.parse(bin)[:relay_secret]
  end

  test "a relay secret longer than the client's 256-byte cap is refused" do
    assert_raises(Ztlp::TokenMinter::InvalidField) do
      Ztlp::TokenMinter.mint(zone, expires_at: 1, relay_secret: "x" * 257)
    end
    assert Ztlp::TokenMinter.mint(zone, expires_at: 1, relay_secret: "x" * 256)
  end

  test "an NS key that is not 64 hex characters is refused" do
    [ "42" * 31, "zz" * 32, "42" * 33, "0x" + "42" * 31 ].each do |bad|
      assert_raises(Ztlp::TokenMinter::InvalidField, bad) do
        Ztlp::TokenMinter.mint(zone, expires_at: 1, ns_key_hex: bad)
      end
    end
  end

  test "flags the Rust client does not know are never emitted" do
    bin = Ztlp::TokenMinter.mint(zone, expires_at: 1, gateway_addr: "1.2.3.4:23097", callback_url: "https://x/cb",
                                       relay_secret: "r", ns_key_hex: "11" * 32)
    assert_equal 0, bin.getbyte(1) & ~(0x01 | 0x02 | 0x08 | 0x10) & 0xff
  end
end
