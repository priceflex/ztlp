# frozen_string_literal: true

require "test_helper"
require "shellwords"

# A panel-minted v1 enrollment token, verified by the REAL name server's own
# `ZtlpNs.Enrollment.process_enroll/1` (the code path `ztlp setup --token` hits),
# via `docker exec <test-ns> /app/bin/ztlp_ns rpc '<ELIXIR>'` on the
# scripts/test-ns.sh container. Pins the 2026-10-23 08:25Z hand proof:
#   genuine -> 0x08 0x00 + config; flipped MAC byte -> 0x08 0x03; replay -> 0x08 0x02.
#
# `rpc` evaluates ELIXIR (Base.decode16!, fn ... end, <<x::16>> all work).
# Erlang syntax (Capitalised vars, `name(X) -> ...` clauses) does NOT -- that is
# what made an earlier skeleton of this file look "blocked".
#
# Gated like ns_roundtrip_test.rb: skipped unless ZTLP_TEST_NS=1
# (bash scripts/test-ns.sh up; set -a; . <scratch>/test_ns.env; set +a).
class EnrollmentNsRoundtripTest < ActiveSupport::TestCase
  CONTAINER = "ztlp-admin-test-ns"
  ZONE_NAME = "rt.test.ztlp"
  RELAY = "10.0.0.9:23095"

  setup do
    skip "set ZTLP_TEST_NS=1 and run scripts/test-ns.sh up first" unless ENV["ZTLP_TEST_NS"] == "1"
    # Test-local throwaway enrollment secret, set on the NS by the test itself
    # (ZtlpNs.Enrollment.set_zone_secret/1). No real secret is involved.
    @secret_hex = SecureRandom.hex(32)
  end

  def mint_token
    zone = Zone.new(name: ZONE_NAME, ns_addr: "127.0.0.1:23096")
    zone.enrollment_secret_ct = @secret_hex
    zone.relay_addrs = [ RELAY ]
    Ztlp::TokenMinter.mint(zone, expires_at: 1.hour.from_now, max_uses: 1) # fresh random nonce per mint
  end

  # The NS reply as an Array of byte integers. Packet (enrollment.ex
  # process_enroll): token_len::16, token, pubkey(32), node_id(16), name_len::16, name, 0::16.
  def process_enroll(token, device_label)
    elixir = <<~EX
      ZtlpNs.Enrollment.set_zone_secret(Base.decode16!("#{@secret_hex.upcase}"))
      tok = Base.decode16!("#{token.unpack1('H*').upcase}")
      name = "#{device_label}.#{ZONE_NAME}"
      pkt = <<byte_size(tok)::16, tok::binary, :crypto.strong_rand_bytes(32)::binary,
              :crypto.strong_rand_bytes(16)::binary, byte_size(name)::16, name::binary, 0::16>>
      IO.puts("REPLY=" <> Enum.join(:binary.bin_to_list(ZtlpNs.Enrollment.process_enroll(pkt)), ","))
    EX
    out = `timeout 60 docker exec #{CONTAINER} /app/bin/ztlp_ns rpc #{elixir.shellescape} 2>&1`
    line = out.lines.find { |l| l.start_with?("REPLY=") }
    flunk "no REPLY from the NS rpc: #{out.lines.last(5).join}" if line.nil?
    line.delete_prefix("REPLY=").strip.split(",").map(&:to_i)
  end

  test "a panel-minted v1 token enrolls against the real NS (0x08 0x00) and gets the token's relay back" do
    reply = process_enroll(mint_token, "rt-ok-#{SecureRandom.hex(3)}")
    assert_equal [ 0x08, 0x00 ], reply[0, 2], "reply #{reply.inspect}"
    # config: relay_count::8, relay_len::16 big-endian, relay bytes
    assert_equal [ 1, 0, RELAY.bytesize, *RELAY.bytes ], reply[2, 3 + RELAY.bytesize], "reply #{reply.inspect}"
  end

  test "a token with a flipped MAC byte is rejected 0x08 0x03 (invalid MAC)" do
    bad = mint_token.dup
    bad.setbyte(-1, bad.getbyte(-1) ^ 0x01)
    assert_equal [ 0x08, 0x03 ], process_enroll(bad, "rt-bad-#{SecureRandom.hex(3)}")[0, 2]
  end

  test "a one-use token replayed is rejected 0x08 0x02 (exhausted)" do
    tok = mint_token
    assert_equal [ 0x08, 0x00 ], process_enroll(tok, "rt-a-#{SecureRandom.hex(3)}")[0, 2]
    assert_equal [ 0x08, 0x02 ], process_enroll(tok, "rt-b-#{SecureRandom.hex(3)}")[0, 2]
  end

  # 1d5d4bc8: panel tokens carry FLAG_HAS_CALLBACK (0x02) + callback_url. NS >= v0.35.12 skips it;
  # an older NS would reject the whole token (0x08 0x06). Prove the real NS accepts it.
  test "a token carrying a callback_url still enrolls (0x08 0x00)" do
    zone = Zone.new(name: ZONE_NAME, ns_addr: "127.0.0.1:23096")
    zone.enrollment_secret_ct = @secret_hex
    zone.relay_addrs = [ RELAY ]
    tok = Ztlp::TokenMinter.mint(zone, expires_at: 1.hour.from_now, max_uses: 1,
                                       callback_url: "http://admin.trs.ztlp/api/enrollment/confirm")
    assert_equal [ 0x08, 0x00 ], process_enroll(tok, "rt-cb-#{SecureRandom.hex(3)}")[0, 2]
  end
end
