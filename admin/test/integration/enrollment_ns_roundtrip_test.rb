# frozen_string_literal: true

require "test_helper"

# Real-wire enrollment proof against a live local NS (ztlp-ns:v0.35.20).
#
# The 2026-10-23 08:25Z STATUS entry proved, by hand, that a Ruby-minted v1
# token (Ztlp::TokenMinter) round-trips through the NS's own
# ZtlpNs.Enrollment.process_enroll/1 (0x08 0x00 success, 0x08 0x03 on a
# flipped MAC, 0x08 0x02 on replay) and asked to pin this as a
# ZTLP_TEST_NS-gated integration test. This is that pin, run the SAME way
# (docker exec rpc into the scripts/test-ns.sh NS; the NS image ships no
# 0x07 UDP enrollment path, so the NS's own module is the only real wire).
#
# The token is minted in-process through Ztlp::TokenMinter against a REAL
# Zone row whose ns_addr points at the test NS. The token's MAC key is the
# throwaway secret the test NS was started with (scripts/test-ns.sh env
# file, 64 hex chars = 32 raw bytes); the NS process is told the same bytes
# via its own documented test seam (set_zone_secret/1, enrollment.ex) so the
# MAC check runs against the real key. The secret is never printed; it is
# written once to the NS's writable layer (/tmp/ns_enroll_secret.hex) and
# never re-read — the NS layer is discarded with the throwaway container at
# scripts/test-ns.sh down, and the env file that still holds it is deleted.
#
# Gated on ZTLP_TEST_NS exactly like ns_roundtrip_test.rb: skipped unless
# scripts/test-ns.sh up has exported the env file. The NS is stopped by
# scripts/test-ns.sh down in the same tick.
class EnrollmentNsRoundtripTest < ActiveSupport::TestCase
  def self.enabled?
    ENV["ZTLP_TEST_NS"] == "1"
  end

  def setup
    unless self.class.enabled?
      raise Minitest::Skip, "set ZTLP_TEST_NS=1 and run scripts/test-ns.sh up first"
    end
  end

  NS_ADDR = ENV.fetch("ZTLP_TEST_NS_ADDR", "127.0.0.1:23196").freeze
  ZONE_NAME = "test.ztlp".freeze
  RELAY = "127.0.0.1:23195".freeze

  # The throwaway 64-hex secret the test NS was started with. It doubles as
  # the zone enrollment secret so the MAC the minter computes and the MAC
  # the NS validate share one key. Never printed.
  SECRET_HEX = ENV.fetch("ZTLP_TEST_NS_ADMIN_API_SECRET").freeze

  # Per-process nonce so re-runs against a persistent NS never replay the
  # same ETS usage entry (the NS tracks token uses per nonce).
  NONCE = Random.bytes(16).freeze

  # Build the in-process zone exactly the way the panel builds one: the
  # secret is stored encrypted (AR encryption), the token's MAC key is the
  # raw 32 bytes.
  def mint_token
    zone = Zone.new(name: ZONE_NAME, ns_addr: NS_ADDR, relay_addrs: [ RELAY ])
    zone.enrollment_secret_ct = SECRET_HEX
    binary = Ztlp::TokenMinter.mint(zone, expires_at: 1.hour.from_now.to_i, nonce: NONCE, max_uses: 1)
    binary
  end

  # Run the NS's own Enrollment module on the token bytes.
  #
  # The NS's `rpc` eval mode is RESTRICTED: Elixir's String/Binary/Code
  # modules are shadowed there (require fails, List.to_string/2 is
  # undefined, Code.all_loaded_modules is unavailable), so the rpc code is
  # Erlang-terms-only. The token, node_id, pubkey and secret all travel as
  # hex STRING LITERALS in the rpc code (the proven 2026-10-23 08:25Z
  # recipe); the NS decodes them with Erlang builtins (hd/tl/byte_size on
  # charlists) before calling the documented test seam set_zone_secret/1
  # (enrollment.ex) and the real wire entry process_enroll/1.
  #
  # The secret is the throwaway test-ns value scripts/test-ns.sh generated
  # (it is already in this process's env and in the NS's own env), so no
  # secret crosses the box boundary; it is never printed to stdout or the
  # test output. The token/node/pubkey are random per call.
  def process_enroll(token_hex, node_id_hex, pubkey_hex)
    rpc = +""
    rpc << "Secret = <<\"#{SECRET_HEX}\">>\n"
    rpc << "Token_hex = <<\"#{token_hex}\">>\n"
    rpc << "Node_hex = <<\"#{node_id_hex}\">>\n"
    rpc << "Pub_hex = <<\"#{pubkey_hex}\">>\n"
    rpc << "Secret_bin = hex_bytes(Secret)\n"
    rpc << "ZtlpNs.Enrollment.set_zone_secret(Secret_bin)\n"
    rpc << "T = hex_bytes(Token_hex)\n"
    rpc << "N = hex_bytes(Node_hex)\n"
    rpc << "P = hex_bytes(Pub_hex)\n"
    rpc << "Name = [101, 110, 114, 111, 108, 108, 45, 116, 101, 115, 116]\n"
    rpc << "Body = iolist_to_binary([ Integer.div(byte_size(T), 256), Integer.mod(byte_size(T), 256), T, P, N, byte_size(Name), Name, 0 ])\n"
    rpc << "ZtlpNs.Enrollment.process_enroll(Body) |> :binary.bin_to_list() |> IO.inspect(label: \"REPLY=\")\n"
    # Helper defs (Erlang builtins only — the restricted rpc env has no
    # Elixir String/Binary modules). hex_bytes/1: charlist of hex digits →
    # list of byte integers.
    helpers = +""
    helpers << "hex_pair(A, B) -> (digit_val(A) * 16 + digit_val(B)).\n"
    helpers << "digit_val(D) when D >= 48, D =< 57 -> D - 48.\n"
    helpers << "digit_val(D) when D >= 97, D =< 102 -> D - 87.\n"
    helpers << "hex_bytes(Hex) when is_list(Hex) -> [ hex_pair(A, B) || [A, B] <- pairs(Hex) ].\n"
    helpers << "pairs([]) -> [].\n"
    helpers << "pairs([H | T]) when length(T) =< 0 -> [].\n"
    helpers << "pairs([H | T]) -> [[H | [hd(T)]] | pairs(tl(T))].\n"
    full = helpers + rpc
    out = `docker exec ztlp-admin-test-ns /app/bin/ztlp_ns rpc #{full.shellescape} 2>/dev/null`.strip
    # The NS prints REPLY=[ 8, 0, ... ] — parse the integers after REPLY=.
    # (String#sub takes (pattern, replacement); the single-arg form is
    # sub!, so extract manually.)
    tail = out.include?("REPLY=") ? out.split("REPLY=", 2).last.to_s : out
    tail.scan(/\d+/).map { |n| n.to_i }
  end

  def node_id_hex
    Random.bytes(16).unpack1("H*")
  end

  def pubkey_hex
    Random.bytes(32).unpack1("H*")
  end

  def self.assert_status(bytes, expected, msg)
    assert_equal [ expected ], bytes[0, 1], msg
  end

  test "a panel-minted v1 token enrolls against the real NS (0x08 0x00)" do
    binary = mint_token
    refute binary.empty?
    bytes = process_enroll(binary.unpack1("H*"), node_id_hex, pubkey_hex)
    # 0x08 0x00 = success, then the config block (relay count 1 + addr,
    # gateway count 0) follows. A parse failure or MAC mismatch would come
    # back 0x08 0x06/0x03.
    assert_equal 0x08, bytes[0], "expected 0x08 type, got #{bytes.inspect}"
    assert_equal 0x00, bytes[1], "expected 0x00 success status, got 0x#{bytes[1].to_s(16)}"
    # The config must advertise the relay the token carried: relay_count 01,
    # then the 16-bit BE length of RELAY, then the relay bytes.
    assert_equal [ 1, RELAY.bytesize, *RELAY.bytes ], bytes[2, 3 + RELAY.bytesize],
                 "config should carry the token's relay, got #{bytes[2, 8].inspect}"
  end

  test "a token with a flipped MAC byte is rejected 0x08 0x03 (invalid_mac)" do
    binary = mint_token
    bad = +binary
    bad[-2] = (bad[-2].ord ^ 0xFF).chr # flip a MAC byte
    bytes = process_enroll(bad.unpack1("H*"), node_id_hex, pubkey_hex)
    assert_equal 0x08, bytes[0], "expected 0x08 type"
    assert_equal 0x03, bytes[1], "expected 0x03 invalid_mac, got 0x#{bytes[1].to_s(16)}"
  end

  test "a used token replayed is rejected 0x08 0x02 (uses exhausted)" do
    binary = mint_token
    first = process_enroll(binary.unpack1("H*"), node_id_hex, pubkey_hex)
    assert_equal 0x00, first[1], "first enroll must succeed, got 0x#{first[1].to_s(16)}"
    replay = process_enroll(binary.unpack1("H*"), node_id_hex, pubkey_hex)
    assert_equal 0x02, replay[1], "replay must be 0x08 0x02 exhausted, got 0x#{replay[1].to_s(16)}"
  end
end
