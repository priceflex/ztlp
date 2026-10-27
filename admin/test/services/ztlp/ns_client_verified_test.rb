# frozen_string_literal: true

require "test_helper"

# NsClient.query_verified: accept an NS answer only if the name server we trust signed it
# (proto/src/ns_verify.rs is the contract). A UDP reply is otherwise unauthenticated: anyone on the
# path could inject a KEY record and have the panel list an attacker's key as a user's device.
class NsClientVerifiedTest < ActiveSupport::TestCase
  class FakeSocket
    def initialize(reply) = @reply = reply
    def send(*) = nil
    def recvfrom(*) = [ @reply, nil ]
    def close = nil
  end

  NS_SEED, NS_PUB = Ztlp::Ed25519.generate
  OTHER_SEED, OTHER_PUB = Ztlp::Ed25519.generate
  NAME = "heidy-mba.chooseforce.ztlp"

  def canonical(name: NAME, type: 0x01, data: { "node_id" => "3f" * 16, "public_key" => "0e" * 32 },
                created_at: Time.now.to_i - 60, ttl: 31_536_000, serial: 7)
    cbor = Ztlp::Cbor.encode(data)
    [ type, name.bytesize ].pack("C n") + name.b + [ cbor.bytesize ].pack("N") + cbor +
      [ created_at, ttl, serial ].pack("Q> N Q>")
  end

  def reply(canon, seed: NS_SEED, pub: NS_PUB, sig: nil)
    sig ||= [ Ztlp::Ed25519.sign(seed_hex: seed, message: canon) ].pack("H*")
    "\x02".b + canon + [ sig.bytesize ].pack("n") + sig + [ 32 ].pack("n") + [ pub ].pack("H*")
  end

  def ask(bytes, name: NAME, type: "key", keys: [ NS_PUB ])
    Ztlp::NsClient.query_verified("127.0.0.1:1", 1, name: name, type: type, trusted_keys: keys,
                                                    socket: FakeSocket.new(bytes))
  end

  test "a record signed by the trusted NS key is returned with its data" do
    rec = ask(reply(canonical))
    assert_equal NAME, rec[:name]
    assert_equal "key", rec[:type]
    assert_equal "0e" * 32, rec[:data]["public_key"]
    assert_equal NS_PUB, rec[:signer]
  end

  test "trusted keys are matched case-insensitively" do
    assert ask(reply(canonical), keys: [ NS_PUB.upcase ])
  end

  test "a record signed by any other key is refused" do
    err = assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(canonical, seed: OTHER_SEED, pub: OTHER_PUB)) }
    assert_match(/untrusted/i, err.message)
  end

  test "a forged signature under the trusted key is refused" do
    bad = reply(canonical, sig: "\x00".b * 64)
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(bad) }
  end

  test "a record whose bytes were altered after signing is refused" do
    canon = canonical
    good = reply(canon)
    tampered = good.sub("0e" * 32, "aa" * 32)
    refute_equal good, tampered
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(tampered) }
  end

  test "an expired record is refused" do
    old = reply(canonical(created_at: Time.now.to_i - 100, ttl: 10))
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(old) }
  end

  test "a valid record for a different name or type is refused" do
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(canonical(name: "other.chooseforce.ztlp"))) }
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(canonical(type: 0x02))) }
  end

  test "a record the NS stored from an unauthenticated registration is refused" do
    rec = canonical(data: { "node_id" => "3f" * 16, "public_key" => "0e" * 32, "registered_unsigned" => true })
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(rec)) }
  end

  test "no trusted key at all is refused before anything is sent" do
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(canonical), keys: []) }
  end

  test "not found and revoked answers pass through" do
    assert_equal :not_found, ask("\x03".b)
    assert_equal :revoked, ask("\x04".b)
  end

  test "trailing bytes after the signer key are refused" do
    assert_raises(Ztlp::NsClient::UntrustedAnswer) { ask(reply(canonical) + "x") }
  end
end
