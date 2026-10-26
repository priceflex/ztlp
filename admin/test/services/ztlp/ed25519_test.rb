# frozen_string_literal: true

require "test_helper"

module Ztlp
  class Ed25519Test < ActiveSupport::TestCase
    setup do
      @seed, @pub = Ztlp::Ed25519.generate
    end

    test "generate yields 32-byte hex keys" do
      assert_match Ztlp::Ed25519::HEX32, @seed
      assert_match Ztlp::Ed25519::HEX32, @pub
    end

    test "round trip sign/verify" do
      msg = "hello"
      sig = Ztlp::Ed25519.sign(seed_hex: @seed, message: msg)
      assert Ztlp::Ed25519.verify(pubkey_hex: @pub, message: msg, signature_hex: sig)
      refute Ztlp::Ed25519.verify(pubkey_hex: @pub, message: "hellp", signature_hex: sig)
    end

    test "verify never raises on garbage" do
      refute Ztlp::Ed25519.verify(pubkey_hex: "zz", message: "m", signature_hex: "00")
      refute Ztlp::Ed25519.verify(pubkey_hex: nil, message: "m", signature_hex: nil)
      refute Ztlp::Ed25519.verify(pubkey_hex: "0" * 64, message: "m", signature_hex: "0" * 128)
    end

    test "canonical json sorts keys recursively and is whitespace free" do
      j = Ztlp::Ed25519.canonical_json({ "b" => 1, "a" => { "d" => [ 2, { "z" => 1, "y" => 2 } ], "c" => "x" } })
      assert_equal '{"a":{"c":"x","d":[2,{"y":2,"z":1}]},"b":1}', j
    end

    test "claim message is sha256 of canonical body and verifies" do
      body = { "username" => "steve", "pubkey_hex" => @pub, "timestamp" => 1_791_264_596, "claim_code" => "X" }
      sig = Ztlp::Ed25519.sign(seed_hex: @seed, message: Ztlp::Ed25519.claim_message(body))
      assert Ztlp::Ed25519.verify(pubkey_hex: @pub, message: Ztlp::Ed25519.claim_message(body.to_a.reverse.to_h),
                                  signature_hex: sig)
      tampered = body.merge("username" => "mallory")
      refute Ztlp::Ed25519.verify(pubkey_hex: @pub, message: Ztlp::Ed25519.claim_message(tampered), signature_hex: sig)
    end

    test "login message shape" do
      assert_equal "ztlp-admin-login\nadmin.trs.ztlp\nabc", Ztlp::Ed25519.login_message("admin.trs.ztlp", "abc")
    end
  end
end
