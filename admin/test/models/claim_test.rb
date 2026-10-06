# frozen_string_literal: true

require "test_helper"

class ClaimTest < ActiveSupport::TestCase
  test "needed only when no admin exists" do
    assert Claim.needed?
    make_admin
    refute Claim.needed?
  end

  test "issue stores digest only and validates with normalisation" do
    code = Claim.issue!
    assert_match(/\A[A-Z2-7]{4}(-[A-Z2-7]{1,4})+\z/, code)
    refute_equal code, SystemSetting[Claim::KEY_DIGEST]
    assert Claim.code_valid?(code)
    assert Claim.code_valid?(code.downcase.delete("-"))
    refute Claim.code_valid?(code.tr("A-Z2-7", "B-Z2-7A"))
  end

  test "ensure_code is idempotent while live" do
    first = Claim.issue!
    assert_nil Claim.ensure_code!
    assert Claim.code_valid?(first)
  end

  test "expired code is rejected" do
    code = Claim.issue!
    SystemSetting[Claim::KEY_EXPIRES] = 1.minute.ago.iso8601
    refute Claim.code_valid?(code)
  end

  test "perform creates super_admin, burns the code, audits" do
    code = Claim.issue!
    _seed, pub = Ztlp::Ed25519.generate
    admin = Claim.perform!({ claim_code: code, username: "Steve", display_name: "Steven Price", email: "s@example.com",
                             pubkey_hex: pub.upcase })
    assert_equal "super_admin", admin.role
    assert_equal "steve", admin.username
    assert_equal pub, admin.pubkey_hex
    assert_nil SystemSetting[Claim::KEY_DIGEST]
    assert AuditLog.exists?(action: "system.claimed", admin_id: admin.id)
    assert_raises(Claim::Error) { Claim.perform!({ claim_code: code, username: "x", display_name: "x", pubkey_hex: pub }) }
  end

  test "perform with signature verifies canonical body" do
    code = Claim.issue!
    seed, pub = Ztlp::Ed25519.generate
    ts = Time.current.to_i
    body = { "claim_code" => code, "username" => "steve", "display_name" => "Steven", "email" => "",
             "pubkey_hex" => pub, "timestamp" => ts }
    sig = Ztlp::Ed25519.sign(seed_hex: seed, message: Ztlp::Ed25519.claim_message(body))
    bad = { claim_code: code, username: "steve", display_name: "Steven", email: "", pubkey_hex: pub, timestamp: ts, signature: sig.sub(/.\z/) do |c|
      c == "0" ? "1" : "0"
    end }
    assert_raises(Claim::Error) { Claim.perform!(bad) }
    stale = bad.merge(signature: sig, timestamp: ts - 1000)
    assert_raises(Claim::Error) { Claim.perform!(stale) }
    good = bad.merge(signature: sig)
    assert Claim.perform!(good).persisted?
  end

  test "bad pubkey rejected" do
    code = Claim.issue!
    assert_raises(Claim::Error) { Claim.perform!({ claim_code: code, username: "s", display_name: "s", pubkey_hex: "nope" }) }
  end
end
