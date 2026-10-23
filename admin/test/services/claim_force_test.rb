# frozen_string_literal: true

require "test_helper"

# Slice 11c: the break-glass force path (spec §4.1 step 6; BUILD_LOOP Slice 11).
# admin:reset_claim -> Claim.issue!(force:) + a Claim.perform! that, when admins
# already exist, creates an ADDITIONAL super_admin instead of failing.
class ClaimForceTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.create!(name: "trs.ztlp", ns_addr: "127.0.0.1:9103")
    make_admin
  end

  def perform_force(pub)
    Claim.perform!({ claim_code: claim_code, username: "roberta", display_name: "Roberta Break-glass",
                     email: "", pubkey_hex: pub }, force: true)
  end

  def claim_code = Claim.issue!(force: true)

  test "issue!(force: true) works while an admin exists and the code is valid" do
    refute Claim.needed?
    code = claim_code
    assert_match(/\A[A-Z2-7]{4}(-[A-Z2-7]{1,4})+\z/, code)
    assert Claim.code_valid?(code)
  end

  test "perform!(force:) creates an additional super_admin alongside the existing admin" do
    _seed, pub = Ztlp::Ed25519.generate
    admin = perform_force(pub)

    assert_equal "super_admin", admin.role
    assert_equal "roberta", admin.username
    assert_equal pub, admin.pubkey_hex
    assert_equal 2, Admin.count
    original = Admin.find_by!(username: "steve")
    assert_equal "super_admin", original.role
    refute original.disabled?
    assert_nil SystemSetting[Claim::KEY_DIGEST]
  end

  test "force claim audits system.reset_claim" do
    _seed, pub = Ztlp::Ed25519.generate
    admin = perform_force(pub)
    assert AuditLog.exists?(action: "system.reset_claim")
  end

  test "perform! WITHOUT force still refuses once an admin exists" do
    _seed, pub = Ztlp::Ed25519.generate
    assert_raises(Claim::Error) do
      Claim.perform!({ claim_code: claim_code, username: "x", display_name: "x",
                       email: "", pubkey_hex: pub })
    end
    assert_equal 1, Admin.count
  end

  test "force claim creates the directory user, link and admin group membership" do
    _seed, pub = Ztlp::Ed25519.generate
    admin = perform_force(pub)

    user = User.find_by!(username: "roberta")
    assert_equal "roberta.users.trs.ztlp", user.ns_name
    assert_equal "admin", user.role
    assert_equal "active", user.status
    assert_equal user.id, admin.reload.user_id
    assert GroupMembership.exists?(group: Group.find_by!(name: "admins"), user_id: user.id)
  end

  test "force claim with a valid signature also verifies" do
    _seed, pub = Ztlp::Ed25519.generate
    code = claim_code
    ts = Time.current.to_i
    body = { "claim_code" => code, "username" => "rob", "display_name" => "Rob", "email" => "",
             "pubkey_hex" => pub, "timestamp" => ts }
    sig = Ztlp::Ed25519.sign(seed_hex: _seed, message: Ztlp::Ed25519.claim_message(body))
    admin = Claim.perform!({ claim_code: code, username: "rob", display_name: "Rob", email: "",
                             pubkey_hex: pub, timestamp: ts, signature: sig }, force: true)
    assert_equal "super_admin", admin.role
    # a flipped signature must still be rejected
    _seed2, pub2 = Ztlp::Ed25519.generate
    body2 = { "claim_code" => claim_code, "username" => "eve", "display_name" => "Eve", "email" => "",
              "pubkey_hex" => pub2, "timestamp" => Time.current.to_i }
    bad_sig = Ztlp::Ed25519.sign(seed_hex: _seed2, message: Ztlp::Ed25519.claim_message(body2))
    last = bad_sig[-1]
    bad_sig = bad_sig[0..-2] + (last == "0" ? "1" : "0")
    assert_raises(Claim::Error) do
      Claim.perform!({ claim_code: claim_code, username: "eve", display_name: "Eve", email: "",
                       pubkey_hex: pub2, timestamp: body2["timestamp"], signature: bad_sig },
                     force: true)
    end
  end
end
