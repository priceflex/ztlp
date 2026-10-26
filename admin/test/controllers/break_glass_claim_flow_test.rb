# frozen_string_literal: true

require "test_helper"

# Break-glass end to end over HTTP (review of 11c): `admin:reset_claim` issues a FORCED code; the
# /claim page must then accept it even though administrators exist. The "force" decision is
# server-side state set by the rake task -- never a request parameter.
class BreakGlassClaimFlowTest < ActionDispatch::IntegrationTest
  setup do
    @old, = make_admin(role: "super_admin", username: "steve")
  end

  def claim!(code, username: "rescue", extra: {})
    _seed, pub = Ztlp::Ed25519.generate
    post claim_path, params: { claim: { claim_code: code, username: username, display_name: "Rescue",
                                        pubkey_hex: pub } }.merge(extra)
  end

  test "a forced code is claimable over HTTP while admins exist; creates an ADDITIONAL super_admin" do
    code = Claim.issue!(force: true)
    get claim_path
    assert_response :success
    claim!(code)
    assert_redirected_to root_path
    assert_equal 2, Admin.count
    assert_equal "super_admin", Admin.find_by(username: "rescue").role
    assert Admin.exists?(id: @old.id), "existing administrators are not touched"
    assert AuditLog.exists?(action: "system.reset_claim", admin_id: Admin.find_by(username: "rescue").id)
  end

  test "the forced code is single-use: the panel closes again after the break-glass claim" do
    code = Claim.issue!(force: true)
    claim!(code)
    delete logout_path if respond_to?(:logout_path)
    reset!
    get claim_path
    assert_redirected_to root_path
    claim!(code, username: "second")
    assert_redirected_to root_path
    assert_nil Admin.find_by(username: "second")
  end

  test "without a forced code, /claim stays closed once claimed (and a client 'force' param does nothing)" do
    code = Claim.issue! # a normal (non-forced) code lying around must not open the door
    get claim_path
    assert_redirected_to root_path
    claim!(code, extra: { force: "1", claim: nil }.compact)
    claim!(code)
    assert_redirected_to root_path
    assert_equal 1, Admin.count
  end

  test "an expired forced code does not open /claim" do
    Claim.issue!(force: true)
    travel 25.hours do
      get claim_path
      assert_redirected_to root_path
    end
  end
end
