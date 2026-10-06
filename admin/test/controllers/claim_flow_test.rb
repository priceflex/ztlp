# frozen_string_literal: true

require "test_helper"

class ClaimFlowTest < ActionDispatch::IntegrationTest
  test "unclaimed panel redirects everything to /claim" do
    get root_path
    assert_redirected_to claim_path
    get login_path
    assert_redirected_to claim_path
    get up_path
    assert_response :success
  end

  test "claim page shows and accepts the browser form" do
    get claim_path
    assert_response :success
    code = Claim.issue!
    _seed, pub = Ztlp::Ed25519.generate
    post claim_path, params: { claim: { claim_code: code, username: "steve", display_name: "Steven", pubkey_hex: pub } }
    assert_redirected_to root_path
    follow_redirect!
    assert_select "h1", "Dashboard"
    assert_equal 1, Admin.count
    get claim_path
    assert_redirected_to root_path
  end

  test "wrong code is 422 and audited" do
    Claim.issue!
    _seed, pub = Ztlp::Ed25519.generate
    post claim_path,
         params: { claim: { claim_code: "AAAA-AAAA", username: "steve", display_name: "Steven", pubkey_hex: pub } }
    assert_response :unprocessable_entity
    assert AuditLog.exists?(action: "system.claim_failed")
    assert_equal 0, Admin.count
  end
end
