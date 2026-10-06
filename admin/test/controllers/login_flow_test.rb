# frozen_string_literal: true

require "test_helper"

class LoginFlowTest < ActionDispatch::IntegrationTest
  setup { @admin, @seed = make_admin }

  test "challenge-response login via JSON then browser" do
    sign_in_as(@admin, @seed)
    assert_select "h1", "Dashboard"
    assert AuditLog.exists?(action: "auth.login", admin_id: @admin.id)
    assert @admin.reload.last_login_at.present?
  end

  test "unknown key still gets a nonce-shaped reply" do
    post auth_challenge_path, params: { pubkey_hex: "ab" * 32 }, as: :json
    assert_response :success
    assert_equal 64, response.parsed_body["nonce"].size
  end

  test "bad signature is 401 and audited" do
    post auth_challenge_path, params: { pubkey_hex: @admin.pubkey_hex }, as: :json
    nonce = response.parsed_body["nonce"]
    post auth_verify_path, params: { pubkey_hex: @admin.pubkey_hex, nonce: nonce, signature: "00" * 64 }, as: :json
    assert_response :unauthorized
    assert AuditLog.exists?(action: "auth.login_failed")
  end

  test "nonce is single use and session link is single use" do
    post auth_challenge_path, params: { pubkey_hex: @admin.pubkey_hex }, as: :json
    nonce = response.parsed_body["nonce"]
    sig = Ztlp::Ed25519.sign(seed_hex: @seed, message: Ztlp::Ed25519.login_message(host, nonce))
    post auth_verify_path, params: { pubkey_hex: @admin.pubkey_hex, nonce: nonce, signature: sig }, as: :json
    url = response.parsed_body["login_url"]
    post auth_verify_path, params: { pubkey_hex: @admin.pubkey_hex, nonce: nonce, signature: sig }, as: :json
    assert_response :unauthorized
    get url
    assert_redirected_to root_path
    reset!
    get url
    assert_redirected_to login_path
  end

  test "disabled admin cannot log in" do
    @admin.update!(disabled_at: Time.current)
    post auth_challenge_path, params: { pubkey_hex: @admin.pubkey_hex }, as: :json
    nonce = response.parsed_body["nonce"]
    sig = Ztlp::Ed25519.sign(seed_hex: @seed, message: Ztlp::Ed25519.login_message(host, nonce))
    post auth_verify_path, params: { pubkey_hex: @admin.pubkey_hex, nonce: nonce, signature: sig }, as: :json
    assert_response :unauthorized
  end

  test "signed-out user is redirected to login" do
    get root_path
    assert_redirected_to login_path
  end
end
