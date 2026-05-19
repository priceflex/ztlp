# frozen_string_literal: true

require "test_helper"
require "ztlp/header_verifier"

class AuthenticationTest < ActionDispatch::IntegrationTest
  GATEWAY_SECRET = "auth-test-shared-secret-XYZ"

  setup do
    @admin = admin_users(:super_admin)
  end

  # --- Unauthenticated access redirects ---

  test "unauthenticated access to root redirects to login" do
    get root_path
    assert_redirected_to login_path
  end

  test "unauthenticated access to networks redirects to login" do
    get networks_path
    assert_redirected_to login_path
  end

  test "unauthenticated access to deployments redirects to login" do
    get deployments_path
    assert_redirected_to login_path
  end

  test "unauthenticated access to audit logs redirects to login" do
    get audit_logs_path
    assert_redirected_to login_path
  end

  test "unauthenticated access to alerts redirects to login" do
    get alerts_path
    assert_redirected_to login_path
  end

  # --- Authenticated access works ---

  test "authenticated access to root works" do
    sign_in(@admin)
    get root_path
    assert_response :success
  end

  test "trusted gateway header with valid HMAC auto signs in without password" do
    headers = signed_gateway_headers(email: @admin.email)
    with_env(
      "ZTLP_TRUST_GATEWAY_AUTH" => "true",
      "ZTLP_GATEWAY_HEADER_SECRET" => GATEWAY_SECRET
    ) do
      get root_path, headers: headers
    end

    assert_response :success
  end

  test "trusted gateway header with corrupted signature redirects to login" do
    headers = signed_gateway_headers(email: @admin.email)
    headers["X-ZTLP-Signature"] = "0" * headers["X-ZTLP-Signature"].length

    with_env(
      "ZTLP_TRUST_GATEWAY_AUTH" => "true",
      "ZTLP_GATEWAY_HEADER_SECRET" => GATEWAY_SECRET
    ) do
      get root_path, headers: headers
    end

    assert_redirected_to login_path
  end

  test "trusted gateway header with no signature redirects to login" do
    headers = signed_gateway_headers(email: @admin.email)
    headers.delete("X-ZTLP-Signature")

    with_env(
      "ZTLP_TRUST_GATEWAY_AUTH" => "true",
      "ZTLP_GATEWAY_HEADER_SECRET" => GATEWAY_SECRET
    ) do
      get root_path, headers: headers
    end

    assert_redirected_to login_path
  end

  test "trusted gateway header redirects to login when server secret is unset" do
    headers = signed_gateway_headers(email: @admin.email)

    with_env(
      "ZTLP_TRUST_GATEWAY_AUTH" => "true",
      "ZTLP_GATEWAY_HEADER_SECRET" => nil
    ) do
      get root_path, headers: headers
    end

    assert_redirected_to login_path
  end

  test "trusted gateway header is ignored unless explicitly enabled" do
    headers = signed_gateway_headers(email: @admin.email)

    with_env(
      "ZTLP_TRUST_GATEWAY_AUTH" => nil,
      "ZTLP_GATEWAY_HEADER_SECRET" => GATEWAY_SECRET
    ) do
      get root_path, headers: headers
    end

    assert_redirected_to login_path
  end

  test "authenticated access to networks works" do
    sign_in(@admin)
    get networks_path
    assert_response :success
  end

  # --- Skip-auth endpoints accessible without login ---

  test "health check endpoint accessible without login" do
    get rails_health_check_path
    assert_response :success
  end

  test "API enrollment confirm accessible without login" do
    # API controllers inherit from ActionController::API, not ApplicationController
    post api_enrollment_confirm_path, params: { token_id: "nonexistent" }
    assert_response :not_found # Token not found, but NOT redirected to login
  end

  test "IdP enrollment page accessible without login" do
    network = networks(:office)
    get network_enroll_path(network)
    # Should either render or redirect to enrollment page, NOT to login
    assert_not_equal login_path, response.location
  end

  test "OmniAuth failure accessible without login" do
    get "/auth/failure", params: { message: "invalid_credentials" }
    # Should redirect somewhere, but NOT to login (it's a public endpoint)
    assert_response :redirect
    assert_not_equal login_url, response.location
  end

  # --- Intended URL redirect ---

  test "stores intended URL and redirects after login" do
    get networks_path
    assert_redirected_to login_path
    post login_path, params: { email: @admin.email, password: "password123" }
    assert_redirected_to networks_path
  end

  # --- Helper methods ---

  test "admin_signed_in? is false when not signed in" do
    get login_path
    assert_response :success
  end

  private

  def sign_in(admin)
    post login_path, params: { email: admin.email, password: "password123" }
  end

  # Build a valid signed X-ZTLP-* header set. Secret defaults to GATEWAY_SECRET.
  def signed_gateway_headers(email:, secret: GATEWAY_SECRET, timestamp: Time.now.utc.iso8601)
    base = {
      "X-ZTLP-Authenticated" => "1",
      "X-ZTLP-Admin-Email" => email,
      "X-ZTLP-Timestamp" => timestamp
    }
    canonical = Ztlp::HeaderVerifier.canonical_string(base.to_a)
    sig = Ztlp::HeaderVerifier.hmac_hex(canonical, secret)
    base.merge("X-ZTLP-Signature" => sig)
  end

  def with_env(overrides)
    old_values = overrides.transform_values { |_value| nil }
    overrides.each_key { |key| old_values[key] = ENV[key] }
    overrides.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
    yield
  ensure
    old_values.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end
