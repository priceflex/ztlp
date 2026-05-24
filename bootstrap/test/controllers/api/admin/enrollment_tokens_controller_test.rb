# frozen_string_literal: true

require "test_helper"
require "ztlp/header_verifier"

# Integration tests for the Option C gateway-auth enrollment-token API.
#
# This is the alternative to the HMAC `Api::V1::EnrollmentTokensController`
# that works in Launch-provisioned topology where the per-tenant ZTLP
# gateway is started with `--http-inject-headers` and strips inbound
# `X-ZTLP-*` headers (which breaks the HMAC v1 contract). See the file
# header on the controller for the full threat model.
class Api::Admin::EnrollmentTokensControllerTest < ActionDispatch::IntegrationTest
  GATEWAY_SECRET = "gw-auth-shared-secret-for-tests"

  setup do
    @admin   = admin_users(:super_admin)
    @network = networks(:office)
    # Ensure exactly one Network row exists so the single-zone fallback
    # in `resolve_network` deterministically picks `@network`.
    Network.where.not(id: @network.id).destroy_all
  end

  # ── Auth ────────────────────────────────────────────────────────

  test "POST without any gateway-auth headers returns 401 JSON" do
    post "/api/admin/enrollment_tokens",
         params: { computer_name: "alice-laptop" }.to_json,
         headers: { "Content-Type" => "application/json" }

    assert_response :unauthorized
    body = JSON.parse(response.body)
    assert_equal "unauthorized", body["error"]
  end

  test "POST with cookie-session admin (no gateway headers) is still 401" do
    # Even a fully-authenticated dashboard session must NOT satisfy
    # this endpoint — gateway-auth-only by design.
    post login_path, params: { email: @admin.email, password: "password123" }
    follow_redirect! if response.redirect?

    post "/api/admin/enrollment_tokens",
         params: { computer_name: "alice-laptop" }.to_json,
         headers: { "Content-Type" => "application/json" }

    assert_response :unauthorized
    body = JSON.parse(response.body)
    assert_equal "unauthorized", body["error"]
  end

  test "POST with corrupted gateway signature returns 401" do
    headers = signed_gateway_headers(email: @admin.email)
    headers["X-ZTLP-Signature"] = "0" * headers["X-ZTLP-Signature"].length

    with_gateway_env do
      post "/api/admin/enrollment_tokens",
           params: { computer_name: "alice-laptop" }.to_json,
           headers: headers.merge("Content-Type" => "application/json")
    end

    assert_response :unauthorized
  end

  # ── Happy path ─────────────────────────────────────────────────

  test "valid gateway-auth + valid body returns 201 with the documented shape" do
    pre_count = EnrollmentToken.count

    post_gateway_authed(body: { computer_name: "alice-laptop" })

    assert_response :created
    assert_equal pre_count + 1, EnrollmentToken.count

    body = JSON.parse(response.body)
    assert_equal "issued", body["status"]
    assert body["enrollment_token"].start_with?("ztlp://enroll/?")
    assert body["token_id"].present?
    assert body["expiration_datetime"].present?
    assert_kind_of Integer, body["token_lifetime_seconds"]
    assert body["token_lifetime_seconds"] > 23 * 3600
    assert body["token_lifetime_seconds"] <= 24 * 3600
    assert_match(/single use/, body["message"])
  end

  test "max_uses defaults to 1 when omitted; expires_in defaults to 24h" do
    post_gateway_authed(body: { computer_name: "alice-laptop" })
    assert_response :created

    body  = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])
    assert_equal 1, token.max_uses
    assert (token.expires_at - 24.hours.from_now).abs < 5
  end

  test "max_uses + expires_in are honored when supplied" do
    post_gateway_authed(body: { computer_name: "bob-laptop", max_uses: 3, expires_in: "1h" })
    assert_response :created

    body  = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])
    assert_equal 3, token.max_uses
    assert (token.expires_at - 1.hour.from_now).abs < 5
    assert_match(/3 uses/, body["message"])
  end

  test "metadata is stored in token.notes (forward-compat for future fields)" do
    post_gateway_authed(
      body: { computer_name: "alice-laptop", metadata: { os: "macOS", owner: "alice@x" } }
    )
    assert_response :created

    body  = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])
    assert_match(/computer_name=alice-laptop/, token.notes)
    assert_match(/issued_by=#{Regexp.escape(@admin.email)}/, token.notes)
    assert_match(/macOS/, token.notes)
  end

  test "writes api.admin.enrollment_token.issued audit log entry" do
    assert_difference -> { AuditLog.where(action: "api.admin.enrollment_token.issued").count }, 1 do
      post_gateway_authed(body: { computer_name: "alice-laptop" })
    end
    assert_response :created

    entry = AuditLog.where(action: "api.admin.enrollment_token.issued").last
    details = entry.parsed_details
    assert_equal "alice-laptop",      details["computer_name"]
    assert_equal @network.zone,       details["zone"]
    assert_equal @admin.email,        details["admin_email"]
  end

  # ── Validation ─────────────────────────────────────────────────

  test "missing computer_name returns 422" do
    post_gateway_authed(body: {})
    assert_response :unprocessable_entity
    body = JSON.parse(response.body)
    assert_equal "validation_failed", body["error"]
    assert_match(/computer_name/i, body["message"])
  end

  test "empty / whitespace computer_name returns 422" do
    post_gateway_authed(body: { computer_name: "  " })
    assert_response :unprocessable_entity
  end

  test "computer_name with invalid characters returns 422" do
    post_gateway_authed(body: { computer_name: "alice's laptop!" })
    assert_response :unprocessable_entity
  end

  test "computer_name exceeding 253 bytes returns 422" do
    too_long = "a" + (".#{"b" * 60}") * 5
    post_gateway_authed(body: { computer_name: too_long })
    assert_response :unprocessable_entity
  end

  # ── Helpers ────────────────────────────────────────────────────

  private

  def post_gateway_authed(body:)
    headers = signed_gateway_headers(email: @admin.email)
    with_gateway_env do
      post "/api/admin/enrollment_tokens",
           params: body.to_json,
           headers: headers.merge("Content-Type" => "application/json")
    end
  end

  # Build a valid signed X-ZTLP-* header set for the gateway-auth path.
  # Mirrors `AuthenticationTest#signed_gateway_headers`.
  def signed_gateway_headers(email:, secret: GATEWAY_SECRET, timestamp: Time.now.utc.iso8601)
    base = {
      "X-ZTLP-Authenticated" => "1",
      "X-ZTLP-Admin-Email"   => email,
      "X-ZTLP-Timestamp"     => timestamp
    }
    canonical = Ztlp::HeaderVerifier.canonical_string(base.to_a)
    sig = Ztlp::HeaderVerifier.hmac_hex(canonical, secret)
    base.merge("X-ZTLP-Signature" => sig)
  end

  def with_gateway_env
    prev_trust  = ENV["ZTLP_TRUST_GATEWAY_AUTH"]
    prev_secret = ENV["ZTLP_GATEWAY_HEADER_SECRET"]
    ENV["ZTLP_TRUST_GATEWAY_AUTH"]    = "true"
    ENV["ZTLP_GATEWAY_HEADER_SECRET"] = GATEWAY_SECRET
    yield
  ensure
    prev_trust.nil?  ? ENV.delete("ZTLP_TRUST_GATEWAY_AUTH")    : ENV["ZTLP_TRUST_GATEWAY_AUTH"]    = prev_trust
    prev_secret.nil? ? ENV.delete("ZTLP_GATEWAY_HEADER_SECRET") : ENV["ZTLP_GATEWAY_HEADER_SECRET"] = prev_secret
  end
end
