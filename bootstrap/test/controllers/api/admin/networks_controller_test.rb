# frozen_string_literal: true

require "test_helper"
require "ztlp/header_verifier"

# Integration tests for the gateway-auth Networks API.
#
# Mirrors Api::Admin::EnrollmentTokensController's auth model: reachable only
# over the ZTLP gateway-auth path (X-ZTLP-* signed headers), never via cookie
# session. Lets Z2LS create a per-customer Network row (zone) idempotently as
# part of one-click onboarding — the missing Phase-1 step that previously had
# to be done by hand (curl / dashboard) before token minting could succeed.
#
# Creating the Network auto-seeds the shared NS+Relay machines via
# Network#after_create_commit (when seed_shared_machines_on_create is on in the
# real container), so a subsequent enrollment-token mint stops returning 503.
class Api::Admin::NetworksControllerTest < ActionDispatch::IntegrationTest
  GATEWAY_SECRET = "gw-auth-shared-secret-for-tests"

  setup do
    @admin = admin_users(:super_admin)
  end

  # ── Auth ────────────────────────────────────────────────────────

  test "POST without any gateway-auth headers returns 401 JSON" do
    post "/api/admin/networks",
         params: { zone: "newco.trs.ztlp", name: "NewCo" }.to_json,
         headers: { "Content-Type" => "application/json" }

    assert_response :unauthorized
    assert_equal "unauthorized", JSON.parse(response.body)["error"]
  end

  test "POST with cookie-session admin (no gateway headers) is still 401" do
    post login_path, params: { email: @admin.email, password: "password123" }
    follow_redirect! if response.redirect?

    post "/api/admin/networks",
         params: { zone: "newco.trs.ztlp", name: "NewCo" }.to_json,
         headers: { "Content-Type" => "application/json" }

    assert_response :unauthorized
  end

  test "POST with corrupted gateway signature returns 401" do
    headers = signed_gateway_headers(email: @admin.email)
    headers["X-ZTLP-Signature"] = "0" * headers["X-ZTLP-Signature"].length

    with_gateway_env do
      post "/api/admin/networks",
           params: { zone: "newco.trs.ztlp", name: "NewCo" }.to_json,
           headers: headers.merge("Content-Type" => "application/json")
    end

    assert_response :unauthorized
  end

  # ── Happy path ─────────────────────────────────────────────────

  test "valid gateway-auth + new zone creates the Network (201)" do
    assert_difference -> { Network.count }, 1 do
      post_gateway_authed(body: { zone: "newco.trs.ztlp", name: "NewCo Inc" })
    end

    assert_response :created
    body = JSON.parse(response.body)
    assert_equal "created", body["status"]
    assert_equal "newco.trs.ztlp", body["zone"]
    assert_equal "NewCo Inc", body["name"]
    assert body["network_id"].present?

    net = Network.find_by(zone: "newco.trs.ztlp")
    assert_not_nil net
    assert_equal "created", net.status
    assert net.enrollment_secret_ciphertext.present?, "should self-assign an enrollment secret"
  end

  test "derives a name from the zone when name omitted" do
    post_gateway_authed(body: { zone: "acme-dental.trs.ztlp" })
    assert_response :created
    body = JSON.parse(response.body)
    assert_equal "acme-dental.trs.ztlp", body["zone"]
    assert body["name"].present?
  end

  # ── Idempotency ────────────────────────────────────────────────

  test "re-POSTing an existing zone returns 200 existing, no duplicate row" do
    existing = networks(:office)

    assert_no_difference -> { Network.count } do
      post_gateway_authed(body: { zone: existing.zone, name: "Whatever Else" })
    end

    assert_response :ok
    body = JSON.parse(response.body)
    assert_equal "existing", body["status"]
    assert_equal existing.zone, body["zone"]
    assert_equal existing.id, body["network_id"]
    # Must NOT clobber the operator's existing name on a re-onboard.
    assert_equal existing.name, Network.find(existing.id).name
  end

  test "writes a network.api_created audit log on creation" do
    assert_difference -> { AuditLog.where(action: "api.admin.network.created").count }, 1 do
      post_gateway_authed(body: { zone: "audited.trs.ztlp", name: "Audited" })
    end
    assert_response :created
  end

  # ── Validation ─────────────────────────────────────────────────

  test "missing zone returns 422" do
    post_gateway_authed(body: { name: "NoZone" })
    assert_response :unprocessable_entity
    assert_equal "validation_failed", JSON.parse(response.body)["error"]
  end

  test "malformed zone returns 422" do
    post_gateway_authed(body: { zone: "Not A Valid Zone!", name: "Bad" })
    assert_response :unprocessable_entity
    assert_equal "validation_failed", JSON.parse(response.body)["error"]
  end

  # ── Helpers ────────────────────────────────────────────────────

  private

  def post_gateway_authed(body:)
    headers = signed_gateway_headers(email: @admin.email)
    with_gateway_env do
      post "/api/admin/networks",
           params: body.to_json,
           headers: headers.merge("Content-Type" => "application/json")
    end
  end

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
