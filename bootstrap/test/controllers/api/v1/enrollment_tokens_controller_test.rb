# frozen_string_literal: true

require "test_helper"

# Integration tests for the Z2LS enrollment-token endpoint.
#
# BS-PR-3 — `POST /api/v1/enrollment_tokens`. This is the headline
# deliverable Steve called out in the 2026-05-23 brief.
#
# Auth is exercised by `Api::V1::HealthControllerTest`; here we
# focus on the endpoint-specific behaviour:
#
#   * Happy path: 201 with URI, token_id, expiry metadata
#   * Validation: missing/malformed computer_name → 422
#   * Cross-tenant safety: token is minted for the auth'd client's zone
#     (not whatever zone-id the caller might try to put in the body)
#   * Single-use enforcement piped through to the model: created
#     token has max_uses=1 and ~24h TTL
#   * 24h default TTL pinned at the API layer
#   * Audit log: api.v1.enrollment_token.issued is written
#   * Service unavailable: 503 when the zone has no provisioned
#     network (api_client exists in the allowlist, Network row doesn't)
class Api::V1::EnrollmentTokensControllerTest < ActionDispatch::IntegrationTest
  ZONE = "office.acme.ztlp"
  CLIENT = "z2ls.office"
  SECRET = "0" * 32
  ENV_KEY = "ZTLP_HMAC_SECRET_OFFICE_ACME_ZTLP"

  setup do
    @client = api_clients(:z2ls_office)
    @network = networks(:office)
    @prev_env = ENV[ENV_KEY]
    ENV[ENV_KEY] = SECRET
  end

  teardown do
    ENV[ENV_KEY] = @prev_env
  end

  # ── Happy path ──────────────────────────────────────────────────

  test "issues a valid enrollment token for a well-formed computer_name" do
    pre_count = EnrollmentToken.count

    post_signed(body: { computer_name: "alice-laptop" })

    assert_response :created
    assert_equal pre_count + 1, EnrollmentToken.count

    body = JSON.parse(response.body)
    assert_equal "issued", body["status"]
    assert body["enrollment_token"].start_with?("ztlp://enroll/?")
    assert body["token_id"].present?
    assert body["expiration_datetime"].present?
    assert_kind_of Integer, body["token_lifetime_seconds"]
    # Lifetime should be ~24h (give or take a few seconds of test runtime)
    assert body["token_lifetime_seconds"] > 23 * 3600
    assert body["token_lifetime_seconds"] <= 24 * 3600
    assert body["message"].present?
  end

  test "issued token has max_uses=1 and ~24h expiry (BS-PR-1 default flows through)" do
    pre = Time.current
    post_signed(body: { computer_name: "alice-laptop" })
    post_time = Time.current
    assert_response :created

    body = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])

    assert_equal 1, token.max_uses
    assert_equal 0, token.current_uses
    assert_equal "active", token.status

    # Token expiry is ~24h from creation time. Allow generous test
    # jitter (the body of the create action takes O(ms)).
    expected = pre + 24.hours
    assert (token.expires_at - expected).abs < (post_time - pre + 2),
           "expected expiry ~24h from now, got delta=#{token.expires_at - expected}s"
  end

  test "stores computer_name + issuer in token notes for audit trail" do
    post_signed(body: { computer_name: "alice-laptop" })
    body = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])

    assert_match(/computer_name=alice-laptop/, token.notes)
    assert_match(/issued_by=z2ls\.office/, token.notes)
  end

  test "stores optional metadata in notes (forward-compat for future fields)" do
    post_signed(body: { computer_name: "alice-laptop", metadata: { os: "macOS", user: "alice" } })
    body = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])

    assert_match(/metadata=/, token.notes)
    assert_match(/macOS/, token.notes)
  end

  test "writes api.v1.enrollment_token.issued audit log entry" do
    assert_difference -> { AuditLog.where(action: "api.v1.enrollment_token.issued").count }, 1 do
      post_signed(body: { computer_name: "alice-laptop" })
    end
    assert_response :created

    entry = AuditLog.where(action: "api.v1.enrollment_token.issued").last
    details = entry.parsed_details
    assert_equal "alice-laptop", details["computer_name"]
    assert_equal ZONE, details["zone"]
    assert_equal CLIENT, details["issued_by_api_client"]
  end

  # ── Validation ──────────────────────────────────────────────────

  test "missing computer_name returns 422" do
    post_signed(body: {})
    assert_response :unprocessable_entity
    body = JSON.parse(response.body)
    assert_equal "error", body["status"]
    assert_match(/computer_name/i, body["message"])
  end

  test "empty computer_name returns 422" do
    post_signed(body: { computer_name: "  " })
    assert_response :unprocessable_entity
  end

  test "computer_name with invalid characters returns 422" do
    post_signed(body: { computer_name: "alice's laptop!" })
    assert_response :unprocessable_entity
  end

  test "computer_name exceeding 253 bytes returns 422" do
    too_long = "a" + ("." + "b" * 60) * 5 # 5 * 61 + 1 = 306 chars
    post_signed(body: { computer_name: too_long })
    assert_response :unprocessable_entity
  end

  test "valid hostname with dotted suffix is accepted" do
    post_signed(body: { computer_name: "alice-laptop.office.acme.ztlp" })
    assert_response :created
  end

  # ── Service unavailable ─────────────────────────────────────────

  test "503 when the auth'd client's zone has no Network row provisioned" do
    # api_clients(:z2ls_acme) has zone="acme.ztlp" but there's no
    # Network with that zone in the fixtures — only office.acme.ztlp
    # and prod.acme.ztlp exist.
    ENV["ZTLP_HMAC_SECRET_ACME_ZTLP"] = SECRET

    post_signed_with(
      path: "/api/v1/enrollment_tokens",
      zone: "acme.ztlp",
      client: "z2ls.acme",
      secret: SECRET,
      body: { computer_name: "orphan" }
    )

    assert_response :service_unavailable
    body = JSON.parse(response.body)
    assert_match(/no network configured/i, body["message"])
  ensure
    ENV.delete("ZTLP_HMAC_SECRET_ACME_ZTLP")
  end

  # ── Cross-tenant safety ─────────────────────────────────────────

  test "token is minted for the AUTH'D client's zone, not anything in the body" do
    # Even if a caller tries to put a different zone in the request
    # body, the controller looks up the network by
    # current_api_client.zone — they cannot mint tokens for another
    # tenant.
    post_signed(body: { computer_name: "alice-laptop", zone: "evil.ztlp" })
    assert_response :created

    body = JSON.parse(response.body)
    token = EnrollmentToken.find_by(token_id: body["token_id"])

    # Token belongs to the OFFICE network (the auth'd client's zone),
    # NOT any "evil" zone.
    assert_equal @network, token.network
    assert_equal "office.acme.ztlp", token.network.zone
  end

  # ── Auth (delegated to Api::V1::BaseController) ─────────────────

  test "request without HMAC headers returns 401" do
    post "/api/v1/enrollment_tokens",
         params: { computer_name: "alice-laptop" }.to_json,
         headers: { "Content-Type" => "application/json" }

    assert_response :unauthorized
  end

  # ── Helpers ─────────────────────────────────────────────────────

  def post_signed(body:)
    post_signed_with(
      path: "/api/v1/enrollment_tokens",
      zone: ZONE,
      client: CLIENT,
      secret: SECRET,
      body: body
    )
  end

  def post_signed_with(path:, zone:, client:, secret:, body:)
    raw = body.to_json
    ts = Time.current.to_i
    sig = Ztlp::ApiAuthenticator.sign(
      method: "POST",
      path: path,
      zone: zone,
      client: client,
      timestamp: ts,
      body: raw,
      secret: secret
    )

    post path,
         params: raw,
         headers: {
           "Content-Type"     => "application/json",
           "X-ZTLP-Client-Zone"      => zone,
           "X-ZTLP-Client-Name"      => client,
           "X-ZTLP-Client-Timestamp" => ts.to_s,
           "X-ZTLP-Client-Signature" => sig
         }
  end
end
