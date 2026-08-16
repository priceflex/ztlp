# frozen_string_literal: true

require "test_helper"

# Integration tests for the `Api::V1` ZTLP-secured API surface.
#
# Covers the BS-PR-2 contract end-to-end: a request with valid HMAC
# headers gets a 200 echoing the authenticated client; every
# adversarial variant (missing header, bad timestamp, wrong
# signature, unknown client, inactive client, no per-zone secret)
# returns a generic 401 without leaking the failure reason in the
# response body.
class Api::V1::HealthControllerTest < ActionDispatch::IntegrationTest
  ZONE = "acme.ztlp"
  CLIENT = "z2ls.acme"
  SECRET = "0" * 32  # 32-byte raw secret — kept short and deterministic for tests
  ENV_KEY = "ZTLP_HMAC_SECRET_ACME_ZTLP"

  setup do
    @client = api_clients(:z2ls_acme)
    @prev_env = ENV[ENV_KEY]
    ENV[ENV_KEY] = SECRET
  end

  teardown do
    ENV[ENV_KEY] = @prev_env
  end

  # ── Happy path ──────────────────────────────────────────────────

  test "valid signed request returns 200 with client + zone echoed" do
    get_signed("/api/v1/health")

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal true, body["ok"]
    assert_equal CLIENT, body["client"]
    assert_equal ZONE, body["zone"]
    assert body["server_time"].present?
  end

  test "valid signed request bumps last_used_at on the api_client" do
    @client.update_column(:last_used_at, 1.day.ago)
    get_signed("/api/v1/health")
    assert_response :success
    assert @client.reload.last_used_at > 1.minute.ago
  end

  test "valid signed request writes an api.v1.auth.success audit log entry" do
    assert_difference -> { AuditLog.where(action: "api.v1.auth.success").count }, 1 do
      get_signed("/api/v1/health")
    end
    assert_response :success
  end

  # ── Failure paths ───────────────────────────────────────────────

  test "missing X-ZTLP-Signature returns 401" do
    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => ZONE,
      "X-ZTLP-Client"    => CLIENT,
      "X-ZTLP-Timestamp" => Time.current.to_i.to_s
      # no signature
    }
    assert_response :unauthorized
    body = JSON.parse(response.body)
    assert_equal "unauthorized", body["error"]
    # Response MUST NOT leak the reason code:
    refute body.key?("reason")
  end

  test "bad signature returns 401" do
    ts = Time.current.to_i.to_s
    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => ZONE,
      "X-ZTLP-Client"    => CLIENT,
      "X-ZTLP-Timestamp" => ts,
      "X-ZTLP-Signature" => "f" * 64
    }
    assert_response :unauthorized
  end

  test "expired timestamp returns 401 even with a valid signature" do
    # Sign for a timestamp from 10 minutes ago — should be outside the
    # default 5-minute window.
    old_ts = (Time.current - 10.minutes).to_i
    nonce = SecureRandom.hex(16)
    sig = Ztlp::ApiAuthenticator.sign(
      method: "GET",
      path: "/api/v1/health",
      zone: ZONE,
      client: CLIENT,
      timestamp: old_ts,
      nonce: nonce,
      body: "",
      secret: SECRET
    )

    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => ZONE,
      "X-ZTLP-Client"    => CLIENT,
      "X-ZTLP-Timestamp" => old_ts.to_s,
      "X-ZTLP-Nonce"     => nonce,
      "X-ZTLP-Signature" => sig
    }
    assert_response :unauthorized
  end

  test "non-integer timestamp returns 401" do
    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => ZONE,
      "X-ZTLP-Client"    => CLIENT,
      "X-ZTLP-Timestamp" => "not-a-number",
      "X-ZTLP-Signature" => "f" * 64
    }
    assert_response :unauthorized
  end

  test "unknown api_client returns 401 (no allowlist row)" do
    ts = Time.current.to_i
    nonce = SecureRandom.hex(16)
    sig = Ztlp::ApiAuthenticator.sign(
      method: "GET",
      path: "/api/v1/health",
      zone: ZONE,
      client: "ghost.acme",
      timestamp: ts,
      nonce: nonce,
      body: "",
      secret: SECRET
    )

    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => ZONE,
      "X-ZTLP-Client"    => "ghost.acme",
      "X-ZTLP-Timestamp" => ts.to_s,
      "X-ZTLP-Nonce"     => nonce,
      "X-ZTLP-Signature" => sig
    }
    assert_response :unauthorized
  end

  test "inactive api_client returns 401 (kill-switch path)" do
    @client.update!(active: false)
    get_signed("/api/v1/health")
    assert_response :unauthorized
  end

  test "no per-zone secret configured returns 401" do
    ENV.delete(ENV_KEY)
    get_signed("/api/v1/health")
    assert_response :unauthorized
  end

  test "request to the wrong zone (cross-tenant attempt) returns 401" do
    # Caller signs with the right secret for the wrong zone — must
    # reject because there's no per-zone secret env for that zone AND
    # because there's no api_client row for (other_zone, ...).
    ts = Time.current.to_i
    nonce = SecureRandom.hex(16)
    sig = Ztlp::ApiAuthenticator.sign(
      method: "GET",
      path: "/api/v1/health",
      zone: "evil.ztlp",
      client: CLIENT,
      timestamp: ts,
      nonce: nonce,
      body: "",
      secret: SECRET
    )

    get "/api/v1/health", headers: {
      "X-ZTLP-Zone"      => "evil.ztlp",
      "X-ZTLP-Client"    => CLIENT,
      "X-ZTLP-Timestamp" => ts.to_s,
      "X-ZTLP-Nonce"     => nonce,
      "X-ZTLP-Signature" => sig
    }
    assert_response :unauthorized
  end

  test "failure writes an api.v1.auth.failure audit log entry" do
    assert_difference -> { AuditLog.where(action: "api.v1.auth.failure").count }, 1 do
      get "/api/v1/health", headers: {
        "X-ZTLP-Zone"      => ZONE,
        "X-ZTLP-Client"    => CLIENT,
        "X-ZTLP-Timestamp" => Time.current.to_i.to_s,
        "X-ZTLP-Signature" => "f" * 64
      }
    end
    assert_response :unauthorized

    entry = AuditLog.where(action: "api.v1.auth.failure").last
    details = entry.parsed_details
    # The audit log MAY carry the reason (server-side only), but the
    # HTTP response body MUST NOT.
    assert details["reason"].present?
  end

  # ── Helpers ─────────────────────────────────────────────────────

  def get_signed(path, zone: ZONE, client: CLIENT, secret: SECRET, body: "")
    ts = Time.current.to_i
    nonce = SecureRandom.hex(16)
    sig = Ztlp::ApiAuthenticator.sign(
      method: "GET",
      path: path,
      zone: zone,
      client: client,
      timestamp: ts,
      nonce: nonce,
      body: body,
      secret: secret
    )

    get path, headers: {
      "X-ZTLP-Zone"      => zone,
      "X-ZTLP-Client"    => client,
      "X-ZTLP-Timestamp" => ts.to_s,
      "X-ZTLP-Nonce"     => nonce,
      "X-ZTLP-Signature" => sig
    }
  end
end
