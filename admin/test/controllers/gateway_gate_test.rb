# frozen_string_literal: true

require "test_helper"

class GatewayGateTest < ActionDispatch::IntegrationTest
  SECRET="***"

  setup do
    ENV["ZTLP_GATEWAY_HEADER_SECRET"] = SECRET
    ENV["ZTLP_GATEWAY_AUDIENCE"] = "admin"
    ENV["ZTLP_REQUIRE_GATEWAY"] = "1"
    @admin, @seed = make_admin(username: "steve")
  end

  teardown do
    ENV.delete("ZTLP_GATEWAY_HEADER_SECRET")
    ENV.delete("ZTLP_GATEWAY_AUDIENCE")
    ENV.delete("ZTLP_REQUIRE_GATEWAY")
    ENV.delete("ZTLP_MIN_ASSURANCE")
  end

  def tunnel_headers(email: "steve", assurance: "software", ts: Time.now.utc)
    f = { "X-ZTLP-Authenticated" => "1", "X-ZTLP-Admin-Email" => email, "X-ZTLP-Device-Name" => "aicomputer.trs.ztlp",
          "X-ZTLP-Zone" => "trs.ztlp", "X-ZTLP-Group" => "", "X-ZTLP-Assurance" => assurance,
          "X-ZTLP-Audience" => "admin", "X-ZTLP-Timestamp" => ts.strftime("%Y-%m-%dT%H:%M:%SZ") }
    canon = f.map { |k, v| "#{k.downcase}:#{v}" }.sort.join("\n")
    f.merge("X-ZTLP-Signature" => OpenSSL::HMAC.hexdigest("SHA256", SECRET, canon))
  end

  test "no gateway headers at all: 403 + audit row" do
    get root_path
    assert_response :forbidden
    assert AuditLog.exists?(action: "auth.gateway_rejected", status: "denied")
  end

  test "no gateway headers: 403 even with a valid signed-in session" do
    # Build a real session with the gate off (decision 8: with the gate on, the
    # Ed25519 challenge endpoints are themselves behind the gate), then turn it on.
    ENV["ZTLP_REQUIRE_GATEWAY"] = "0"
    sign_in_as(@admin, @seed)
    get root_path
    assert_response :success
    ENV["ZTLP_REQUIRE_GATEWAY"] = "1"
    get root_path
    assert_response :forbidden
    assert AuditLog.exists?(action: "auth.gateway_rejected", status: "denied")
  end

  test "gate on: the Ed25519 challenge endpoint is also behind the gate" do
    post auth_challenge_path, params: { pubkey_hex: @admin.pubkey_hex }, as: :json
    assert_response :forbidden
  end

  test "gate on and no admin yet: /claim still requires the tunnel (decision 9)" do
    Admin.delete_all
    get claim_path
    assert_response :forbidden
  end

  test "gate on and no admin yet: /claim through the tunnel renders" do
    Admin.delete_all
    get claim_path, headers: tunnel_headers
    assert_response :success
  end

  test "valid signed bundle: signed in and 200" do
    get root_path, headers: tunnel_headers
    assert_response :success
    assert_select "h1", "Overview"
    assert AuditLog.exists?(action: "auth.login_ztlp", admin_id: @admin.id)
  end

  test "assurance floor: below ZTLP_MIN_ASSURANCE is 403 + auth.assurance_insufficient" do
    ENV["ZTLP_MIN_ASSURANCE"] = "device-bound"
    get root_path, headers: tunnel_headers(assurance: "software")
    assert_response :forbidden
    assert AuditLog.exists?(action: "auth.assurance_insufficient", status: "denied")
  end

  test "assurance at the floor passes" do
    ENV["ZTLP_MIN_ASSURANCE"] = "device-bound"
    get root_path, headers: tunnel_headers(assurance: "device-bound")
    assert_response :success
  end

  test "/up is never gated" do
    get "/up"
    assert_response :success
  end

  test "forged signature is rejected with an audit row" do
    h = tunnel_headers
    get root_path, headers: h.merge("X-ZTLP-Signature" => "00" * 32)
    assert_response :forbidden
    assert AuditLog.exists?(action: "auth.gateway_rejected", status: "denied")
  end
end
