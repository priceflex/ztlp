require "test_helper"

class GatewaySsoTest < ActionDispatch::IntegrationTest
  SECRET = "sso-test-secret"

  setup do
    ENV["ZTLP_GATEWAY_HEADER_SECRET"] = SECRET
    ENV["ZTLP_GATEWAY_AUDIENCE"] = "admin"
    @admin, _seed = make_admin(username: "steve")
  end

  teardown { ENV.delete("ZTLP_GATEWAY_HEADER_SECRET"); ENV.delete("ZTLP_GATEWAY_AUDIENCE") }

  def tunnel_headers(email: "steve", ts: Time.now.utc)
    f = { "X-ZTLP-Authenticated" => "1", "X-ZTLP-Admin-Email" => email, "X-ZTLP-Device-Name" => "aicomputer.trs.ztlp",
          "X-ZTLP-Zone" => "trs.ztlp", "X-ZTLP-Group" => "", "X-ZTLP-Assurance" => "software",
          "X-ZTLP-Audience" => "admin", "X-ZTLP-Timestamp" => ts.strftime("%Y-%m-%dT%H:%M:%SZ") }
    canon = f.map { |k, v| "#{k.downcase}:#{v}" }.sort.join("\n")
    f.merge("X-ZTLP-Signature" => OpenSSL::HMAC.hexdigest("SHA256", SECRET, canon))
  end

  test "verified tunnel identity signs in without a form" do
    get root_path, headers: tunnel_headers
    assert_response :success
    assert_select "h1", "Dashboard"
    assert_match(/via ZTLP aicomputer\.trs\.ztlp/, response.body)
    assert AuditLog.exists?(action: "auth.login_ztlp", admin_id: @admin.id)
    # session persists without headers on the next request
    get admins_path
    assert_response :success
  end

  test "unknown subject is not signed in and login page explains" do
    get login_path, headers: tunnel_headers(email: "nobody")
    assert_response :success
    assert_match(/no active administrator matches/, response.body)
    get root_path, headers: tunnel_headers(email: "nobody")
    assert_redirected_to login_path
  end

  test "forged or stale headers do nothing" do
    h = tunnel_headers
    get root_path, headers: h.merge("X-ZTLP-Admin-Email" => "steve", "X-ZTLP-Signature" => "00" * 32)
    assert_redirected_to login_path
    get root_path, headers: tunnel_headers(ts: 10.minutes.ago)
    assert_redirected_to login_path
  end

  test "disabled admin is not signed in via tunnel" do
    @admin.update!(disabled_at: Time.current)
    get root_path, headers: tunnel_headers
    assert_redirected_to login_path
  end

  test "logout pauses tunnel SSO" do
    get root_path, headers: tunnel_headers
    assert_response :success
    delete logout_path, headers: tunnel_headers
    assert_redirected_to login_path
    get root_path, headers: tunnel_headers
    assert_redirected_to login_path
  end

  test "no secret configured means SSO is off" do
    ENV.delete("ZTLP_GATEWAY_HEADER_SECRET")
    get root_path, headers: tunnel_headers
    assert_redirected_to login_path
  end
end
