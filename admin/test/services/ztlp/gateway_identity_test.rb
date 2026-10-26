require "test_helper"

class Ztlp::GatewayIdentityTest < ActiveSupport::TestCase
  SECRET = "unit-test-header-secret"

  setup do
    ENV["ZTLP_GATEWAY_HEADER_SECRET"] = SECRET
    ENV["ZTLP_GATEWAY_AUDIENCE"] = "admin"
    @now = Time.utc(2026, 10, 6, 7, 0, 0)
  end

  teardown { ENV.delete("ZTLP_GATEWAY_HEADER_SECRET"); ENV.delete("ZTLP_GATEWAY_AUDIENCE") }

  # Mirrors proto/src/http_injector.rs::inject_headers exactly.
  def signed_headers(email: "steve", audience: "admin", ts: @now, secret: SECRET, **over)
    f = { "X-ZTLP-Authenticated" => "1", "X-ZTLP-Admin-Email" => email, "X-ZTLP-Device-Name" => "aicomputer.trs.ztlp",
          "X-ZTLP-Zone" => "trs.ztlp", "X-ZTLP-Group" => "", "X-ZTLP-Assurance" => "software",
          "X-ZTLP-Audience" => audience, "X-ZTLP-Timestamp" => ts.strftime("%Y-%m-%dT%H:%M:%SZ") }.merge(over)
    canon = f.map { |k, v| "#{k.downcase}:#{v}" }.sort.join("\n")
    f.merge("X-ZTLP-Signature" => OpenSSL::HMAC.hexdigest("SHA256", secret, canon))
  end

  test "golden vector matches the Rust canonicalisation" do
    # Computed independently: sorted lowercased name:value pairs joined by LF.
    h = signed_headers
    canon = "x-ztlp-admin-email:steve\nx-ztlp-assurance:software\nx-ztlp-audience:admin\nx-ztlp-authenticated:1\n" \
            "x-ztlp-device-name:aicomputer.trs.ztlp\nx-ztlp-group:\nx-ztlp-timestamp:2026-10-06T07:00:00Z\nx-ztlp-zone:trs.ztlp"
    assert_equal OpenSSL::HMAC.hexdigest("SHA256", SECRET, canon), h["X-ZTLP-Signature"]
  end

  test "valid bundle verifies and yields subject" do
    r = Ztlp::GatewayIdentity.verify(signed_headers, now: @now + 5)
    assert r.ok, r.error
    assert_equal "steve", r.subject
    assert_equal "aicomputer.trs.ztlp", r.device_name
  end

  test "accepts rack env form" do
    env = signed_headers.to_h { |k, v| [ "HTTP_" + k.upcase.tr("-", "_"), v ] }
    assert Ztlp::GatewayIdentity.verify(env, now: @now).ok
  end

  test "rejects tampered field, wrong secret, wrong audience, stale, missing" do
    h = signed_headers
    refute Ztlp::GatewayIdentity.verify(h.merge("X-ZTLP-Admin-Email" => "mallory"), now: @now).ok
    refute Ztlp::GatewayIdentity.verify(signed_headers(secret: "other"), now: @now).ok
    refute Ztlp::GatewayIdentity.verify(signed_headers(audience: "www"), now: @now).ok
    assert_equal "stale", Ztlp::GatewayIdentity.verify(h, now: @now + 120).error
    assert_equal "no signature", Ztlp::GatewayIdentity.verify({}, now: @now).error
  end

  test "disabled without secret" do
    ENV.delete("ZTLP_GATEWAY_HEADER_SECRET")
    assert_equal "disabled", Ztlp::GatewayIdentity.verify(signed_headers, now: @now).error
  end
end
