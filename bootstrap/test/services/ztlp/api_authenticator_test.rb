# frozen_string_literal: true

require "test_helper"

# Unit tests for Ztlp::ApiAuthenticator's pure helper methods.
# Integration with Rails request flow is covered in
# `test/controllers/api/v1/health_controller_test.rb`.
class Ztlp::ApiAuthenticatorTest < ActiveSupport::TestCase
  # ── slugify_zone ────────────────────────────────────────────────

  test "slugify_zone matches the gateway/relay rule" do
    # Cross-checks with the cases from
    # gateway/lib/ztlp_gateway/hmac_secrets.ex#slugify_zone/1
    assert_equal "ACME", Ztlp::ApiAuthenticator.slugify_zone("acme")
    assert_equal "ACME_ZTLP", Ztlp::ApiAuthenticator.slugify_zone("acme.ztlp")
    assert_equal "TECH_ROCKSTARS_ZTLP",
                 Ztlp::ApiAuthenticator.slugify_zone("tech-rockstars.ztlp")
  end

  # ── canonical_signing_string ────────────────────────────────────

  test "canonical signing string is exactly six newline-joined lines" do
    msg = Ztlp::ApiAuthenticator.canonical_signing_string(
      method: "POST",
      path: "/api/v1/enrollment_tokens",
      zone: "acme.ztlp",
      client: "z2ls.acme",
      timestamp: 1_700_000_000,
      body: '{"computer_name":"x"}'
    )
    lines = msg.split("\n", -1)
    assert_equal 6, lines.size
    assert_equal "POST", lines[0]
    assert_equal "/api/v1/enrollment_tokens", lines[1]
    assert_equal "acme.ztlp", lines[2]
    assert_equal "z2ls.acme", lines[3]
    assert_equal "1700000000", lines[4]
    assert_equal Digest::SHA256.hexdigest('{"computer_name":"x"}'), lines[5]
  end

  test "canonical signing string upper-cases METHOD" do
    msg = Ztlp::ApiAuthenticator.canonical_signing_string(
      method: "post", path: "/a", zone: "z", client: "c",
      timestamp: 1, body: ""
    )
    assert msg.start_with?("POST\n")
  end

  test "canonical signing string digests an empty body to the empty-string SHA256" do
    empty_digest = Digest::SHA256.hexdigest("")
    msg = Ztlp::ApiAuthenticator.canonical_signing_string(
      method: "GET", path: "/a", zone: "z", client: "c",
      timestamp: 1, body: ""
    )
    assert msg.end_with?("\n#{empty_digest}")
  end

  # ── sign ────────────────────────────────────────────────────────

  test "sign yields a deterministic 64-char hex HMAC-SHA256" do
    sig = Ztlp::ApiAuthenticator.sign(
      method: "GET", path: "/a", zone: "z", client: "c",
      timestamp: 1_700_000_000, body: "", secret: "topsecret"
    )
    assert_equal 64, sig.length
    assert_match(/\A[0-9a-f]{64}\z/, sig)
    # Re-signing the same input produces the same output.
    sig2 = Ztlp::ApiAuthenticator.sign(
      method: "GET", path: "/a", zone: "z", client: "c",
      timestamp: 1_700_000_000, body: "", secret: "topsecret"
    )
    assert_equal sig, sig2
  end

  test "sign matches OpenSSL::HMAC over the canonical message" do
    secret = "topsecret"
    msg = Ztlp::ApiAuthenticator.canonical_signing_string(
      method: "POST", path: "/x", zone: "acme.ztlp", client: "z2ls.acme",
      timestamp: 42, body: "hello"
    )
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, msg)
    actual = Ztlp::ApiAuthenticator.sign(
      method: "POST", path: "/x", zone: "acme.ztlp", client: "z2ls.acme",
      timestamp: 42, body: "hello", secret: secret
    )
    assert_equal expected, actual
  end

  # ── resolve_zone_secret ─────────────────────────────────────────

  test "resolve_zone_secret reads the slugified env var" do
    ENV["ZTLP_HMAC_SECRET_RESOLVE_TEST"] = "rawsecretvalue"
    assert_equal "rawsecretvalue",
                 Ztlp::ApiAuthenticator.resolve_zone_secret("resolve-test")
  ensure
    ENV.delete("ZTLP_HMAC_SECRET_RESOLVE_TEST")
  end

  test "resolve_zone_secret returns nil when env var is unset" do
    ENV.delete("ZTLP_HMAC_SECRET_UNSET_ZTLP")
    assert_nil Ztlp::ApiAuthenticator.resolve_zone_secret("unset.ztlp")
  end

  test "resolve_zone_secret decodes a 64-char hex value to raw bytes" do
    raw = SecureRandom.random_bytes(32)
    hex = raw.unpack1("H*")
    ENV["ZTLP_HMAC_SECRET_HEX_TEST"] = hex
    decoded = Ztlp::ApiAuthenticator.resolve_zone_secret("hex-test")
    assert_equal 32, decoded.bytesize
    assert_equal raw, decoded
  ensure
    ENV.delete("ZTLP_HMAC_SECRET_HEX_TEST")
  end

  test "resolve_zone_secret takes the first comma-separated entry as primary" do
    ENV["ZTLP_HMAC_SECRET_ROTATE_TEST"] = "primary_one,grace_two,grace_three"
    assert_equal "primary_one",
                 Ztlp::ApiAuthenticator.resolve_zone_secret("rotate-test")
  ensure
    ENV.delete("ZTLP_HMAC_SECRET_ROTATE_TEST")
  end
end
