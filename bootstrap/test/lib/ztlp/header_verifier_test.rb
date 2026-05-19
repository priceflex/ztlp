# frozen_string_literal: true

require "test_helper"
require "ztlp/header_verifier"

class Ztlp::HeaderVerifierTest < ActiveSupport::TestCase
  SECRET = "test-shared-secret-xyz"

  def fresh_timestamp(offset_seconds = 0)
    (Time.now.utc + offset_seconds).iso8601
  end

  def sign(headers, secret = SECRET)
    canonical = Ztlp::HeaderVerifier.canonical_string(headers)
    Ztlp::HeaderVerifier.hmac_hex(canonical, secret)
  end

  def build_signed_headers(extra = {}, timestamp: fresh_timestamp, secret: SECRET)
    base = {
      "X-ZTLP-Authenticated" => "1",
      "X-ZTLP-Admin-Email" => "admin@example.com",
      "X-ZTLP-Timestamp" => timestamp
    }.merge(extra)

    sig = sign(base.to_a, secret)
    base.merge("X-ZTLP-Signature" => sig)
  end

  test "happy path returns :ok with identity hash including email" do
    headers = build_signed_headers
    status, identity = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET)

    assert_equal :ok, status
    assert_equal "admin@example.com", identity["admin-email"]
    assert_equal "1", identity["authenticated"]
    assert identity.key?("timestamp")
    refute identity.key?("signature"), "identity must not leak the signature back out"
  end

  test "missing X-ZTLP-Signature returns :missing_signature" do
    headers = build_signed_headers
    headers.delete("X-ZTLP-Signature")

    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET)
    assert_equal :error, status
    assert_equal :missing_signature, reason
  end

  test "bad signature returns :invalid_signature" do
    headers = build_signed_headers
    headers["X-ZTLP-Signature"] = "deadbeef" * 8

    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET)
    assert_equal :error, status
    assert_equal :invalid_signature, reason
  end

  test "missing X-ZTLP-Timestamp returns :missing_timestamp" do
    # Build headers without timestamp, then sign them so signature is valid;
    # the missing-timestamp guard must still trip.
    base = {
      "X-ZTLP-Authenticated" => "1",
      "X-ZTLP-Admin-Email" => "admin@example.com"
    }
    sig = sign(base.to_a)
    headers = base.merge("X-ZTLP-Signature" => sig)

    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET)
    assert_equal :error, status
    assert_equal :missing_timestamp, reason
  end

  test "expired timestamp returns :expired" do
    headers = build_signed_headers(timestamp: fresh_timestamp(-3600))

    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET, max_age_seconds: 60)
    assert_equal :error, status
    assert_equal :expired, reason
  end

  test "verifies regardless of input header order" do
    headers = build_signed_headers
    # Reverse to ensure order is not preserved.
    shuffled = headers.to_a.reverse.to_h

    status, _identity = Ztlp::HeaderVerifier.verify_request(shuffled, secret: SECRET)
    assert_equal :ok, status
  end

  test "header NAME is case-insensitive when verifying" do
    headers = build_signed_headers
    # Re-key with mixed/uppercase header names. Value is unchanged.
    upcased = headers.each_with_object({}) do |(name, value), acc|
      acc[name.upcase] = value
    end

    status, _identity = Ztlp::HeaderVerifier.verify_request(upcased, secret: SECRET)
    assert_equal :ok, status
  end

  test "header VALUE is case-sensitive" do
    headers = build_signed_headers
    # Tamper only with case of the email value — signature must no longer match.
    headers["X-ZTLP-Admin-Email"] = headers["X-ZTLP-Admin-Email"].upcase

    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: SECRET)
    assert_equal :error, status
    assert_equal :invalid_signature, reason
  end

  test "accepts Rack-style env header names (HTTP_X_ZTLP_*)" do
    headers = build_signed_headers
    rack_style = headers.each_with_object({}) do |(name, value), acc|
      acc["HTTP_" + name.upcase.tr("-", "_")] = value
    end

    status, identity = Ztlp::HeaderVerifier.verify_request(rack_style, secret: SECRET)
    assert_equal :ok, status
    assert_equal "admin@example.com", identity["admin-email"]
  end

  test "wrong secret produces :invalid_signature" do
    headers = build_signed_headers
    status, reason = Ztlp::HeaderVerifier.verify_request(headers, secret: "different-secret")
    assert_equal :error, status
    assert_equal :invalid_signature, reason
  end
end
