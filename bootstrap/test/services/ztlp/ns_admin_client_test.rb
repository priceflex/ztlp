# frozen_string_literal: true

require "test_helper"
require "net/http"
require "openssl"
require "digest"
require "json"
require "securerandom"

# Ztlp::NsAdminClient — Bootstrap-side HTTP client for the NS
# /admin/records read-only admin endpoint. The wire contract (HMAC
# signing, header names, canonical message format) is shared with
# `ZtlpNs.AdminApi.verify_request/5` on the NS side. If you change
# the canonical signing string here, change it in NS too — this test
# file is the canonical source of truth for the Ruby side of that
# contract.
#
# We stub `Net::HTTP#request` with Mocha rather than pulling in
# webmock, because webmock isn't in the bootstrap Gemfile and we
# don't want to add a deps just for one client.
class Ztlp::NsAdminClientTest < ActiveSupport::TestCase
  # 64-char hex secret, matches the format NS expects in
  # ZTLP_NS_ADMIN_API_SECRET. SecureRandom.hex(32) gives 64 hex chars
  # = 32 raw bytes after `[secret].pack("H*")`.
  SECRET = SecureRandom.hex(32)
  BASE = "http://ns.test:9103"

  # Build a Net::HTTPOK-like response with the given body string.
  def make_response(code_class, body_string = "")
    resp = code_class.new("1.1", code_class.const_get(:HAS_BODY) ? "200" : "200", "OK")
    resp.instance_variable_set(:@body, body_string)
    resp.instance_variable_set(:@read, true)
    def resp.body; @body; end
    resp
  end

  # Compute the expected HMAC for a given path + timestamp + empty
  # body, using the same canonical-signing rule the client (and NS)
  # use. Local helper so each test reads as a contract check.
  def expected_signature(path, ts, body = "")
    canonical = "GET\n#{path}\n#{ts}\n#{Digest::SHA256.hexdigest(body)}"
    OpenSSL::HMAC.hexdigest("sha256", [SECRET].pack("H*"), canonical)
  end

  test "list_records signs the request with HMAC and parses JSON" do
    payload = { records: [{ name: "x", type: "key" }], count: 1, generated_at: 0 }.to_json
    fake_resp = Net::HTTPOK.new("1.1", "200", "OK")
    fake_resp.instance_variable_set(:@body, payload)
    def fake_resp.body; @body; end

    captured_path = nil
    captured_ts   = nil
    captured_sig  = nil

    Net::HTTP.any_instance.stubs(:request).with do |req|
      captured_path = req.path
      captured_ts   = req["X-NS-Timestamp"]
      captured_sig  = req["X-NS-Signature"]
      true
    end.returns(fake_resp)

    result = Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)

    assert_equal "/admin/records", captured_path
    refute_nil captured_ts
    refute_nil captured_sig
    assert_equal expected_signature("/admin/records", captured_ts), captured_sig
    assert_equal 1, result["count"]
    assert_equal "x", result["records"][0]["name"]
  end

  test "passes zone and type as query params and signs over the FULL path" do
    fake_resp = Net::HTTPOK.new("1.1", "200", "OK")
    fake_resp.instance_variable_set(:@body, '{"records":[],"count":0,"generated_at":0}')
    def fake_resp.body; @body; end

    captured_path = nil
    captured_ts   = nil
    captured_sig  = nil

    Net::HTTP.any_instance.stubs(:request).with do |req|
      captured_path = req.path
      captured_ts   = req["X-NS-Timestamp"]
      captured_sig  = req["X-NS-Signature"]
      true
    end.returns(fake_resp)

    Ztlp::NsAdminClient.list_records(
      zone: "trs.ztlp", type: "key", base_url: BASE, secret: SECRET
    )

    # Query params must be sorted alphabetically — type before zone —
    # and the path used for signing must include the query string
    # byte-for-byte. Otherwise NS will reject the signature.
    assert_equal "/admin/records?type=key&zone=trs.ztlp", captured_path
    assert_equal expected_signature(captured_path, captured_ts), captured_sig
  end

  test "raises AuthenticationError on 401" do
    fake_resp = Net::HTTPUnauthorized.new("1.1", "401", "Unauthorized")
    fake_resp.instance_variable_set(:@body, "")
    def fake_resp.body; @body; end
    Net::HTTP.any_instance.stubs(:request).returns(fake_resp)

    assert_raises(Ztlp::NsAdminClient::AuthenticationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
  end

  test "raises ServerError on 500" do
    fake_resp = Net::HTTPInternalServerError.new("1.1", "500", "Internal Server Error")
    fake_resp.instance_variable_set(:@body, "")
    def fake_resp.body; @body; end
    Net::HTTP.any_instance.stubs(:request).returns(fake_resp)

    assert_raises(Ztlp::NsAdminClient::ServerError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
  end

  test "raises TransportError when the connection is refused" do
    Net::HTTP.any_instance.stubs(:request).raises(Errno::ECONNREFUSED.new("connection refused"))

    assert_raises(Ztlp::NsAdminClient::TransportError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
  end

  test "raises ConfigurationError when secret missing" do
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: nil)
    end
  end

  test "raises ConfigurationError when base_url missing" do
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: nil, secret: SECRET)
    end
  end

  test "ENV-based config falls through when args omitted" do
    fake_resp = Net::HTTPOK.new("1.1", "200", "OK")
    fake_resp.instance_variable_set(:@body, '{"records":[],"count":0,"generated_at":0}')
    def fake_resp.body; @body; end
    Net::HTTP.any_instance.stubs(:request).returns(fake_resp)

    ENV["ZTLP_NS_ADMIN_BASE_URL"]   = BASE
    ENV["ZTLP_NS_ADMIN_API_SECRET"] = SECRET
    result = Ztlp::NsAdminClient.list_records
    assert_equal 0, result["count"]
  ensure
    ENV.delete("ZTLP_NS_ADMIN_BASE_URL")
    ENV.delete("ZTLP_NS_ADMIN_API_SECRET")
  end

  # ── CodeRabbit follow-up hardening (PR #96 review) ──

  test "raises ServerError when NS returns 200 with malformed JSON" do
    fake_resp = Net::HTTPOK.new("1.1", "200", "OK")
    fake_resp.instance_variable_set(:@body, "not-json-at-all{")
    def fake_resp.body; @body; end
    Net::HTTP.any_instance.stubs(:request).returns(fake_resp)

    err = assert_raises(Ztlp::NsAdminClient::ServerError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
    assert_match(/invalid JSON/, err.message)
  end

  test "raises ConfigurationError for 64-char non-hex secret" do
    bogus = "gg" * 32  # 64 chars, every char invalid hex
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: bogus)
    end
  end

  test "raises ConfigurationError for hex with one invalid character" do
    # 63 valid hex + 1 invalid — would silently pack to garbage without validation
    bogus = ("a" * 63) + "z"
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: bogus)
    end
  end

  test "accepts uppercase hex" do
    upper_hex = SECRET.upcase
    fake_resp = Net::HTTPOK.new("1.1", "200", "OK")
    fake_resp.instance_variable_set(:@body, '{"records":[],"count":0,"generated_at":0}')
    def fake_resp.body; @body; end
    Net::HTTP.any_instance.stubs(:request).returns(fake_resp)

    # Should not raise — uppercase hex is canonical
    Ztlp::NsAdminClient.list_records(base_url: BASE, secret: upper_hex)
  end
end
