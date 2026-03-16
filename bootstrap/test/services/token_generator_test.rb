require "test_helper"

class TokenGeneratorTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @generator = TokenGenerator.new(@network)
  end

  test "generates enrollment token" do
    token = @generator.generate!(expires_in: 24.hours, max_uses: 3, notes: "test token")

    assert token.persisted?
    assert_equal @network, token.network
    assert_equal 3, token.max_uses
    assert_equal 0, token.current_uses
    assert_equal "active", token.status
    assert_equal "test token", token.notes
    assert token.token_id.present?
    assert token.token_uri.present?
    assert token.qr_svg.present?
  end

  test "token URI contains zone and NS info" do
    token = @generator.generate!

    assert_includes token.token_uri, "ztlp://enroll/"
    assert_includes token.token_uri, "zone=office.acme.ztlp"
    # Should reference one of the NS machines
    assert_match(/ns=10\.0\.1\.\d+:23096/, token.token_uri)
  end

  test "token URI includes relay when available" do
    token = @generator.generate!
    assert_includes token.token_uri, "relay="
  end

  test "generates valid QR SVG" do
    token = @generator.generate!
    assert token.qr_svg.start_with?("<?xml") || token.qr_svg.include?("<svg")
  end

  test "raises without NS machine" do
    network = networks(:production)  # has no machines
    generator = TokenGenerator.new(network)

    assert_raises TokenGenerator::TokenError do
      generator.generate!
    end
  end

  test "creates audit log on generation" do
    assert_difference "AuditLog.count" do
      @generator.generate!
    end

    log = AuditLog.last
    assert_equal "token_generate", log.action
    assert_equal "success", log.status
  end

  test "custom expiration" do
    token = @generator.generate!(expires_in: 1.hour)
    assert token.expires_at < 2.hours.from_now
    assert token.expires_at > 30.minutes.from_now
  end

  test "cli_available? returns false when CLI not found" do
    assert_not @generator.cli_available?  # ztlp not installed in test env
  end
end
