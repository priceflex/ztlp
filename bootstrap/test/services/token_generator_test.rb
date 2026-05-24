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

  # ── Phase A: target_kind / target_label round-trip ──────────────
  #
  # The generator is the single chokepoint for token creation; both
  # the dashboard controller (`TokensController#create`) and the
  # Z2LS API (`Api::V1::EnrollmentTokensController`) call it. Pin the
  # round-trip so future refactors can't silently drop the kwargs.

  test "generates a device-target token when target_kind: 'device' + target_label:" do
    token = @generator.generate!(target_kind: "device", target_label: "alice-laptop")

    assert token.persisted?
    assert_equal "device", token.target_kind
    assert_equal "alice-laptop", token.target_label
    assert token.device_target?
    refute token.user_target?
    assert_nil token.ztlp_user_id
  end

  test "generates a user-target token when target_kind: 'user' + ztlp_user:" do
    user = ztlp_users(:alice)
    token = @generator.generate!(
      target_kind: "user",
      target_label: user.name,
      ztlp_user: user
    )

    assert_equal "user", token.target_kind
    assert_equal user.name, token.target_label
    assert_equal user.id, token.ztlp_user_id
    assert token.user_target?
  end

  test "back-compat: legacy callers (no target kwargs) keep working" do
    token = @generator.generate!(notes: "legacy mint, no principal")

    assert token.persisted?
    assert_nil token.target_kind
    assert_nil token.target_label
    assert_equal "legacy mint, no principal", token.notes
  end

  test "ztlp_user kwarg sets ztlp_user_id (back-compat with API v1)" do
    user = ztlp_users(:bob)
    token = @generator.generate!(ztlp_user: user)

    assert_equal user.id, token.ztlp_user_id
  end

  test "rejects target_kind without target_label (model validation propagates)" do
    assert_raises(ActiveRecord::RecordInvalid) do
      @generator.generate!(target_kind: "device")
    end
  end

  test "rejects target_label without target_kind (model validation propagates)" do
    assert_raises(ActiveRecord::RecordInvalid) do
      @generator.generate!(target_label: "alice-laptop")
    end
  end

  test "rejects unknown target_kind (model validation propagates)" do
    assert_raises(ActiveRecord::RecordInvalid) do
      @generator.generate!(target_kind: "machine", target_label: "x")
    end
  end
end
