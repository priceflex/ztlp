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

  # ───────────────────────────────────────────────────────────────────────
  # Phase B redemption fix — RED tests written BEFORE the implementation.
  #
  # Background: tokens were minted with `callback=nil` because the bootstrap
  # container never had `BOOTSTRAP_URL` set in its environment. The CLI saw
  # `token.callback_url == None` and silently skipped calling the
  # `Api::EnrollmentController#confirm` endpoint, so `EnrollmentToken#use!`
  # never ran and the token stayed `active` forever.
  #
  # The fix removes the strict dependency on `ENV["BOOTSTRAP_URL"]`. The
  # caller (controller, job, or test) now passes in a `bootstrap_url:`
  # keyword argument derived from `request.base_url`. This is correct
  # architecturally because the bootstrap *is* the public endpoint the
  # operator just visited to mint the token; whatever URL got them to the
  # dashboard is the same URL the CLI should call back to.
  # ───────────────────────────────────────────────────────────────────────

  test "callback URL is embedded when bootstrap_url is supplied" do
    token = @generator.generate!(bootstrap_url: "https://acme.bootstrap.example")

    assert_match(
      /callback=https%3A%2F%2Facme\.bootstrap\.example%2Fapi%2Fenrollment%2Fconfirm/,
      token.token_uri,
      "expected URL-encoded callback in token_uri, got: #{token.token_uri}"
    )
  end

  test "callback URL falls back to BOOTSTRAP_URL env when bootstrap_url arg is nil" do
    ENV["BOOTSTRAP_URL"] = "https://env-fallback.example"
    begin
      token = @generator.generate!(bootstrap_url: nil)
      assert_match(
        /callback=https%3A%2F%2Fenv-fallback\.example%2Fapi%2Fenrollment%2Fconfirm/,
        token.token_uri,
        "expected env fallback URL in token_uri, got: #{token.token_uri}"
      )
    ensure
      ENV.delete("BOOTSTRAP_URL")
    end
  end

  test "callback URL is omitted entirely when no bootstrap_url and no env" do
    ENV.delete("BOOTSTRAP_URL")
    token = @generator.generate!(bootstrap_url: nil)
    assert_no_match(
      /callback=/,
      token.token_uri,
      "expected no callback param when no URL available, got: #{token.token_uri}"
    )
  end

  test "supplied bootstrap_url takes precedence over BOOTSTRAP_URL env" do
    ENV["BOOTSTRAP_URL"] = "https://env-loser.example"
    begin
      token = @generator.generate!(bootstrap_url: "https://request-winner.example")
      assert_match(
        /callback=https%3A%2F%2Frequest-winner\.example/,
        token.token_uri,
        "expected request URL to win over env, got: #{token.token_uri}"
      )
      assert_no_match(/env-loser/, token.token_uri,
                      "env URL should not appear in token_uri")
    ensure
      ENV.delete("BOOTSTRAP_URL")
    end
  end

  test "trailing slash on bootstrap_url is normalised" do
    token = @generator.generate!(bootstrap_url: "https://acme.example/")
    # Should not produce '...example//api/...'
    assert_no_match(%r{example/{2}api}, token.token_uri,
                    "double slash detected in callback URL: #{token.token_uri}")
    assert_match(/callback=https%3A%2F%2Facme\.example%2Fapi%2Fenrollment%2Fconfirm/, token.token_uri)
  end
end
