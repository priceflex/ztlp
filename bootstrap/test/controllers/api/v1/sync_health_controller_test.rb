# frozen_string_literal: true

require "test_helper"

# Integration tests for /api/v1/sync_health — external-monitoring
# endpoint that exposes Ztlp::SyncState as JSON. Reuses the
# Api::V1::BaseController per-zone HMAC auth scheme (BS-PR-2),
# so a request without valid signed headers returns 401 just like
# every other v1 surface.
#
# Three covered shapes:
#   1. Unauthed → 401
#   2. Authed + success state → 200, status "green"-ish JSON
#   3. Authed + failure state → 200, status "red", error class + next_retry_at populated
class Api::V1::SyncHealthControllerTest < ActionDispatch::IntegrationTest
  ZONE    = "acme.ztlp"
  CLIENT  = "z2ls.acme"
  SECRET  = "0" * 32
  ENV_KEY = "ZTLP_HMAC_SECRET_ACME_ZTLP"

  setup do
    # Per-test tmp file — Rails parallelizes workers above 50 runs so
    # SyncState's global tmp/ztlp_sync_state.json would otherwise race.
    @tmpdir = Dir.mktmpdir("ztlp-api-sync-health")
    @state_path = Pathname.new(File.join(@tmpdir, "ztlp_sync_state.json"))
    Ztlp::SyncState.stubs(:state_file).returns(@state_path)

    @client   = api_clients(:z2ls_acme)
    @prev_env = ENV[ENV_KEY]
    ENV[ENV_KEY] = SECRET
  end

  teardown do
    ENV[ENV_KEY] = @prev_env
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.exist?(@tmpdir)
  end

  test "GET /api/v1/sync_health without auth returns 401" do
    get "/api/v1/sync_health"
    assert_response :unauthorized
  end

  test "GET /api/v1/sync_health with valid HMAC returns 200 + JSON shape (success state)" do
    Ztlp::SyncState.record_success!

    get_signed("/api/v1/sync_health")

    assert_response :ok
    body = JSON.parse(response.body)
    assert_equal "green", body["status"]
    assert body["last_success_at"].present?
    assert_kind_of Integer, body["consecutive_failures"]
    assert_equal 0, body["consecutive_failures"]
    assert_nil body["last_error_class"]
    assert_nil body["next_retry_at"]
  end

  test "GET /api/v1/sync_health reflects failure state (red, error class, next_retry_at)" do
    Ztlp::SyncState.record_failure!(error_class: "TransportError")

    get_signed("/api/v1/sync_health")

    assert_response :ok
    body = JSON.parse(response.body)
    # No last_success_at yet → helper short-circuits to :red.
    assert_equal "red", body["status"]
    assert_equal "TransportError", body["last_error_class"]
    assert_equal 1, body["consecutive_failures"]
    assert body["next_retry_at"].present?
    assert body["last_failure_at"].present?
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
