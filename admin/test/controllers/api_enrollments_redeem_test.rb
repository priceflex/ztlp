# frozen_string_literal: true

# Slice 10b sub-slice 3: the SIGNED redeem endpoint
#   POST /api/v1/enrollments/:token_id/redeem   (spec §7.4)
#
# A newly-enrolled device (whose agent will not call this yet — that is a
# ZTLP release) POSTs its identity, signed with its fresh Ed25519 key:
#   {node_id, name, noise_pubkey_hex, signing_pubkey_hex, platform,
#    agent_version, timestamp, signature}
#   signature = Ed25519(sha256(canonical JSON of the body WITHOUT signature))
#
# The endpoint is machine-to-machine: it does NOT require the tunnel gateway
# bundle (it is called over the client's ZTLP tunnel, not a browser) and does
# NOT require an administrator session. That is why this controller extends
# ActionController::Base directly (not ApplicationController).
#
# Server validation (spec §7.4): token exists, pending, not expired,
# uses < max_uses, timestamp within ±300 s, signature verifies with
# signing_pubkey_hex. On success: uses += 1, status → redeemed when
# exhausted, create-or-upsert the DEVICE (owner = enrollment user, status
# enrolled), user invited → active, set user signing_pubkey_hex if null,
# audit. Then publish DEVICE + USER to the NS.
#
# The panel's OWN refusal (review 10b-1): a REVOKED token must be refused
# HERE — the NS has no per-token revocation, so the redeem path is where the
# panel's revocation is enforced (the NS still accepts the token until expiry
# or use; that is a separate, honest fact).
#
# Fail-closed (permanent security action): if the NS publish fails, NOTHING
# changes in the panel DB — the exception is raised so the transaction rolls
# back and the device is not shown as enrolled.
#
# NOTE: the body is posted as a JSON Hash (`as: :json`), so the test harness
# serializes it to clean JSON and `request.raw_post` is the canonical wire
# form. A real client's JSON round-trips to the same canonical shape
# Ztlp::Ed25519.deep_sort expects.
require "test_helper"

class ApiEnrollmentsRedeemTest < ActionDispatch::IntegrationTest
  def redeem_url(token)
    "/api/v1/enrollments/#{token.token_id}/redeem"
  end

  # The redeem path publishes DEVICE + USER to the NS. In tests the NS is not
  # running, so the established app-wide pattern stubs at the Publisher level
  # (users/groups/devices tests all do `Ztlp::Publisher.expects(:publish_*)`).
  # The fail-closed test overrides these with `.raises` (stubbed on the
  # specific call it needs) — but since `.expects` replaces the real method,
  # it must be re-stubbed per test. So: re-stub to SUCCEED at the start of
  # each test that reaches the publish step, and to RAISE in the fail-closed
  # test. Mocha stubs are per-test (torn down between tests).
  def stub_publishers!
    Ztlp::Publisher.stubs(:publish_device!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_user!).returns(:ok)
  end

  def post_redeem(token, body, seed)
    msg = Ztlp::Ed25519.claim_message(body) # sha256(canonical JSON)
    signed = body.merge("signature" => Ztlp::Ed25519.sign(seed_hex: seed, message: msg))
    post redeem_url(token), params: signed, as: :json
    signed
  end

  setup do
    # A real administrator whose seed we use for the NS write; the redeem path
    # is not session-gated, but the zone's authority must be configured for the
    # publish step.
    @admin, @admin_seed = make_admin
    sign_in_as(@admin, @admin_seed)
    @zone = Zone.primary
    @zone.update!(authority_seed_ct: @admin_seed)

    @device_seed, @device_pub = Ztlp::Ed25519.generate
    @body = {
      "node_id" => SecureRandom.hex(16),
      "name" => "alice-mbp",
      "noise_pubkey_hex" => SecureRandom.hex(32),
      "signing_pubkey_hex" => @device_pub,
      "platform" => "macos",
      "agent_version" => "0.35.16",
      "timestamp" => Time.current.to_i
    }

    @alice = @zone.users.create!(username: "alice", display_name: "Alice",
                                 role: "user", status: "invited",
                                 signing_pubkey_hex: @device_pub)
    @token = @zone.enrollments.create!(
      kind: "user_device", user: @alice, device_name: "alice-mbp",
      embed_relay_secret: true, max_uses: 1, uses: 0,
      expires_at: 2.hours.from_now, status: "pending",
      code: "ABCDEFGH", token_id: "cc" * 16, created_by_admin: @admin
    )
  end

  # ------------------------------------------------------- happy path
  test "signed redeem enrolls the device, activates the user, marks token redeemed" do
    stub_publishers!
    post_redeem(@token, @body, @device_seed)
    assert_response :success, "expected 200, got #{response.status}: #{response.body}"
    payload = response.parsed_body
    assert_equal "redeemed", payload["status"]
    assert_equal "alice-mbp.#{@zone.name}", payload["device"]
    assert_equal "alice.users.#{@zone.name}", payload["owner"]

    @token.reload
    assert_equal "redeemed", @token.status
    assert_equal 1, @token.uses
    assert @token.redeemed_at.present?

    @alice.reload
    assert_equal "active", @alice.status

    device = @zone.devices.find_by(name: "alice-mbp")
    assert device, "device row not created"
    assert_equal "enrolled", device.status
    assert_equal @alice.id, device.user_id
    assert_equal @token.id, device.enrollment_id
    assert_equal @body["node_id"], device.node_id_hex
    assert_equal @body["noise_pubkey_hex"], device.noise_pubkey_hex
    assert_equal @device_pub, device.signing_pubkey_hex
    assert_equal "macos", device.platform
    assert_equal "0.35.16", device.agent_version
    assert device.enrolled_at.present?

    # The audit row records the device name + token code.
    row = AuditLog.order(:id).last
    assert_equal "enrollment.redeem", row.action
    assert_equal "alice-mbp", row.details["device"]
    assert_equal "ABCDEFGH", row.details["code"]
  end

  test "a second redeem (token exhausted) is refused" do
    stub_publishers!
    post_redeem(@token, @body, @device_seed)
    assert_response :success
    @token.reload
    assert_equal "redeemed", @token.status

    post_redeem(@token, @body, @device_seed)
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s, "exhausted"
  end

  # ---------------------------------------------------------- refusals
  test "an EXPIRED token is refused even with a valid signature" do
    @token.update!(expires_at: 1.hour.ago)
    post_redeem(@token, @body, @device_seed)
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s, "expired"
  end

  test "a REVOKED token is refused (the panel's own refusal — the NS has no per-token revoke)" do
    @token.update!(status: "revoked")
    post_redeem(@token, @body, @device_seed)
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s, "revoked"
  end

  test "an unknown token_id is a 404" do
    post "/api/v1/enrollments/#{SecureRandom.hex(16)}/redeem",
         params: @body.merge("signature" => "00" * 64), as: :json
    assert_response :not_found
  end

  test "a MISSING signature is refused" do
    post redeem_url(@token), params: @body, as: :json
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s.downcase, "signature"
  end

  test "a BAD signature (signed with a different key) is refused" do
    wrong_seed, = Ztlp::Ed25519.generate
    post redeem_url(@token), params: @body.merge(
      "signature" => Ztlp::Ed25519.sign(seed_hex: wrong_seed,
                                        message: Ztlp::Ed25519.claim_message(@body))
    ), as: :json
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s, "Signature does not verify."
    @token.reload
    assert_equal "pending", @token.status # nothing changed
  end

  test "a timestamp outside the ±300 s window is refused" do
    stale = @body.merge("timestamp" => (Time.current - 10.minutes).to_i)
    post redeem_url(@token), params: stale.merge(
      "signature" => Ztlp::Ed25519.sign(seed_hex: @device_seed,
                                        message: Ztlp::Ed25519.claim_message(stale))
    ), as: :json
    assert_response :unprocessable_entity
    assert_includes response.parsed_body["error"].to_s, "stale"
  end

  test "a device_only token (no user) enrolls with no owner" do
    stub_publishers!
    @orphan = @zone.enrollments.create!(
      kind: "device_only", embed_relay_secret: false, max_uses: 1, uses: 0,
      expires_at: 1.hour.from_now, status: "pending",
      code: "MNOPQRST", token_id: "dd" * 16, created_by_admin: @admin
    )
    body = @body.merge("name" => "standalone-box")
    post_redeem(@orphan, body, @device_seed)
    assert_response :success, "expected 200, got #{response.status}: #{response.body}"
    device = @zone.devices.find_by(name: "standalone-box")
    assert device
    assert_nil device.user_id
  end

  # ------------------------------------- fail-closed: NS publish failure
  test "if the NS publish fails, nothing changes in the panel DB (fail-closed)" do
    # Intercept at the NsClient level (the real Publisher path runs its
    # audit + the controller's transaction), so the whole flow is exercised
    # and only the wire write fails.
    Ztlp::NsClient.expects(:register).raises(Ztlp::NsClient::NsError.new(0x05, "unauthorized"))

    # A 500 (not a silent 200) and NO panel change.
    post_redeem(@token, @body, @device_seed)
    assert_response 500
    @token.reload
    assert_equal "pending", @token.status
    assert_equal 0, @token.uses
    assert_nil @zone.devices.find_by(name: "alice-mbp")
  end

  # ------------------------------------------------------- idempotent upsert
  test "redeeming a second token for the same device name upserts the device row" do
    stub_publishers!
    @token2 = @zone.enrollments.create!(
      kind: "user_device", user: @alice, device_name: "alice-mbp",
      embed_relay_secret: false, max_uses: 1, uses: 0,
      expires_at: 1.hour.from_now, status: "pending",
      code: "WXYZ2345", token_id: "ee" * 16, created_by_admin: @admin
    )
    post_redeem(@token, @body, @device_seed)
    assert_response :success
    post_redeem(@token2, @body, @device_seed)
    assert_response :success
    assert_equal 1, @zone.devices.where(name: "alice-mbp").count
  end
end
