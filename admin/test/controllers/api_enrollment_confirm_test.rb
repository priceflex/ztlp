# frozen_string_literal: true

# Slice 10b sub-slice 4: the LEGACY confirm endpoint (spec §7.4 "Legacy
# clients"): older clients still call the token's legacy `callback_url` shape
# — `POST /api/enrollment/confirm` with a FORM body, UNAUTHENTICATED.
#
# It may NOT enroll (no signed identity). It only:
#   - marks the enrollment `redeemed_unverified` (a NEW status, not
#     `redeemed`: the token has been used by a client whose identity the
#     panel has NOT verified),
#   - creates the DEVICE row as `pending` (an administrator adopts it later;
#     a pending device is NOT published to the NS — the NS stays authoritative
#     over identity and a pending device must not exist there),
#   - does NOT publish anything, does NOT activate the user, does NOT set the
#     user's signing key (none was signed), and NEVER leaks the token.
#
# Same machine-to-machine posture as the signed redeem endpoint: extends
# ActionController::Base directly (no admin session, no tunnel gate),
# skip_forgery_protection (form body, no browser CSRF token), rate-limited by
# rack-attack's `api/ip` throttle (10/min/IP).
require "test_helper"

class ApiEnrollmentConfirmTest < ActionDispatch::IntegrationTest
  CONFIRM_URL = "/enrollment/confirm"

  # The legacy client identifies the token by the human CODE (that is all a
  # form body has — the token_id is inside the token itself, and the code is
  # the human-facing half of it, like the signed redeem path's audit shape).
  def post_confirm(code, **extra)
    post CONFIRM_URL, params: { code: code, device_name: "old-pc" }.merge(extra)
  end

  setup do
    @admin, @admin_seed = make_admin
    sign_in_as(@admin, @admin_seed) # for zone setup only; the endpoint itself is unauthenticated
    @zone = Zone.primary
    @zone.update!(authority_seed_ct: @admin_seed)

    @bob = @zone.users.create!(username: "bob", display_name: "Bob",
                               role: "user", status: "invited")
    @token = @zone.enrollments.create!(
      kind: "user_device", user: @bob, device_name: "old-pc",
      embed_relay_secret: true, max_uses: 1, uses: 0,
      expires_at: 2.hours.from_now, status: "pending",
      code: "KJKQ5PNM", token_id: "dd" * 16, created_by_admin: @admin
    )
  end

  # --------------------------------------------- happy path
  test "legacy confirm marks the enrollment redeemed_unverified and creates a pending device" do
    post_confirm("KJKQ5PNM")
    assert_response :success, "expected 200, got #{response.status}: #{response.body}"
    payload = response.parsed_body
    assert_equal "pending_adoption", payload["status"]
    assert_equal "old-pc.#{@zone.name}", payload["device"]

    @token.reload
    assert_equal "redeemed_unverified", @token.status
    assert_equal 1, @token.uses
    assert @token.redeemed_at.present?

    device = @zone.devices.find_by(name: "old-pc")
    assert device, "device row not created"
    assert_equal "pending", device.status
    assert_equal @bob.id, device.user_id
    assert_equal @token.id, device.enrollment_id
    assert_nil device.node_id_hex
    assert_nil device.signing_pubkey_hex

    # The legacy path must NOT activate the user (identity is unverified).
    assert_equal "invited", @bob.reload.status
  end

  test "the audit row records the code + device, never the token URI" do
    post_confirm("KJKQ5PNM")
    row = AuditLog.order(:id).last
    assert_equal "enrollment.confirm", row.action
    assert_equal "ok", row.status
    details = row.details
    assert_equal "KJKQ5PNM", details["code"]
    assert_equal "old-pc", details["device"]
    assert_equal "bob", details["user"]
    assert_includes row.ip.to_s, "127.0.0.1"
    assert_not_includes row.to_s, "ztlp://enroll"
  end

  # --------------------------------------------- refusions
  test "unknown code is 404" do
    post_confirm("ZZZZZZZZ")
    assert_response :not_found
  end

  test "expired token is refused" do
    @token.update!(status: "expired", expires_at: 1.hour.ago)
    post_confirm("KJKQ5PNM")
    assert_response :unprocessable_entity
    assert_equal "expired", @token.reload.status
    assert_equal 0, @token.uses
    assert_nil @zone.devices.find_by(name: "old-pc")
  end

  test "revoked token is refused" do
    @token.update!(status: "revoked")
    post_confirm("KJKQ5PNM")
    assert_response :unprocessable_entity
    assert_equal 0, @token.uses
  end

  test "a second confirm of a used one-use token is refused (exhausted)" do
    post_confirm("KJKQ5PNM")
    assert_response :success
    post_confirm("KJKQ5PNM")
    assert_response :unprocessable_entity
    assert_equal 1, @token.reload.uses
    assert_equal 1, @zone.devices.where(name: "old-pc").count
  end

  test "missing or blank code is 422 with no row written" do
    # `sign_in_as` (setup) has already written an `auth.login` row, so the
    # honest assertion is "the confirm wrote nothing" (delta 0), not a clean
    # table.
    before = AuditLog.count
    post_confirm(nil)
    assert_response :unprocessable_entity
    assert_equal before, AuditLog.count
    post CONFIRM_URL, params: { code: "   " }
    assert_response :unprocessable_entity
    assert_equal before, AuditLog.count
    assert_equal "pending", @token.reload.status
    assert_equal 0, @token.uses
  end

  test "device name mismatch is refused when the token pins a device name" do
    post_confirm("KJKQ5PNM", device_name: "other-pc")
    assert_response :unprocessable_entity
    assert_equal 0, @token.reload.uses
    assert_nil @zone.devices.find_by(name: "other-pc")
  end

  test "an already-taken device name is refused (no key overwrite, no adoption race)" do
    existing = @zone.devices.create!(name: "old-pc", status: "enrolled",
                                     node_id_hex: SecureRandom.hex(16),
                                     noise_pubkey_hex: SecureRandom.hex(32),
                                     signing_pubkey_hex: SecureRandom.hex(32),
                                     key_source: "unknown", assurance: 1)
    post_confirm("KJKQ5PNM")
    assert_response :conflict
    assert_equal 0, @token.reload.uses
    assert_equal "enrolled", existing.reload.status
  end

  test "device_only enrollment creates an ownerless pending device and does not touch a user" do
    @bare = @zone.enrollments.create!(kind: "device_only", device_name: "kiosk",
                                      embed_relay_secret: true, max_uses: 1, uses: 0,
                                      expires_at: 1.hour.from_now, status: "pending",
                                      code: "MNP52KQR", token_id: "ee" * 16,
                                      created_by_admin: @admin)
    post_confirm("MNP52KQR", device_name: "kiosk")
    assert_response :success
    device = @zone.devices.find_by(name: "kiosk")
    assert_equal "pending", device.status
    assert_nil device.user_id
    assert_equal "redeemed_unverified", @bare.reload.status
  end

  # CSRF must be skipped for this form POST (machine-to-machine, no browser
  # token): prove it with forgery protection turned ON.
  test "works with forgery protection enabled (skip_forgery_protection)" do
    ActionController::Base.allow_forgery_protection = true
    post_confirm("KJKQ5PNM")
    assert_response :success
  ensure
    ActionController::Base.allow_forgery_protection = false
  end
end
