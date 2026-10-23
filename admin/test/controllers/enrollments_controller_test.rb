# frozen_string_literal: true

# Slice 10b (sub-slice 1): the Enrollments page — read side.
#
# GET /enrollments       list of this zone's enrollment tokens: code, kind,
#                        user, device name, expiry, status, created by/when.
# GET /enrollments/new   the mint form: user pick (existing / new inline /
#                        device only), optional device name, expiry (1h
#                        default, max 24h), embed-relay-secret (default on).
#
# The list renders an HONEST EMPTY STATE until the zone enrollment secret is
# configured — the page never fabricates a mintable state (the "New token"
# button and the explanatory warning are the two surfaces that agree about
# whether minting is possible).
#
# The token URI itself is minted on POST /enrollments (sub-slice 2); this
# file pins only the read side + the form shape.
require "test_helper"

class EnrollmentsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "invited")

    # A redeemed + a pending token for the list. Codes use the unambiguous
    # CODE_ALPHABET (no I/O/0/1, so '1' is never a legal code char).
    @token1 = @zone.enrollments.create!(
      kind: "user_device", user: @alice, device_name: "alice-mbp",
      embed_relay_secret: true, max_uses: 1, uses: 1,
      expires_at: 2.hours.from_now, status: "redeemed",
      code: "ABCDEFGH", token_id: "aa" * 16, created_by_admin: @admin
    )
    @token2 = @zone.enrollments.create!(
      kind: "device_only",
      expires_at: 23.hours.from_now, status: "pending",
      code: "MNOPQRST", token_id: "bb" * 16, created_by_admin: @admin
    )
  end

  # ----------------------------------------------------------------- index

  test "index lists tokens with code, kind, user, device, expiry and status" do
    get "/enrollments"
    assert_response :success
    body = response.body

    assert_includes body, "ABCDEFGH"
    assert_includes body, "MNOPQRST"
    # kind labels
    assert_includes body, "User + device"
    assert_includes body, "Device only"
    # user for the user_device token, none for device_only
    assert_includes body, "Alice Anderson"
    assert_includes body, "alice-mbp"
    # status badges
    assert_select "span.badge.ok", text: "redeemed"
    assert_select "span.badge.warn", text: "pending"
  end

  test "index renders the human code in monospace and an expiry column" do
    get "/enrollments"
    assert_response :success
    assert_match %r{ABCDEFGH}, response.body
    # expiry renders as a human date/time, not a raw epoch
    assert_match %r{\d{4}-\d{2}-\d{2}}, response.body
  end

  test "index shows an honest empty state when the zone has no tokens" do
    @token1.delete
    @token2.delete
    get "/enrollments"
    assert_response :success
    assert_includes response.body, "No enrollment tokens"
  end

  test "index shows the New token button for a write-capable admin" do
    get "/enrollments"
    assert_select "a.btn[href=?]", "/enrollments/new"
  end

  test "index hides the New token button from a read_only admin" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly3")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get "/enrollments"
    assert_response :success
    assert_select "a[href=?]", "/enrollments/new", count: 0
  end

  test "index shows a warning that minting needs the zone enrollment secret" do
    @zone.update!(enrollment_secret_ct: nil)
    get "/enrollments"
    assert_response :success
    assert_includes response.body, "enrollment secret"
    assert_includes response.body, "zone:set_secret"
  end

  # ------------------------------------------------------------------- new

  test "new renders the mint form with every field" do
    get "/enrollments/new"
    assert_response :success
    assert_select "form[action=?]", "/enrollments"
    assert_select "select[name=?]", "enrollment[user_id]"
    assert_select "select[name=?]", "enrollment[kind]"
    assert_select "input[name=?]", "enrollment[device_name]"
    assert_select "select[name=?]", "enrollment[kind]"
    assert_select "input[type=number][name=?]", "enrollment[expiry_hours]", true,
                 "expiry is a number input (1h default, 24h max)"
    assert_select "input[name=?]", "enrollment[embed_relay_secret]"
  end

  test "new defaults embed_relay_secret on" do
    get "/enrollments/new"
    assert_select "input[name=?][checked]", "enrollment[embed_relay_secret]", true,
                 "the relay secret is embedded by default"
  end

  test "new lists existing users as options with a device-only choice" do
    get "/enrollments/new"
    body = response.body
    assert_includes body, "Alice Anderson"
    assert_includes body, "Bob Brown"
    assert_includes body, "Device only"
  end

  test "new is 403 for a read_only admin" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly4")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get "/enrollments/new"
    assert_response :forbidden
  end

  # ------------------------------------------------------------------- nav

  test "rail marks Enrollments current on the enrollments pages" do
    get "/enrollments"
    assert_select ".rail .nav a[aria-current=page]", text: /Enrollments/
  end

  test "signed-out index redirects to login" do
    delete logout_path
    follow_redirect!
    get "/enrollments"
    assert_response :redirect
    assert response.location.include?("/login")
  end

  # ------------------------------------------------------------------- show

  test "show renders the token facts and the revoke affordance for a pending token" do
    get "/enrollments/#{@token2.id}"
    assert_response :success
    body = response.body
    assert_includes body, @token2.code
    assert_includes body, "Device only"
    assert_includes body, "None (device only)"
    assert_includes body, "Not yet (device has not enrolled)"
    assert_select "form[action=?]", "/enrollments/#{@token2.id}/revoke"
    # audit: no row yet (show is read-only)
  end

  test "show of a redeemed token has no revoke affordance" do
    get "/enrollments/#{@token1.id}"
    assert_response :success
    assert_select "form[action=?]", "/enrollments/#{@token1.id}/revoke", count: 0
  end

  # ------------------------------------------------------------------ revoke

  test "revoke flips a pending token to revoked and audits" do
    post "/enrollments/#{@token2.id}/revoke"
    assert_redirected_to "/enrollments"
    assert_equal "revoked", @token2.reload.status
    assert @token2.revoked_at.present?
    assert AuditLog.where(action: "enrollment.revoke", status: "ok").any?
  end

  test "revoke of a redeemed token is a no-op with an alert" do
    post "/enrollments/#{@token1.id}/revoke"
    assert_redirected_to "/enrollments/#{@token1.id}"
    assert_equal "redeemed", @token1.reload.status
    follow_redirect!
    assert_select "[data-toast]", /Only pending tokens/
  end

  test "revoke is 403 for a read_only admin" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly5")
    delete logout_path
    sign_in_as(ro, ro_seed)
    post "/enrollments/#{@token2.id}/revoke"
    assert_response :forbidden
    assert_equal "pending", @token2.reload.status
  end

  # The audit helper takes **details; a `details: {}` kwarg used to land under details.details.
  test "revoke audit stores the code at the top level of details (no double nesting)" do
    post "/enrollments/#{@token2.id}/revoke"
    row = AuditLog.where(action: "enrollment.revoke").last
    assert_equal @token2.code, row.details["code"], row.details.inspect
    refute row.details.key?("details"), row.details.inspect
  end

  # Today a device enrolls straight against the NS (ztlp setup --token -> NS process_enroll), which
  # validates the MAC/expiry/uses only: a panel revoke cannot stop that. Say so, never overclaim.
  test "revoke tells the truth about the name server" do
    get "/enrollments/#{@token2.id}"
    assert_select "form[action=?][data-confirm]", "/enrollments/#{@token2.id}/revoke" do |forms|
      assert_match(/name server still accepts it until it expires/i, forms.first["data-confirm"])
    end
    refute_match(/can no longer be redeemed/i, response.body)
    post "/enrollments/#{@token2.id}/revoke"
    follow_redirect!
    assert_select "[data-toast]", /name server still accepts it until it expires/i
  end
end
