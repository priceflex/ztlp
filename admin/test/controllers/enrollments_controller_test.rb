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

  # --------------------------------------------------------------- create
  #
  # Slice 10b sub-slice 2: POST /enrollments mints the v1 token, stores the
  # URI encrypted at rest (token_uri_ct), redirects to the show-once result
  # page, and stores the human code. The token URI is shown exactly once and
  # is NEVER written to the audit log.
  setup do
    # The zone enrollment secret (64-hex) is the MAC key the minter needs.
    @zone.update!(enrollment_secret_ct: "cd" * 32)
    @zone.relay_addrs = %w[10.0.0.9:23095]
  end

  test "create mints a pending token, stores the encrypted URI, and redirects to the result page" do
    before = @zone.enrollments.count
    post "/enrollments", params: { enrollment: {
      kind: "user_device", user_id: @alice.id, device_name: "alice-mac",
      expiry_hours: "2", embed_relay_secret: "1"
    } }
    assert_response :redirect

    tok = @zone.enrollments.order(:id).last
    assert_equal before + 1, @zone.enrollments.count, "a new enrollment row was created"
    assert_equal "pending", tok.status
    assert_equal "user_device", tok.kind
    assert_equal @alice.id, tok.user_id
    assert_equal "alice-mac", tok.device_name
    assert tok.embed_relay_secret
    assert_equal 1, tok.max_uses
    assert tok.expires_at.present?, "expiry was set from expiry_hours"
    # expiry ≈ 2h from now (allow a few minutes of skew)
    assert_in_delta 2.hours.from_now.to_i, tok.expires_at.to_i, 300
    # the URI is stored encrypted (decrypts to a valid ztlp://enroll/ URI)
    assert tok.token_uri_ct.present?, "token_uri_ct is persisted"
    uri = tok.token_uri_ct
    assert uri.start_with?("ztlp://enroll/"), "stored URI is the enroll URI form"
    # the result page is the redirect target
    assert response.location.include?("/enrollments/#{tok.id}/result"), response.location
    # the human code is assigned
    assert tok.code.match?(/\A[A-Z2-9]{8}\z/), tok.code
  end

  test "create default expiry is 1h and clamps above-24h to 24h" do
    # default (no expiry_hours) → 1h
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "" } }
    assert_response :redirect
    default_tok = @zone.enrollments.order(:id).last
    assert_in_delta 1.hour.from_now.to_i, default_tok.expires_at.to_i, 300,
                    "no expiry_hours → 1h default"

    # above-max → clamped to 24h
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "72" } }
    assert_response :redirect
    clamped = @zone.enrollments.order(:id).last
    assert_in_delta 24.hours.from_now.to_i, clamped.expires_at.to_i, 300,
                    "72h request → clamped to 24h max"
  end

  test "create stores a MAC-valid v1 token whose binary verifies against the zone secret" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    tok = @zone.enrollments.order(:id).last
    bin = Ztlp::TokenMinter.from_uri(tok.token_uri_ct)
    # version byte 0x01, then flags
    assert_equal 0x01, bin.getbyte(0), "v1 token"
    data, mac = bin.byteslice(0, bin.bytesize - 32), bin.byteslice(bin.bytesize - 32, 32)
    secret = [ @zone.enrollment_secret_ct ].pack("H*")
    assert_equal Ztlp::Blake2sHmac.mac(secret, data), mac,
                 "MAC verifies against the zone enrollment secret (NS-accepting token)"
  end

  test "create writes an audit row that does NOT contain the token URI" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    row = AuditLog.where(action: "enrollment.mint").last
    assert row, "an enrollment.mint audit row was written"
    assert_equal "ok", row.status
    details = row.details
    # the token URI must never leak into the audit
    refute details.to_s.include?("ztlp://enroll/"), "audit details must not carry the token"
    # but the human code + user are safe to record
    code = @zone.enrollments.order(:id).last.code
    assert details.to_s.include?(code), "the human code is recorded (safe)"
  end

  test "create is 400 (not 500) when the enrollment params are missing" do
    post "/enrollments", params: {}
    assert_response :unprocessable_entity
  end

  test "create is 400 when a user_device token has no linked user" do
    post "/enrollments", params: { enrollment: { kind: "user_device", user_id: "", expiry_hours: "1" } }
    assert_response :unprocessable_entity
    assert_equal @zone.enrollments.count, @zone.enrollments.count, "no token created"
  end

  test "create is 403 for a read_only admin" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly6")
    delete logout_path
    sign_in_as(ro, ro_seed)
    before = @zone.enrollments.count
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :forbidden
    assert_equal before, @zone.enrollments.count
  end

  # --------------------------------------------------------------- result
  #
  # GET /enrollments/:id/result — the show-once page. It renders the token
  # URI, the QR, and the setup command exactly once; a second GET (and the
  # plain show page) never re-expose the token.

  test "result renders the token URI once, the QR, and the setup command" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    tok = @zone.enrollments.order(:id).last
    follow_redirect!
    assert_response :success
    body = response.body
    assert_includes body, tok.token_uri_ct, "the full token URI is shown"
    assert_match(/ztlp setup --token/, body, "the setup command is copyable")
    assert_match(tok.code, body, "the human code is shown")
    assert_select "#token-qr svg", 1, "the QR is an inline <svg> (CSP-safe, no external img)"
  end

  test "result shows the token on the first request and hides it on the second (exactly once)" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    tok = @zone.enrollments.order(:id).last
    result_url = response.location

    # First request after the mint: the token is exposed.
    get result_url
    assert_response :success
    assert response.body.include?(tok.token_uri_ct), "first request shows the token"

    # Second request: the reveal is consumed — the token is gone (404 or a
    # page that does not carry the URI). It must not re-expose.
    get result_url
    if response.status == 404
      # acceptable: consumed → not found
    else
      refute response.body.include?(tok.token_uri_ct),
             "second request must not re-expose the token"
    end
  end

  test "plain show page never exposes the token URI (result is the only place)" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    tok = @zone.enrollments.order(:id).last
    # fetch the show page directly (not the result)
    get "/enrollments/#{tok.id}"
    assert_response :success
    refute_match(tok.token_uri_ct, response.body, "show must never show the token")
  end

  test "result 404s for a token that was never minted through the panel (no URI stored)" do
    # a fixture token with no token_uri_ct (pre-sub-slice-2 shape)
    bare = @zone.enrollments.create!(kind: "device_only", status: "pending",
                                     code: "ZQXVUTSR", token_id: "ee" * 16)
    get "/enrollments/#{bare.id}/result"
    assert_response :not_found
  end

  # The relay secret rides INSIDE the token (flag 0x08, ZT-01): `ztlp setup` writes it to agent.toml,
  # so the command no longer carries --relay-secret (docs/admin-panel/PLAN-enrollment-token-trust.md).
  test "embed relay secret puts the secret inside the token, not on the command line or in the audit" do
    relay = "Rk3" + "a" * 45
    @zone.update!(relay_secret_ct: relay)
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1", embed_relay_secret: "1" } }
    tok = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(@zone.enrollments.order(:id).last.token_uri_ct))
    assert_equal relay, tok[:relay_secret]
    follow_redirect!
    assert_select "pre.code-box", text: /ztlp setup --token "ztlp:\/\/enroll\/[^"]+"/
    assert_no_match(/--relay-secret/, response.body)
    assert_select "[data-relay-warning]", /inside the token/i
    refute_includes AuditLog.where(action: "enrollment.mint").last.details.to_json, relay
  end

  test "without embed the token has no relay secret" do
    @zone.update!(relay_secret_ct: "Rk3" + "a" * 45)
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    tok = Ztlp::TokenMinter.parse(Ztlp::TokenMinter.from_uri(@zone.enrollments.order(:id).last.token_uri_ct))
    assert_nil tok[:relay_secret]
    follow_redirect!
    assert_no_match(/--relay-secret/, response.body)
  end

  test "embed requested but the zone has no relay secret: say so" do
    @zone.update!(relay_secret_ct: nil)
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1", embed_relay_secret: "1" } }
    follow_redirect!
    assert_no_match(/--relay-secret/, response.body)
    assert_select "[data-relay-warning]", /no relay secret is set/i
  end

  # Shown once means stored never: after the reveal nothing needs the URI (redeem is keyed by token_id).
  test "the token URI is wiped from the database after the one-time reveal" do
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    tok = @zone.enrollments.order(:id).last
    assert tok.token_uri_ct.present?
    follow_redirect!
    assert_nil tok.reload.token_uri_ct
  end
  # ------------------------------------------------- callback_url wiring
  #
  # The 10b-4 follow-up: minted tokens must carry a callback_url pointing at
  # the panel's OWN unauthenticated legacy endpoint (/api/enrollment/confirm)
  # so the CLI's post-enrollment confirmation (ztlp-cli.rs confirm_enrollment)
  # lands on the panel. The token is self-locating (no token_id in the
  # binary; the callback body carries it). The panel's public URL comes from
  # ZTLP_PANEL_PUBLIC_URL (prod: https://admin.trs.ztlp; the local smoke
  # stack uses its own published address). When unset, the controller falls
  # back to request.host_with_port (dev/test host).

  def _parse_callback(bin)
    pos = 2
    zlen = bin.byteslice(pos, 2).unpack1("n"); pos += 2 + zlen
    nlen = bin.byteslice(pos, 2).unpack1("n"); pos += 2 + nlen
    rc = bin.getbyte(pos); pos += 1
    (1..rc).each { |_| _r = bin.byteslice(pos, 2).unpack1("n"); pos += 2 + _r }
    clen = bin.byteslice(pos, 2).unpack1("n"); pos += 2
    [ bin.getbyte(1), bin.byteslice(pos, clen) ]
  end

  def _last_minted_token
    @zone.enrollments.order(:id).last
  end

  test "create embeds the callback_url pointing at the panel legacy endpoint when the public URL is set" do
    ENV["ZTLP_PANEL_PUBLIC_URL"] = "https://admin.trs.ztlp"
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    tok = _last_minted_token
    bin = Ztlp::TokenMinter.from_uri(tok.token_uri_ct)
    flag, cb = _parse_callback(bin)
    assert_equal 0x02, flag, "callback flag set"
    assert_equal "https://admin.trs.ztlp/api/enrollment/confirm", cb
  ensure
    ENV.delete("ZTLP_PANEL_PUBLIC_URL")
  end

  test "create embeds a different public URL host when the env is set to it" do
    ENV["ZTLP_PANEL_PUBLIC_URL"] = "https://panel.example.ztlp"
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    tok = _last_minted_token
    bin = Ztlp::TokenMinter.from_uri(tok.token_uri_ct)
    flag, cb = _parse_callback(bin)
    assert_equal 0x02, flag
    assert_equal "https://panel.example.ztlp/api/enrollment/confirm", cb
  ensure
    ENV.delete("ZTLP_PANEL_PUBLIC_URL")
  end

  test "create falls back to request.host_with_port when the public URL is unset" do
    ENV.delete("ZTLP_PANEL_PUBLIC_URL")
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    tok = _last_minted_token
    bin = Ztlp::TokenMinter.from_uri(tok.token_uri_ct)
    flag, cb = _parse_callback(bin)
    assert_equal 0x02, flag, "callback is always embedded (self-locating token)"
    assert cb.end_with?("/api/enrollment/confirm"), "callback targets the legacy endpoint"
    assert cb.start_with?("http"), "callback is a scheme-qualified absolute URL"
  end

  test "create with a malformed public URL falls back to a scheme-qualified URL" do
    ENV["ZTLP_PANEL_PUBLIC_URL"] = "not a url"
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    assert_response :redirect
    tok = _last_minted_token
    bin = Ztlp::TokenMinter.from_uri(tok.token_uri_ct)
    flag, cb = _parse_callback(bin)
    assert_equal 0x02, flag
    assert_match(%r{\Ahttps?://}, cb, "callback is a scheme-qualified absolute URL")
  ensure
    ENV.delete("ZTLP_PANEL_PUBLIC_URL")
  end

  test "the callback_url is never written to the audit log" do
    ENV["ZTLP_PANEL_PUBLIC_URL"] = "https://admin.trs.ztlp"
    post "/enrollments", params: { enrollment: { kind: "device_only", expiry_hours: "1" } }
    row = AuditLog.where(action: "enrollment.mint").last
    refute row.details.to_s.include?("https://admin.trs.ztlp"),
           "callback URL stays out of the audit"
  ensure
    ENV.delete("ZTLP_PANEL_PUBLIC_URL")
  end
end
