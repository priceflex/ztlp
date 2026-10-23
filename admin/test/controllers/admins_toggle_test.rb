# frozen_string_literal: true

# Slice 11d: the administrators page must let a super_admin disable/enable an
# administrator inline (list/disable), not only via the edit form.
require "test_helper"

class AdminsToggleTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
  end

  test "super_admin disables an admin inline and the row reflects it" do
    _s, pub = Ztlp::Ed25519.generate
    dana = Admin.create!(username: "dana", display_name: "Dana", role: "admin", pubkey_hex: pub)
    get admins_path
    assert_response :success
    # The disabled admin's row carries the inline re-enable control.
    assert_includes response.body, "data-admin-toggle=\"#{dana.id}\""

    post toggle_admin_path(dana), params: { disabled: "1" }
    assert_redirected_to admins_path
    assert dana.reload.disabled?
    assert AuditLog.exists?(action: "admin.updated")

    get admins_path
    assert_response :success
    assert_match(/dana[\s\S]*disabled/, response.body)
  end

  test "disabling again is a no-op with no duplicate audit row" do
    _s, pub = Ztlp::Ed25519.generate
    dana = Admin.create!(username: "dana", display_name: "Dana", role: "admin", pubkey_hex: pub)
    post toggle_admin_path(dana), params: { disabled: "1" }
    before = AuditLog.where(action: "admin.updated").count
    post toggle_admin_path(dana), params: { disabled: "1" }
    assert_equal before, AuditLog.where(action: "admin.updated").count
    assert dana.reload.disabled?
  end

  test "re-enable clears disabled_at" do
    _s, pub = Ztlp::Ed25519.generate
    dana = Admin.create!(username: "dana", display_name: "Dana", role: "admin", pubkey_hex: pub)
    dana.update!(disabled_at: Time.current)
    post toggle_admin_path(dana), params: { disabled: "0" }
    assert_redirected_to admins_path
    refute dana.reload.disabled?
  end

  test "a disabled admin cannot sign in" do
    s2, pub = Ztlp::Ed25519.generate
    dana = Admin.create!(username: "dana", display_name: "Dana", role: "admin", pubkey_hex: pub)
    post toggle_admin_path(dana), params: { disabled: "1" }
    reset!
    post auth_challenge_path, params: { pubkey_hex: dana.pubkey_hex }, as: :json
    nonce = response.parsed_body["nonce"]
    assert nonce, "challenge issued for a disabled admin"
    sig = Ztlp::Ed25519.sign(seed_hex: s2, message: Ztlp::Ed25519.login_message(host, nonce))
    post auth_verify_path,
         params: { pubkey_hex: dana.pubkey_hex, nonce: nonce, signature: sig }, as: :json
    assert_response :unauthorized
  end

  test "non-super_admin cannot toggle an admin" do
    _s, pub = Ztlp::Ed25519.generate
    dana = Admin.create!(username: "dana", display_name: "Dana", role: "admin", pubkey_hex: pub)
    helper, hseed = make_admin(role: "helpdesk", username: "helper")
    reset!
    sign_in_as(helper, hseed)
    post toggle_admin_path(dana), params: { disabled: "1" }
    assert_response :forbidden
    refute dana.reload.disabled?
  end

  test "no inline toggle control is rendered for non-super_admins" do
    helper, hseed = make_admin(role: "helpdesk", username: "helper")
    reset!
    sign_in_as(helper, hseed)
    get admins_path
    assert_response :success
    assert_not_includes response.body, "data-admin-toggle"
  end
end
