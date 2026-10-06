# frozen_string_literal: true

require "test_helper"

class AdminsTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
  end

  test "super_admin adds and edits an administrator" do
    _s, pub = Ztlp::Ed25519.generate
    post admins_path,
         params: { admin: { username: "Dana", display_name: "Dana", email: "d@example.com", role: "helpdesk",
                            pubkey_hex: pub } }
    assert_redirected_to admins_path
    dana = Admin.find_by!(username: "dana")
    assert AuditLog.exists?(action: "admin.created", target_id: dana.id)
    patch admin_path(dana),
          params: { admin: { username: "dana", display_name: "Dana K", role: "admin", disabled: "1" } }
    assert_redirected_to admins_path
    assert dana.reload.disabled?
    assert_equal "admin", dana.role
  end

  test "cannot demote or disable self" do
    patch admin_path(@admin), params: { admin: { username: @admin.username, display_name: "x", role: "admin" } }
    assert_redirected_to edit_admin_path(@admin)
    assert_equal "super_admin", @admin.reload.role
  end

  test "duplicate pubkey rejected" do
    post admins_path,
         params: { admin: { username: "dup", display_name: "Dup", role: "admin", pubkey_hex: @admin.pubkey_hex } }
    assert_response :unprocessable_entity
  end

  test "non-super_admin is forbidden from managing admins" do
    helper, hseed = make_admin(role: "helpdesk", username: "helper")
    reset!
    sign_in_as(helper, hseed)
    get admins_path
    assert_response :success
    get new_admin_path
    assert_response :forbidden
  end
end
