# frozen_string_literal: true

require "test_helper"

class IdentityControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @alice = ztlp_users(:alice)
    @bob = ztlp_users(:bob)
    @charlie = ztlp_users(:charlie)
    @revoked_user = ztlp_users(:revoked_user)
    @suspended_user = ztlp_users(:suspended_user)
  end

  # === Tab Loading ===

  test "index loads overview tab by default" do
    get identity_network_path(@network)
    assert_response :success
    assert_match "Identity & Access Management", response.body
    assert_match "Active Users", response.body
    assert_match "Enrolled Devices", response.body
    assert_match "Groups", response.body
    assert_match "Revoked", response.body
  end

  test "index loads users tab" do
    get identity_network_path(@network, tab: "users")
    assert_response :success
    assert_match "alice", response.body
    assert_match "bob", response.body
  end

  test "index loads devices tab" do
    get identity_network_path(@network, tab: "devices")
    assert_response :success
    assert_match "alice-laptop", response.body
  end

  test "index loads groups tab" do
    get identity_network_path(@network, tab: "groups")
    assert_response :success
    assert_match "engineering", response.body
    assert_match "ops", response.body
  end

  # === Overview Tab ===

  test "overview shows summary counts" do
    get identity_network_path(@network)
    assert_response :success
    # Verify the page has the summary card structure
    assert_select ".rounded-lg"
  end

  test "overview shows user-device associations" do
    get identity_network_path(@network)
    assert_response :success
    assert_match "User", response.body
    assert_match "alice", response.body
  end

  test "overview shows recent identity activity" do
    AuditLog.record(action: "ztlp_user_create", target: @alice, details: { name: "alice", network: @network.name })
    get identity_network_path(@network)
    assert_response :success
    assert_match "Recent Identity Activity", response.body
  end

  # === Users Tab Filtering ===

  test "users tab filters by role" do
    get identity_network_path(@network, tab: "users", role: "admin")
    assert_response :success
    assert_match "alice", response.body
    assert_no_match(/\bbob\b/, response.body.gsub(/<[^>]+>/, "")) # bob is role:user, shouldn't appear
  end

  test "users tab filters by status" do
    get identity_network_path(@network, tab: "users", status: "revoked")
    assert_response :success
    assert_match "dave", response.body
  end

  test "users tab filters by suspended status" do
    get identity_network_path(@network, tab: "users", status: "suspended")
    assert_response :success
    assert_match "frank", response.body
  end

  test "users tab search by name" do
    get identity_network_path(@network, tab: "users", search: "alice")
    assert_response :success
    assert_match "alice", response.body
  end

  test "users tab search by email" do
    get identity_network_path(@network, tab: "users", search: "bob@example")
    assert_response :success
    assert_match "bob", response.body
  end

  # === Users Tab Sorting ===

  test "users tab sorts by name ascending by default" do
    get identity_network_path(@network, tab: "users")
    assert_response :success
  end

  test "users tab sorts by role" do
    get identity_network_path(@network, tab: "users", sort: "role", dir: "asc")
    assert_response :success
  end

  test "users tab sorts by created_at descending" do
    get identity_network_path(@network, tab: "users", sort: "created_at", dir: "desc")
    assert_response :success
  end

  # === Devices Tab Filtering ===

  test "devices tab filters by status" do
    get identity_network_path(@network, tab: "devices", device_status: "enrolled")
    assert_response :success
    assert_match "alice-laptop", response.body
  end

  test "devices tab filters by owner" do
    get identity_network_path(@network, tab: "devices", owner_id: @alice.id)
    assert_response :success
    assert_match "alice-laptop", response.body
  end

  test "devices tab searches by name" do
    get identity_network_path(@network, tab: "devices", device_search: "laptop")
    assert_response :success
    assert_match "alice-laptop", response.body
  end
end

class ZtlpUsersSuspendReactivateTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @user = ztlp_users(:bob)
  end

  # === Suspend ===

  test "suspend changes user status to suspended" do
    assert_equal "active", @user.status
    post suspend_network_ztlp_user_path(@network, @user)
    assert_redirected_to network_ztlp_user_path(@network, @user)
    @user.reload
    assert_equal "suspended", @user.status
    assert_not_nil @user.suspended_at
  end

  test "suspend records audit log" do
    assert_difference "AuditLog.count", 1 do
      post suspend_network_ztlp_user_path(@network, @user)
    end
    log = AuditLog.last
    assert_equal "ztlp_user_suspend", log.action
  end

  test "suspend shows notice" do
    post suspend_network_ztlp_user_path(@network, @user)
    follow_redirect!
    assert_match "suspended", response.body
  end

  # === Reactivate ===

  test "reactivate changes user from suspended to active" do
    @user.suspend!
    post reactivate_network_ztlp_user_path(@network, @user)
    assert_redirected_to network_ztlp_user_path(@network, @user)
    @user.reload
    assert_equal "active", @user.status
    assert_nil @user.suspended_at
  end

  test "reactivate records audit log" do
    @user.suspend!
    assert_difference "AuditLog.count", 1 do
      post reactivate_network_ztlp_user_path(@network, @user)
    end
    log = AuditLog.last
    assert_equal "ztlp_user_reactivate", log.action
  end

  # === Suspended User Show Page ===

  test "show displays suspended banner" do
    suspended = ztlp_users(:suspended_user)
    get network_ztlp_user_path(@network, suspended)
    assert_response :success
    assert_match "suspended", response.body
    assert_match "Reactivate", response.body
  end
end

class ZtlpUsersCascadeRevokeTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @user = ztlp_users(:alice)
  end

  test "cascade revoke revokes user and all enrolled devices" do
    enrolled_count = @user.ztlp_devices.enrolled.count
    assert enrolled_count > 0, "alice should have enrolled devices for this test"

    post cascade_revoke_network_ztlp_user_path(@network, @user)
    assert_redirected_to network_ztlp_user_path(@network, @user)

    @user.reload
    assert_equal "revoked", @user.status
    assert_not_nil @user.revoked_at

    @user.ztlp_devices.reload.each do |device|
      assert_equal "revoked", device.status, "Device #{device.name} should be revoked"
    end
  end

  test "cascade revoke records audit log" do
    assert_difference "AuditLog.count", 1 do
      post cascade_revoke_network_ztlp_user_path(@network, @user)
    end
    log = AuditLog.last
    assert_equal "ztlp_user_cascade_revoke", log.action
    details = log.parsed_details
    assert details["devices_revoked"] > 0
  end

  test "cascade revoke with custom reason" do
    post cascade_revoke_network_ztlp_user_path(@network, @user), params: { reason: "Security breach" }
    @user.reload
    assert_equal "Security breach", @user.revocation_reason
    @user.ztlp_devices.reload.each do |device|
      assert_match "Security breach", device.revocation_reason
    end
  end
end

class ZtlpUsersUpdateRoleTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @user = ztlp_users(:bob)
  end

  test "update role changes user role" do
    assert_equal "user", @user.role
    patch update_role_network_ztlp_user_path(@network, @user), params: { role: "admin" }
    assert_redirected_to network_ztlp_user_path(@network, @user)
    @user.reload
    assert_equal "admin", @user.role
  end

  test "update role records audit log" do
    assert_difference "AuditLog.count", 1 do
      patch update_role_network_ztlp_user_path(@network, @user), params: { role: "tech" }
    end
    log = AuditLog.last
    assert_equal "ztlp_user_update_role", log.action
  end

  test "update role rejects invalid role" do
    patch update_role_network_ztlp_user_path(@network, @user), params: { role: "superadmin" }
    assert_redirected_to network_ztlp_user_path(@network, @user)
    @user.reload
    assert_equal "user", @user.role # unchanged
  end
end

class ZtlpUsersEnhancedShowTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @alice = ztlp_users(:alice)
  end

  test "show page has avatar and info cards" do
    get network_ztlp_user_path(@network, @alice)
    assert_response :success
    # Avatar initials
    assert_match "AL", response.body
    # Info card sections
    assert_match "Contact Info", response.body
    assert_match "Security", response.body
    assert_match "Access Groups", response.body
  end

  test "show page displays devices section" do
    get network_ztlp_user_path(@network, @alice)
    assert_response :success
    assert_match "alice-laptop", response.body
    assert_match "alice-phone", response.body
  end

  test "show page displays activity timeline section" do
    AuditLog.record(action: "ztlp_user_create", target: @alice, details: { name: "alice" })
    get network_ztlp_user_path(@network, @alice)
    assert_response :success
    assert_match "Activity Timeline", response.body
  end

  test "show page has cascade revoke button for user with devices" do
    get network_ztlp_user_path(@network, @alice)
    assert_response :success
    assert_match "Revoke User &amp; All Devices", response.body
  end

  test "show page has role update form" do
    get network_ztlp_user_path(@network, @alice)
    assert_response :success
    assert_select "select[name='role']"
  end
end
