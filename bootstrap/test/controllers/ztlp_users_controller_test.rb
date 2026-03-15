# frozen_string_literal: true

require "test_helper"

class ZtlpUsersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @user = ztlp_users(:alice)
  end

  test "index lists users" do
    get network_ztlp_users_path(@network)
    assert_response :success
    assert_select "table"
    assert_match "alice", response.body
    assert_match "bob", response.body
  end

  test "show displays user details" do
    get network_ztlp_user_path(@network, @user)
    assert_response :success
    assert_match "alice", response.body
    assert_match "admin", response.body
    assert_match "alice@example.com", response.body
  end

  test "show displays linked devices" do
    get network_ztlp_user_path(@network, @user)
    assert_response :success
    assert_match "alice-laptop", response.body
    assert_match "alice-phone", response.body
  end

  test "show displays group memberships" do
    get network_ztlp_user_path(@network, @user)
    assert_response :success
    assert_match "engineering", response.body
    assert_match "ops", response.body
  end

  test "new renders form" do
    get new_network_ztlp_user_path(@network)
    assert_response :success
    assert_select "form"
    assert_select "input[name='ztlp_user[name]']"
    assert_select "select[name='ztlp_user[role]']"
  end

  test "create adds new user" do
    assert_difference "ZtlpUser.count", 1 do
      post network_ztlp_users_path(@network), params: {
        ztlp_user: { name: "frank", role: "tech", email: "frank@example.com" }
      }
    end
    assert_redirected_to network_ztlp_user_path(@network, ZtlpUser.last)
    follow_redirect!
    assert_match "frank", response.body
  end

  test "create with invalid data re-renders form" do
    assert_no_difference "ZtlpUser.count" do
      post network_ztlp_users_path(@network), params: {
        ztlp_user: { name: "", role: "user" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create with duplicate name re-renders form" do
    assert_no_difference "ZtlpUser.count" do
      post network_ztlp_users_path(@network), params: {
        ztlp_user: { name: "alice", role: "user" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create records audit log" do
    assert_difference "AuditLog.count", 1 do
      post network_ztlp_users_path(@network), params: {
        ztlp_user: { name: "audit-test", role: "user" }
      }
    end
    log = AuditLog.last
    assert_equal "ztlp_user_create", log.action
  end

  test "destroy revokes user" do
    assert_equal "active", @user.status
    delete network_ztlp_user_path(@network, @user)
    assert_redirected_to network_ztlp_users_path(@network)
    @user.reload
    assert_equal "revoked", @user.status
    assert_not_nil @user.revoked_at
  end

  test "destroy with custom reason" do
    delete network_ztlp_user_path(@network, @user), params: { reason: "Security concern" }
    @user.reload
    assert_equal "Security concern", @user.revocation_reason
  end

  test "destroy records audit log" do
    assert_difference "AuditLog.count", 1 do
      delete network_ztlp_user_path(@network, @user)
    end
    log = AuditLog.last
    assert_equal "ztlp_user_revoke", log.action
  end

  test "show revoked user displays revocation info" do
    revoked = ztlp_users(:revoked_user)
    get network_ztlp_user_path(@network, revoked)
    assert_response :success
    assert_match "Revoked", response.body
    assert_match "Left the company", response.body
  end
end
