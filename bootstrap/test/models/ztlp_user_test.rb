# frozen_string_literal: true

require "test_helper"

class ZtlpUserTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @user = ztlp_users(:alice)
  end

  test "valid user" do
    assert @user.valid?
  end

  test "requires name" do
    user = ZtlpUser.new(network: @network, role: "user", status: "active")
    assert_not user.valid?
    assert_includes user.errors[:name], "can't be blank"
  end

  test "name must be unique within network" do
    duplicate = ZtlpUser.new(name: "alice", network: @network, role: "user", status: "active")
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:name], "has already been taken"
  end

  test "name can be reused across networks" do
    other = ZtlpUser.new(name: "alice", network: networks(:production), role: "user", status: "active")
    assert other.valid?
  end

  test "validates role inclusion" do
    @user.role = "superadmin"
    assert_not @user.valid?
    assert_includes @user.errors[:role], "is not included in the list"
  end

  test "accepts valid roles" do
    %w[user tech admin].each do |role|
      @user.role = role
      assert @user.valid?, "#{role} should be valid"
    end
  end

  test "validates status inclusion" do
    @user.status = "banned"
    assert_not @user.valid?
    assert_includes @user.errors[:status], "is not included in the list"
  end

  test "accepts valid statuses" do
    %w[active revoked].each do |status|
      @user.status = status
      assert @user.valid?, "#{status} should be valid"
    end
  end

  test "revoke! sets status and timestamp" do
    @user.revoke!(reason: "Testing revocation")
    @user.reload
    assert_equal "revoked", @user.status
    assert_not_nil @user.revoked_at
    assert_equal "Testing revocation", @user.revocation_reason
  end

  test "active? returns true for active users" do
    assert @user.active?
    assert_not @user.revoked?
  end

  test "revoked? returns true for revoked users" do
    revoked = ztlp_users(:revoked_user)
    assert revoked.revoked?
    assert_not revoked.active?
  end

  test "belongs to network" do
    assert_equal @network, @user.network
  end

  test "has many devices" do
    assert_equal 2, @user.ztlp_devices.count
  end

  test "has many groups through memberships" do
    assert_includes @user.ztlp_groups, ztlp_groups(:engineering)
    assert_includes @user.ztlp_groups, ztlp_groups(:ops)
  end

  test "destroying user nullifies device ownership" do
    device = ztlp_devices(:alice_laptop)
    @user.destroy
    device.reload
    assert_nil device.ztlp_user_id
  end

  test "destroying user destroys memberships" do
    assert_difference "GroupMembership.count", -2 do
      @user.destroy
    end
  end

  test "scope active" do
    active = ZtlpUser.active
    assert_includes active, ztlp_users(:alice)
    assert_not_includes active, ztlp_users(:revoked_user)
  end

  test "scope revoked" do
    revoked = ZtlpUser.revoked
    assert_includes revoked, ztlp_users(:revoked_user)
    assert_not_includes revoked, ztlp_users(:alice)
  end
end
