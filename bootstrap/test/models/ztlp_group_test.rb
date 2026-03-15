# frozen_string_literal: true

require "test_helper"

class ZtlpGroupTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @group = ztlp_groups(:engineering)
  end

  test "valid group" do
    assert @group.valid?
  end

  test "requires name" do
    group = ZtlpGroup.new(network: @network)
    assert_not group.valid?
    assert_includes group.errors[:name], "can't be blank"
  end

  test "name must be unique within network" do
    duplicate = ZtlpGroup.new(name: "engineering", network: @network)
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:name], "has already been taken"
  end

  test "name can be reused across networks" do
    other = ZtlpGroup.new(name: "engineering", network: networks(:production))
    assert other.valid?
  end

  test "belongs to network" do
    assert_equal @network, @group.network
  end

  test "has many members through memberships" do
    assert_includes @group.ztlp_users, ztlp_users(:alice)
    assert_includes @group.ztlp_users, ztlp_users(:bob)
  end

  test "member_count returns correct count" do
    assert_equal 2, @group.member_count
    assert_equal 0, ztlp_groups(:empty_group).member_count
  end

  test "has_member? checks membership" do
    assert @group.has_member?(ztlp_users(:alice))
    assert_not @group.has_member?(ztlp_users(:charlie))
  end

  test "destroying group destroys memberships" do
    assert_difference "GroupMembership.count", -2 do
      @group.destroy
    end
  end

  test "description is optional" do
    group = ZtlpGroup.new(name: "no-desc", network: @network)
    assert group.valid?
  end
end
