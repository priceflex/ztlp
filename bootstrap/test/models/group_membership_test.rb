# frozen_string_literal: true

require "test_helper"

class GroupMembershipTest < ActiveSupport::TestCase
  setup do
    @membership = group_memberships(:alice_engineering)
  end

  test "valid membership" do
    assert @membership.valid?
  end

  test "belongs to ztlp_group" do
    assert_equal ztlp_groups(:engineering), @membership.ztlp_group
  end

  test "belongs to ztlp_user" do
    assert_equal ztlp_users(:alice), @membership.ztlp_user
  end

  test "user cannot be in same group twice" do
    duplicate = GroupMembership.new(
      ztlp_group: ztlp_groups(:engineering),
      ztlp_user: ztlp_users(:alice)
    )
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:ztlp_user_id], "is already a member of this group"
  end

  test "user can be in multiple groups" do
    # alice is already in engineering and ops
    assert_equal 2, ztlp_users(:alice).group_memberships.count
  end

  test "same user can join different groups" do
    membership = GroupMembership.new(
      ztlp_group: ztlp_groups(:empty_group),
      ztlp_user: ztlp_users(:charlie)
    )
    assert membership.valid?
  end
end
