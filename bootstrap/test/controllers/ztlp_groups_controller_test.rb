# frozen_string_literal: true

require "test_helper"

class ZtlpGroupsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
    @group = ztlp_groups(:engineering)
  end

  test "index lists groups" do
    get network_ztlp_groups_path(@network)
    assert_response :success
    assert_select "table"
    assert_match "engineering", response.body
    assert_match "ops", response.body
  end

  test "index shows member count" do
    get network_ztlp_groups_path(@network)
    assert_response :success
    # engineering has 2 members
    assert_match "2", response.body
  end

  test "show displays group details" do
    get network_ztlp_group_path(@network, @group)
    assert_response :success
    assert_match "engineering", response.body
    assert_match "Engineering team", response.body
  end

  test "show displays members" do
    get network_ztlp_group_path(@network, @group)
    assert_response :success
    assert_match "alice", response.body
    assert_match "bob", response.body
  end

  test "show displays add member form" do
    get network_ztlp_group_path(@network, @group)
    assert_response :success
    # charlie is not a member, should be in the available users dropdown
    assert_match "charlie", response.body
  end

  test "new renders form" do
    get new_network_ztlp_group_path(@network)
    assert_response :success
    assert_select "form"
    assert_select "input[name='ztlp_group[name]']"
  end

  test "create adds new group" do
    assert_difference "ZtlpGroup.count", 1 do
      post network_ztlp_groups_path(@network), params: {
        ztlp_group: { name: "security", description: "Security team" }
      }
    end
    assert_redirected_to network_ztlp_group_path(@network, ZtlpGroup.last)
  end

  test "create with invalid data re-renders form" do
    assert_no_difference "ZtlpGroup.count" do
      post network_ztlp_groups_path(@network), params: {
        ztlp_group: { name: "" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create with duplicate name re-renders form" do
    assert_no_difference "ZtlpGroup.count" do
      post network_ztlp_groups_path(@network), params: {
        ztlp_group: { name: "engineering" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create records audit log" do
    assert_difference "AuditLog.count", 1 do
      post network_ztlp_groups_path(@network), params: {
        ztlp_group: { name: "audit-test" }
      }
    end
    log = AuditLog.last
    assert_equal "ztlp_group_create", log.action
  end

  test "destroy deletes group" do
    assert_difference "ZtlpGroup.count", -1 do
      delete network_ztlp_group_path(@network, @group)
    end
    assert_redirected_to network_ztlp_groups_path(@network)
  end

  test "destroy removes memberships" do
    assert_difference "GroupMembership.count", -2 do
      delete network_ztlp_group_path(@network, @group)
    end
  end

  test "destroy records audit log" do
    assert_difference "AuditLog.count", 1 do
      delete network_ztlp_group_path(@network, @group)
    end
    log = AuditLog.last
    assert_equal "ztlp_group_destroy", log.action
  end

  test "add_member adds user to group" do
    charlie = ztlp_users(:charlie)
    assert_difference "GroupMembership.count", 1 do
      post add_member_network_ztlp_group_path(@network, @group), params: { user_id: charlie.id }
    end
    assert_redirected_to network_ztlp_group_path(@network, @group)
    assert @group.has_member?(charlie)
  end

  test "add_member records audit log" do
    charlie = ztlp_users(:charlie)
    assert_difference "AuditLog.count", 1 do
      post add_member_network_ztlp_group_path(@network, @group), params: { user_id: charlie.id }
    end
    log = AuditLog.last
    assert_equal "ztlp_group_add_member", log.action
  end

  test "add_member prevents duplicate" do
    alice = ztlp_users(:alice)
    assert_no_difference "GroupMembership.count" do
      post add_member_network_ztlp_group_path(@network, @group), params: { user_id: alice.id }
    end
    assert_redirected_to network_ztlp_group_path(@network, @group)
  end

  test "remove_member removes user from group" do
    alice = ztlp_users(:alice)
    assert_difference "GroupMembership.count", -1 do
      delete remove_member_network_ztlp_group_path(@network, @group), params: { user_id: alice.id }
    end
    assert_redirected_to network_ztlp_group_path(@network, @group)
    assert_not @group.has_member?(alice)
  end

  test "remove_member records audit log" do
    alice = ztlp_users(:alice)
    assert_difference "AuditLog.count", 1 do
      delete remove_member_network_ztlp_group_path(@network, @group), params: { user_id: alice.id }
    end
    log = AuditLog.last
    assert_equal "ztlp_group_remove_member", log.action
  end
end
