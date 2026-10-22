# frozen_string_literal: true

# Slice 7a: Groups read side (spec Slice 7).
#
# GET /groups          index  name, description, member count, applications
#                       referencing it (none yet -- Slice 9); New group button
#                       (gated by write access; the form is Slice 7b).
# GET /groups/:id      show   normal page or drawer fragment under X-Drawer: 1
#                       (same contract as users#show). Description, members
#                       table (display name, username, role, status), and a
#                       read-only "Policies that reference this group" panel
#                       (empty note until Slice 9 builds applications/rules).
#
# Read-only slice: Publisher is never touched here (7b adds the publish_group!
# hook on membership changes).
require "test_helper"

class GroupsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "invited")
    @eng = @zone.groups.create!(name: "eng", description: "Engineering on-call")
    @eng.users << @alice
    @hr = @zone.groups.create!(name: "hr")
  end

  # -------------------------------------------------------------- index

  test "index lists groups with name, ns_name, description, member count and reference count" do
    get groups_path
    assert_response :success
    body = response.body
    assert_includes body, "eng"
    assert_includes body, "eng.groups.test.ztlp"
    assert_includes body, "Engineering on-call"
    assert_includes body, "hr"
    # member counts: eng has 1, hr has 0
    assert_select ".row-members", text: "1"
    assert_select ".row-members", text: "0"
  end

  test "index rows are drawer-linked" do
    get groups_path
    assert_select "tr[data-drawer=?]", group_path(@eng)
  end

  test "index shows a New group button for write admins only" do
    get groups_path
    assert_select "a.btn.primary[href=?]", "/groups/new"

    read_only, ro_seed = make_admin(role: "read_only", username: "rory")
    sign_in_as(read_only, ro_seed)
    get groups_path
    assert_select "a.btn.primary[href=?]", "/groups/new", false
  end

  test "index empty state when no groups" do
    @zone.groups.destroy_all
    get groups_path
    assert_response :success
    assert_includes response.body, "No groups"
  end

  # -------------------------------------------------------------- show

  test "show renders members with user, role and status" do
    get group_path(@eng)
    assert_response :success
    body = response.body
    assert_includes body, "eng.groups.test.ztlp"
    assert_includes body, "Engineering on-call"
    assert_includes body, "Alice Anderson"
    assert_includes body, "alice"
    # her role + status
    assert_includes body, "user"
    assert_includes body, "active"
    # a non-member must NOT be listed
    refute_includes body, "Bob Brown"
  end

  test "show is the drawer fragment under X-Drawer header and a full page otherwise" do
    get group_path(@eng), headers: { "X-Drawer" => "1" }
    assert_response :success
    refute_includes response.body, "<html", "drawer fragment must not carry a layout"
    assert_includes response.body, "Alice Anderson"

    get group_path(@eng)
    assert_response :success
    assert_includes response.body, "<html"
  end

  test "show lists an empty members note for a group with no members" do
    get group_path(@hr)
    assert_response :success
    assert_includes response.body, "No members"
    refute_includes response.body, "Alice Anderson"
  end

  test "show lists policies referencing the group (empty until Slice 9)" do
    get group_path(@eng)
    assert_response :success
    assert_includes response.body, "Policies"
    assert_includes response.body, "No policies"
  end

  test "show 404s for a group in another zone" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:23096")
    stranger = other.groups.create!(name: "eng")
    get group_path(stranger)
    assert_response :not_found
  end
end
