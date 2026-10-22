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
    # a non-member must NOT be listed in the members table (they appear in
    # the Add member select only)
    members_table = response.body[/<h2>Members<\/h2>.*?<\/table>/m]
    refute_includes members_table, "Bob Brown"
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
    # the Members panel ends at the next panel; the add-member form is not a
    # <table>, so an empty group has no members table at all.
    members_panel = response.body[/<h2>Members<\/h2>(?:(?!<h2>).)*$/m]
    assert_includes members_panel, "No members."
    assert_nil members_panel[/<table>/], "an empty group must not render a members table"
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
  end  # ------------------------------------------------ slice 7b: mutations
  #
  # Spec Slice 7: new/create + edit/update + destroy, and add_member /
  # remove_member on the show page. EVERY membership change calls
  # Publisher.publish_group! immediately (spec F13) — rescued per the 6b
  # rule (NS failure -> the DB change stands, a warning toast, never 500).
  # Destroy is blocked while any policy rule references the group and for
  # the default `admins` group.

  # -------------------------------------------------------------- new/create

  test "new renders the group form" do
    get new_group_path
    assert_response :success
    assert_select "form[action=?]", "/groups"
    assert_select "input[name=?]", "group[name]"
    assert_select "input[name=?]", "group[description]"
  end

  test "create persists name/description and publishes the group" do
    @zone.authority_seed_ct = Ztlp::Ed25519.generate.first
    Ztlp::Publisher.expects(:publish_group!)
                   .with { |g, _kw| g.name == "qa" && g.zone == @zone }.returns(:ok)
    post groups_path, params: { group: { name: "QA", description: "Quality gate" } }
    g = @zone.groups.find_by(name: "qa")
    refute_nil g, "name is normalized to lowercase before validation"
    assert_equal "qa.groups.test.ztlp", g.ns_name
    assert_equal "Quality gate", g.description
    assert_redirected_to group_path(g)
    assert AuditLog.where(action: "group.create", status: "ok").any?
  end

  test "create publishes the group with an empty members array when created with no members" do
    Ztlp::Publisher.expects(:publish_group!)
                   .with { |g, _kw| g.name == "qa" && g.users.to_a.empty? }.returns(:ok)
    post groups_path, params: { group: { name: "qa" } }
    assert_response :redirect
  end

  test "create re-renders the form on validation errors without publishing" do
    Ztlp::Publisher.expects(:publish_group!).never
    post groups_path, params: { group: { name: "eng" } }
    assert_response :unprocessable_content
    assert_includes response.body, "name"
    assert_equal 2, @zone.groups.count
  end

  test "create saves and warns when the NS publish fails" do
    Ztlp::Publisher.expects(:publish_group!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    post groups_path, params: { group: { name: "qa" } }
    refute_nil @zone.groups.find_by(name: "qa"), "the DB save stands even when the NS refuses"
    follow_redirect!
    assert_select "[data-toast]", /not published to the name server.*0x00 no_authority/
  end

  # -------------------------------------------------------------- edit/update

  test "edit renders the form for a group" do
    get edit_group_path(@eng)
    assert_response :success
    assert_select "form[action=?]", "/groups/#{@eng.id}"
    assert_select "input[name=?][value=?]", "group[name]", "eng"
  end

  test "update persists description and republishes the group" do
    @zone.authority_seed_ct = Ztlp::Ed25519.generate.first
    Ztlp::Publisher.expects(:publish_group!).times(1).returns(:ok)
    patch group_path(@eng), params: { group: { description: "On-call, rotated" } }
    assert_equal "On-call, rotated", @eng.reload.description
    assert_redirected_to group_path(@eng)
    assert AuditLog.where(action: "group.update", status: "ok").any?
  end

  test "update re-renders the form on a duplicate name without publishing" do
    Ztlp::Publisher.expects(:publish_group!).never
    patch group_path(@eng), params: { group: { name: "hr" } }
    assert_response :unprocessable_content
    assert_equal "eng", @eng.reload.name
  end

  # ------------------------------------------------------ add_member/remove_member

  test "show lists every non-member user in the Add member select" do
    get group_path(@hr)
    assert_response :success
    body = response.body
    assert_includes body, "Add member"
    assert_includes body, "Bob Brown"
    # alice is already in eng, not hr — she is a candidate here too, so the
    # "no candidates" proof is the eng page:
    get group_path(@eng)
    assert_response :success
    add_select = response.body[/<select name="user_id".*?<\/select>/m]
    assert_includes add_select, "Bob Brown"
    refute_includes add_select, "Alice Anderson", "eng already has alice"
  end

  test "add_member adds the user and publishes the group immediately" do
    @zone.authority_seed_ct = Ztlp::Ed25519.generate.first
    Ztlp::Publisher.expects(:publish_group!)
                   .with { |g, _kw| g.name == "hr" && g.users.to_a.map(&:username) == [ "bob" ] }
                   .returns(:ok)
    post add_member_group_path(@hr), params: { user_id: @bob.id }
    assert_equal [ "bob" ], @hr.reload.users.to_a.map(&:username)
    assert_redirected_to group_path(@hr)
    follow_redirect!
    assert_select "[data-toast]", /added to hr/
    assert AuditLog.where(action: "group.add_member", status: "ok").any?
  end

  test "add_member does not publish for a user already in the group" do
    Ztlp::Publisher.expects(:publish_group!).never
    post add_member_group_path(@eng), params: { user_id: @alice.id }
    follow_redirect!
    assert_select "[data-toast]", /already a member/
  end

  test "remove_member removes the user and publishes the group immediately" do
    @zone.authority_seed_ct = Ztlp::Ed25519.generate.first
    Ztlp::Publisher.expects(:publish_group!)
                   .with { |g, _kw| g.name == "eng" && g.users.to_a.empty? }
                   .returns(:ok)
    delete remove_member_group_path(@eng), params: { user_id: @alice.id }
    assert_empty @eng.reload.users.to_a
    assert_redirected_to group_path(@eng)
    assert AuditLog.where(action: "group.remove_member", status: "ok").any?
  end

  test "removing the last member publishes an empty members array" do
    Ztlp::Publisher.expects(:publish_group!) do |g, _kw|
      g.users.to_a.empty? ? Ztlp::Publisher.publish!(g, "group", { "members" => [] }) : nil
    end
    delete remove_member_group_path(@eng), params: { user_id: @alice.id }
    assert_empty @eng.reload.users.to_a, "the last membership is gone"
  end

  test "membership add/remove rescues an NS failure: the save stands, a warning shows" do
    Ztlp::Publisher.expects(:publish_group!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    post add_member_group_path(@hr), params: { user_id: @bob.id }
    assert_equal [ "bob" ], @hr.reload.users.to_a.map(&:username), "the DB change stands"
    follow_redirect!
    assert_select "[data-toast]", /not published to the name server.*0x00 no_authority/
  end

  test "add_member ignores an unknown user id" do
    Ztlp::Publisher.expects(:publish_group!).never
    post add_member_group_path(@hr), params: { user_id: 99_999 }
    assert_empty @hr.users.to_a
    follow_redirect!
    assert_response :success
  end

  # ---------------------------------------------------------------- destroy

  test "destroy deletes the group when nothing references it" do
    post "/groups/#{@hr.id}", params: { _method: :delete }
    refute @zone.groups.exists?(@hr.id)
    assert AuditLog.where(action: "group.destroy", status: "ok").any?
  end

  test "destroy is blocked while a policy rule references the group" do
    gw = @zone.gateways.create!(name: "docs-gw")
    app = gw.applications.create!(name: "docs", backend: "10.0.0.9:80")
    app.policy_rules.create!(subject_type: "group",
                             subject_id: @eng.id, subject_value: "eng.groups.test.ztlp")
    delete group_path(@eng)
    assert @zone.groups.exists?(@eng.id), "the group must survive"
    follow_redirect!
    assert_select "[data-toast]", /referenced by a policy/
  end

  test "destroy is blocked for the default admins group" do
    # the default admins group is created by the claim flow (Slice 3); in a
    # bare test zone it does not exist, so create it the way Claim would.
    admin_user = @zone.users.create!(username: "root-admin", display_name: "Root Admin",
                                     role: "admin", status: "active")
    admins = @zone.groups.create!(name: "admins")
    admins.users << admin_user
    delete group_path(admins)
    assert @zone.groups.exists?(admins.id), "the admins group is permanent"
    follow_redirect!
    assert_select "[data-toast]", /cannot be deleted/
  end

  # ------------------------------------------------------------ access gates

  test "read_only admin gets 403 on every groups mutation" do
    ro, ro_seed = make_admin(role: "read_only", username: "ro7b")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get new_group_path
    assert_response :forbidden
    post groups_path, params: { group: { name: "x1" } }
    assert_response :forbidden
    get edit_group_path(@eng)
    assert_response :forbidden
    patch group_path(@eng), params: { group: { description: "x" } }
    assert_response :forbidden
    post add_member_group_path(@hr), params: { user_id: @bob.id }
    assert_response :forbidden
    delete remove_member_group_path(@eng), params: { user_id: @alice.id }
    assert_response :forbidden
    delete group_path(@hr)
    assert_response :forbidden
    assert_equal [ "eng", "hr" ], @zone.groups.order(:name).pluck(:name)
  end

  test "index New group button uses the new_group_path helper" do
    get groups_path
    assert_select "a.btn.primary[href=?]", new_group_path
  end
end
