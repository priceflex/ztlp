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

  # The name drives ns_name; a rename would publish a NEW GROUP record and leave the old one
  # (with its members) live in the NS. Name is immutable after create, like username.
  test "update ignores a submitted name: ns_name and the published record stay the same" do
    published = nil
    Ztlp::Publisher.expects(:publish_group!).with { |g, **| published = g.ns_name; true }.returns(:ok)
    patch group_path(@eng), params: { group: { name: "ops", description: "renamed?" } }
    @eng.reload
    assert_equal "eng", @eng.name
    assert_equal "eng.groups.test.ztlp", @eng.ns_name
    assert_equal "renamed?", @eng.description
    assert_equal "eng.groups.test.ztlp", published
  end

  test "edit shows the name read-only" do
    get edit_group_path(@eng)
    assert_select "input[name=?][readonly]", "group[name]"
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

  # Deleting the DB row alone would leave the GROUP record (and its members) live in the NS with
  # no panel row to fix it. Publish members: [] first; fail closed if the NS refuses.
  test "destroy publishes the group with no members first, then deletes it" do
    published_members = nil
    Ztlp::Publisher.expects(:publish_group!)
                   .with { |g, **| published_members = Ztlp::Records.group_data(g)["members"]; true }.returns(:ok)
    delete group_path(@eng)
    assert_equal [], published_members, "the NS must see an empty group before the row goes"
    refute @zone.groups.exists?(@eng.id)
    assert AuditLog.where(action: "group.destroy", status: "ok").any?
  end

  test "destroy keeps the group when the NS refuses the empty publish" do
    Ztlp::Publisher.expects(:publish_group!).raises(Ztlp::NsClient::NsError.new(0x0C, "timeout"))
    delete group_path(@eng)
    assert @zone.groups.exists?(@eng.id)
    assert_equal [ @alice.id ], @eng.reload.users.map(&:id), "members must be unchanged"
    follow_redirect!
    assert_select "[data-toast]", /NOT deleted.*0x0C timeout/
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

  # ---------------------------------------------------- 9a seam: group references

  # A `group:` policy rule must surface in the Groups directory: the index
  # "Applications" column (7a placeholder "0") and the show page's Policies
  # panel (7a placeholder "No policies"). Rules are matched on the pinned
  # subject_value (ns_name), so a rule whose group row was deleted still
  # counts against the ns_name (stale but honest, per 9a).
  test "index shows the referencing-application count per group" do
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    api = gw.applications.create!(name: "api", backend: "127.0.0.1:8080")
    PolicyRule.create!(application: api, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    get groups_path
    assert_response :success
    rows = []
    assert_select "tbody tr" do |els|
      rows.concat(els)
    end
    eng_row = rows.detect { |el| el.text.include?(@eng.ns_name) }
    hr_row = rows.detect { |el| el.text.include?(@hr.ns_name) }
    refute_nil eng_row, "eng row missing from index"
    refute_nil hr_row, "hr row missing from index"
    assert_equal "1", eng_row.at_css("td.row-apps").text
    assert_equal "0", hr_row.at_css("td.row-apps").text
  end

  test "show lists the applications whose rules reference the group" do
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    api = gw.applications.create!(name: "api")
    dash = gw.applications.create!(name: "dash")
    PolicyRule.create!(application: api, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    PolicyRule.create!(application: dash, subject_type: "role", subject_value: "tech", position: 1)
    get group_path(@eng)
    assert_response :success
    assert_includes response.body, "api.test.ztlp"
    assert_includes response.body, "gw1.test.ztlp"
    refute_includes response.body, "dash.test.ztlp"
    # hr has no referencing rule: the placeholder stands
    get group_path(@hr)
    assert_includes response.body, "No policies reference this group yet."
  end

  test "show drawer fragment includes the referencing applications" do
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    api = gw.applications.create!(name: "api")
    PolicyRule.create!(application: api, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    get group_path(@eng), headers: { "X-Drawer" => "1" }
    assert_response :success
    assert_includes response.body, "api.test.ztlp"
  end

  # The 7a/9a stale-rule contract: a rule whose group row is deleted keeps its
  # pinned subject_value. The show page is keyed on the row (404 when gone);
  # the index must not crash or render a ghost row, and the count text for a
  # stale ns_name must not appear in any group's cell.
  test "index does not crash when a group rule references a deleted group row" do
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    api = gw.applications.create!(name: "api")
    rule = PolicyRule.create!(application: api, subject_type: "group", subject_id: @eng.id,
                              subject_value: @eng.ns_name, position: 1)
    @eng.destroy! # the rule keeps the pinned subject_value (stale but honest)
    get groups_path
    assert_response :success
    # only the hr row remains; its referencing count is 0
    assert_equal 1, assert_select("td.row-apps").size
    assert_equal "0", assert_select("td.row-apps")[0].text
    # no ghost row for the deleted group
    refute_includes response.body, @eng.ns_name
    rule.destroy
  end

  test "destroy is refused while a policy rule references the group" do
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    api = gw.applications.create!(name: "api")
    PolicyRule.create!(application: api, subject_type: "group", subject_id: @hr.id,
                       subject_value: @hr.ns_name, position: 1)
    delete group_path(@hr)
    assert_response :redirect
    follow_redirect!
    assert_response :success
    assert_match /referenced by a policy rule/, response.body
    assert Group.exists?(@hr.id), "the group must survive a refused destroy"
  end
end
