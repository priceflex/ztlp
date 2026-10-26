# frozen_string_literal: true

# Slice 6a: the Users directory (spec Slice 6, §2.1 routes).
#
# GET /users            index  segmented status filter (?status=), server-side
#                       search (?q=), columns name/kind/role/groups/devices/status
# GET /users/:id        show   drawer fragment under X-Drawer: 1 (no layout),
#                       normal page otherwise; profile fields, groups with
#                       remove, devices owned with assurance badge, actions.
#
# create/edit/disable/enable are later sub-slices (6b); this file pins the
# read side + nav. Publisher is never touched here (read-only pages).
require "test_helper"

class UsersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active", email: "alice@example.com")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "invited")
    @carol = @zone.users.create!(username: "carol", display_name: "Carol Cline",
                                 role: "user", status: "disabled")
    @eng = @zone.groups.create!(name: "eng", description: "Engineering")
    @eng.users << @alice
    @device = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "secure-enclave",
                                    assurance: 3, status: "enrolled")
    @pending = @zone.devices.create!(name: "bob-pc", user: @bob, node_id_hex: "ef" * 16,
                                     noise_pubkey_hex: "aa" * 32, status: "pending")
  end

  # ---------------------------------------------------------------- index

  test "index lists users with name, username, kind, role, groups, devices and status" do
    get users_path
    assert_response :success
    body = response.body
    assert_includes body, "Alice Anderson"
    assert_includes body, "alice.users.test.ztlp"
    assert_includes body, "Bob Brown"
    assert_includes body, "Carol Cline"
    # groups chip on alice's row
    assert_includes body, ">eng<"
    # device count for alice (her enrolled device) vs bob (pending does not count)
    assert_select ".row-devices", texts: [ "1", "0" ]
    # status badges
    assert_select "span.badge.ok", text: "active"
    assert_select "span.badge.warn", text: "invited"
    assert_select "span.badge.bad", text: "disabled"
  end

  test "index filter segmented links for all/active/invited/disabled/revoked" do
    get users_path
    assert_select ".seg a[href=?][aria-current=page]", "/users?status=all", true,
                  "the all link must be marked on the unfiltered page"
    %w[active invited disabled revoked].each do |s|
      assert_select ".seg a[href=?]", "/users?status=#{s}", true,
                    "expected the #{s} filter link"
    end
  end

  test "index status filter narrows rows" do
    get users_path(status: "active")
    assert_includes response.body, "Alice Anderson"
    refute_includes response.body, "Bob Brown"
    refute_includes response.body, "Carol Cline"

    get users_path(status: "disabled")
    assert_includes response.body, "Carol Cline"
    refute_includes response.body, "Alice Anderson"
  end

  test "index search filters server-side by name username and email" do
    get users_path(q: "bob")
    assert_includes response.body, "Bob Brown"
    refute_includes response.body, "Alice Anderson"

    # deterministic-encrypted email cannot be ILIKE'd; exact match only
    get users_path(q: "alice@example.com")
    assert_includes response.body, "Alice Anderson"
    refute_includes response.body, "Bob Brown"

    # email is encrypted: substring search cannot reach it (substring match
    # would need the plaintext in the clear); an exact full-address query can.
    get users_path(q: "alice@")
    refute_includes response.body, "Alice Anderson"
  end

  test "index kind column shows service users" do
    @zone.users.create!(username: "backup", display_name: "Backup service", kind: "service",
                        role: "user", status: "active")
    get users_path
    assert_includes response.body, "Backup service"
    assert_includes response.body, ">Service account<"
  end

  test "index search is escaped and unknown status falls back to all" do
    get users_path(q: "<script>alert(1)</script>")
    assert_response :success
    refute_includes response.body, "<script>alert(1)"
    assert_includes response.body, "&lt;script&gt;"

    get users_path(status: "nonsense")
    assert_includes response.body, "Alice Anderson"
    assert_includes response.body, "Bob Brown"
  end

  test "index row links to the user page and drawer" do
    get users_path
    assert_select "tr[data-act=open][data-drawer=?]", "/users/#{@alice.id}" do
      assert_select "a[href=?]", "/users/#{@alice.id}", minimum: 1
    end
  end

  test "empty state when nothing matches" do
    get users_path(q: "zzzznothing")
    assert_response :success
    assert_includes response.body, "No users match"
  end

  # ----------------------------------------------------------------- show

  test "show renders profile fields groups devices and actions" do
    get user_path(@alice)
    assert_response :success
    body = response.body
    assert_includes body, "Alice Anderson"
    assert_includes body, "alice.users.test.ztlp"
    assert_includes body, "alice@example.com"
    # group with remove affordance + device row with assurance badge
    assert_includes body, "eng"
    assert_includes body, "alice-mbp"
    assert_includes body, "device-bound"
    # actions: Edit, reversible Disable (PLAN-services-wizard-and-helpdesk.md slice 3) and the
    # permanent Revoke user (operator decision 2026-10-22); Enable only once disabled.
    assert_select "a.btn[href=?]", "/users/#{@alice.id}/edit"
    assert_select "form[action=?]", "/users/#{@alice.id}/revoke"
    assert_select "form[action=?]", "/users/#{@alice.id}/disable"
    refute_includes body, "/users/#{@alice.id}/enable"
  end

  test "show of a legacy disabled user (NS-revoked by the old Disable) offers Revoke, never Enable" do
    AuditLog.record!("ns.publish", target: @carol, status: "ok", details: { "name" => @carol.ns_name, "type" => "revoke" })
    get user_path(@carol)
    assert_response :success
    assert_select "form[action=?]", "/users/#{@carol.id}/revoke"
    refute_includes response.body, "/users/#{@carol.id}/enable"
  end

  test "show with X-Drawer renders the fragment without the layout shell" do
    get user_path(@alice), headers: { "X-Drawer" => "1" }
    assert_response :success
    body = response.body
    assert_includes body, "Alice Anderson"
    refute_includes body, 'class="rail"', "drawer fragment must not carry the rail shell"
    refute_includes body, "<!DOCTYPE html>"
  end

  test "show of a user with no email or devices renders cleanly" do
    lone = @zone.users.create!(username: "lone", role: "user", status: "invited")
    get user_path(lone)
    assert_response :success
    assert_includes response.body, "No devices"
  end

  # ------------------------------------------------------------------ nav

  test "rail marks Users current on the users pages" do
    get users_path
    assert_select ".rail .nav a[aria-current=page]", text: /Users/
  end

  test "signed-out index redirects to login" do
    delete logout_path
    follow_redirect!
    get users_path
    assert_response :redirect
    assert response.location.include?("/login")
  end

  test "index shows a New user button for a write-capable admin" do
    get users_path
    assert_select "a.btn[href=?]", new_user_path
  end

  test "index hides the New user button from a read_only admin" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly3")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get users_path
    assert_response :success
    assert_select "a[href=?]", new_user_path, count: 0
  end

  # -------------------------------------------------------- slice 6b: create
  #
  # Spec decision 2 (§14): publish a USER record on `active` only. A newly
  # created user is `invited`, so create never publishes. `Ztlp::Publisher`
  # is stubbed on every create/edit test so the controller cannot reach the
  # NS; the assertion that it was (or was not) called is the contract.

  test "new renders a form with the user fields" do
    get new_user_path
    assert_response :success
    assert_select "form[action=?]", "/users"
    assert_select "input[name=?]", "user[username]"
    assert_select "input[name=?]", "user[display_name]"
    assert_select "input[name=?]", "user[email]"
    assert_select "select[name=?]", "user[role]"
    assert_select "select[name=?]", "user[kind]"
    assert_select "textarea[name=?]", "user[notes]"
  end

  test "create builds an invited user with normalized username and no publish" do
    # invited => no publish (spec decision 2)
    Ztlp::Publisher.expects(:publish_user!).never
    post users_path, params: { user: { username: "Dave", display_name: "Dave Dee",
                                       first_name: "Dave", last_name: "Dee",
                                       email: "dave@example.com", role: "tech",
                                       kind: "person", notes: "new hire" } }
    dave = @zone.users.find_by(username: "dave")
    assert dave, "user should be created"
    assert_equal "invited", dave.status
    assert_equal "dave.users.test.ztlp", dave.ns_name
    assert_equal "tech", dave.role
    assert_equal "new hire", dave.notes
    assert_equal "dave@example.com", dave.email
    follow_redirect!
    assert_response :success
    # audit row recorded
    assert AuditLog.where(action: "user.create", status: "ok").any?
  end

  test "create always yields an invited user, even if an active status is submitted" do
    # Spec: a new user is always invited; `status` is not a form field. So
    # create never publishes even when the form claims `active`.
    Ztlp::Publisher.expects(:publish_user!).never
    post users_path, params: { user: { username: "evan", display_name: "Evan",
                                       role: "user", kind: "person", status: "active" } }
    evan = @zone.users.find_by(username: "evan")
    assert evan
    assert_equal "invited", evan.status
    follow_redirect!
    assert_response :success
  end

  test "create rejects an invalid username and re-renders the form with errors" do
    Ztlp::Publisher.expects(:publish_user!).never
    post users_path, params: { user: { username: "UPPER_bad", role: "user", kind: "person" } }
    assert_response :unprocessable_content
    assert_equal 0, @zone.users.where(username: "upper_bad").count
    assert_includes response.body, "lowercase DNS label"
  end

  test "create rejects a duplicate username in the zone" do
    Ztlp::Publisher.expects(:publish_user!).never
    post users_path, params: { user: { username: "alice", role: "user", kind: "person" } }
    assert_response :unprocessable_content
    # one alice already exists; not two
    assert_equal 1, @zone.users.where(username: "alice").count
    assert_includes response.body, "taken"
  end

  test "read_only admin gets 403 on create and new" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get new_user_path
    assert_response :forbidden
    post users_path, params: { user: { username: "frank", role: "user", kind: "person" } }
    assert_response :forbidden
    assert_nil @zone.users.find_by(username: "frank")
  end

  # --------------------------------------------------------- slice 6b: edit

  test "edit renders the existing user's fields and a locked username" do
    get edit_user_path(@alice)
    assert_response :success
    body = response.body
    assert_select "form[action=?]", "/users/#{@alice.id}"
    assert_select "input[name=?][value=?]", "user[username]", "alice"
    assert_select "input[name=?][readonly]", "user[username]", true,
                  "username is immutable after create"
    assert_select "input[name=?][value=?]", "user[email]", "alice@example.com"
  end

  test "update persists changed fields and ignores the submitted username" do
    # alice is active => republish on save
    @zone.authority_seed_ct = Ztlp::Ed25519.generate.first
    Ztlp::Publisher.expects(:publish_user!).times(1).returns(:ok)
    patch user_path(@alice), params: { user: { username: "EVE", display_name: "Alice A.",
                                               email: "alice2@example.com", role: "admin",
                                               notes: "promoted" } }
    @alice.reload
    assert_equal "alice", @alice.username, "username must not change"
    assert_equal "Alice A.", @alice.display_name
    assert_equal "alice2@example.com", @alice.email
    assert_equal "admin", @alice.role
    assert_equal "promoted", @alice.notes
    follow_redirect!
    assert_response :success
    assert AuditLog.where(action: "user.update", status: "ok").any?
  end

  # The DB change is the source of truth; an NS failure (no authority imported yet, NS down,
  # rate limit) must not 500 after the save. The 6-hourly RepublishNsJob retries.
  test "update of an active user still saves and warns when the NS publish fails" do
    Ztlp::Publisher.expects(:publish_user!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    patch user_path(@alice), params: { user: { display_name: "Alice NS-down" } }
    assert_redirected_to user_path(@alice)
    assert_equal "Alice NS-down", @alice.reload.display_name
    follow_redirect!
    assert_select "[data-toast]", /not published to the name server.*0x00 no_authority/
  end

  test "update of a non-active user does not publish" do
    # bob is invited
    Ztlp::Publisher.expects(:publish_user!).never
    patch user_path(@bob), params: { user: { display_name: "Bob B.", role: "tech" } }
    @bob.reload
    assert_equal "Bob B.", @bob.display_name
  end

  test "update validates and re-renders on a bad role" do
    Ztlp::Publisher.expects(:publish_user!).never
    patch user_path(@bob), params: { user: { role: "wizard" } }
    assert_response :unprocessable_content
    assert_includes response.body, "role"
    assert_equal "tech", @bob.reload.role
  end

  test "read_only admin gets 403 on edit and update" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly2")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get edit_user_path(@alice)
    assert_response :forbidden
    patch user_path(@alice), params: { user: { display_name: "X" } }
    assert_response :forbidden
    assert_equal "Alice Anderson", @alice.reload.display_name
  end

  # ------------------------------------------------------ slice 6c: revoke
  #
  # Operator decision 2026-10-22: "Disable" is a PERMANENT "Revoke user". In the NS a
  # revocation can never be lifted (server.ex step 7 "revoked entities cannot re-register";
  # nothing deletes from ztlp_ns_revoked), so there is no Enable. ONE REVOKE record lists
  # the user AND every enrolled device ns name (the gateway does not cascade owner→device).
  # It is a security action: if the NS write fails, NOTHING changes in the DB (the panel must
  # never say "revoked" while access continues; the republish job never retries a revoke).

  test "revoke writes ONE REVOKE for the user plus every enrolled device and marks them revoked" do
    Ztlp::Publisher.expects(:revoke!)
                   .with { |zone, kw| zone == @zone && kw[:name] == "alice.users.test.ztlp" &&
                                      kw[:also] == [ "alice-mbp.test.ztlp", @alice.devices.first.node_id_hex ] &&
                                      kw[:target].id == @alice.id }
                   .returns(:ok)
    post revoke_user_path(@alice)
    assert_equal "revoked", @alice.reload.status
    assert_equal [ "revoked" ], @alice.devices.reload.map(&:status)
    refute_nil @alice.devices.first.revoked_at
    follow_redirect!
    assert_select "[data-toast]", /revoked.*1 device/
    assert AuditLog.where(action: "user.revoke", status: "ok").any?
  end

  test "pending devices are not listed in the REVOKE and stay pending" do
    Ztlp::Publisher.expects(:revoke!).with { |_z, kw| kw[:also] == [] }.returns(:ok)
    post revoke_user_path(@bob) # bob has only a pending device
    assert_equal "revoked", @bob.reload.status
    assert_equal [ "pending" ], @bob.devices.reload.map(&:status)
  end

  test "when the NS revoke fails nothing changes and the admin is told" do
    Ztlp::Publisher.expects(:revoke!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    post revoke_user_path(@alice)
    assert_redirected_to user_path(@alice)
    assert_equal "active", @alice.reload.status, "panel must not claim a revocation the NS did not accept"
    assert_equal [ "enrolled" ], @alice.devices.reload.map(&:status)
    follow_redirect!
    assert_select "[data-toast]", /NOT revoked.*0x00 no_authority/
    assert AuditLog.where(action: "user.revoke", status: "failed").any?
  end

  test "revoking an already-revoked user is refused without a second REVOKE" do
    @alice.update!(status: "revoked")
    Ztlp::Publisher.expects(:revoke!).never
    post revoke_user_path(@alice)
    follow_redirect!
    assert_select "[data-toast]", /already revoked/
  end

  test "enable refuses a legacy disabled user whose name the old Disable revoked on the NS" do
    AuditLog.record!("ns.publish", target: @carol, status: "ok", details: { "name" => @carol.ns_name, "type" => "revoke" })
    Ztlp::Publisher.expects(:publish_user!).never
    post enable_user_path(@carol)
    assert_equal "disabled", @carol.reload.status
    follow_redirect!
    assert_select "[data-toast]", /permanent/
  end

  test "read_only admin gets 403 on revoke" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly4")
    delete logout_path
    sign_in_as(ro, ro_seed)
    Ztlp::Publisher.expects(:revoke!).never
    post revoke_user_path(@alice)
    assert_response :forbidden
    assert_equal "active", @alice.reload.status
  end

  test "show offers a permanent Revoke with a confirm naming the device count; none once revoked" do
    get user_path(@alice)
    assert_select "form[action=?] button[data-confirm]", revoke_user_path(@alice) do |b|
      assert_match(/permanent/i, b.first["data-confirm"])
      assert_match(/1 device/, b.first["data-confirm"])
    end
    assert_select "form[action$='/enable']", 0
    @alice.update!(status: "revoked")
    get user_path(@alice)
    assert_select "form[action=?]", revoke_user_path(@alice), 0
    assert_select ".actions", /Revoked permanently/
  end
end
