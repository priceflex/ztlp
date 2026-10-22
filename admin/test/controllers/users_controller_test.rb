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
    assert_includes response.body, ">Service<"
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
    # actions per spec: Edit / Disable / New enrollment. Enable is for disabled users only.
    assert_select "a.btn[href=?]", "/users/#{@alice.id}/edit"
    assert_select "form[action=?]", "/users/#{@alice.id}/disable"
    refute_includes body, "/users/#{@alice.id}/enable"
  end

  test "show of a disabled user offers Enable not Disable" do
    get user_path(@carol)
    assert_response :success
    assert_select "form[action=?]", "/users/#{@carol.id}/enable"
    refute_includes response.body, "/users/#{@carol.id}/disable"
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
end
