# frozen_string_literal: true

# Slice 8a: the Devices directory — read side (spec Slice 8).
#
# GET /devices          index  segmented status filter (?status=), platform
#                       chips, columns name (mono ns_name) / platform / owner
#                       (link) / key source + assurance badge / agent version /
#                       last seen / status. Row -> drawer (show).
# GET /devices/:id      show   identity (node id, pubkey fingerprints, copy
#                       buttons), owner link, Revoke (reason required ->
#                       REVOKE record, status revoked).
#
# Read-only slice: no new NS writes (revoke lands in 8b; assign_owner in 8c).
# No create form: devices come from enrollment redeem (Slice 10) or the
# reconcile import (Slice 12); the page says so, it does not pretend.
require "test_helper"

class DevicesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "invited")
    @laptop = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "secure-enclave",
                                    assurance: 3, status: "enrolled", platform: "macos",
                                    agent_version: "0.35.17", last_seen_at: 20.minutes.ago)
    @server = @zone.devices.create!(name: "fileserver01", user: nil, node_id_hex: "ef" * 16,
                                    noise_pubkey_hex: "aa" * 32, key_source: "file",
                                    assurance: 1, status: "pending", platform: "windows",
                                    agent_version: "0.35.15")
    @laptop1 = @zone.devices.create!(name: "laptop1", user: @alice, node_id_hex: "11" * 16,
                                     noise_pubkey_hex: "22" * 32, key_source: "yubikey",
                                     assurance: 4, status: "revoked", platform: "linux",
                                     agent_version: "0.35.16", last_seen_at: 2.days.ago,
                                     revoked_at: 1.day.ago)
  end

  # ---------------------------------------------------------------- index

  test "index lists devices with name, ns_name, platform, owner, key source + assurance, agent version, last seen and status" do
    get devices_path
    assert_response :success
    body = response.body
    assert_includes body, "alice-mbp"
    assert_includes body, "alice-mbp.test.ztlp"
    assert_includes body, "fileserver01"
    assert_includes body, "laptop1"
    # platform column
    assert_includes body, "macos"
    # owner: alice's name links to her user page (her two devices each); fileserver01 shows the honest empty
    assert_includes body, "Alice Anderson"
    assert_select "a[href=?]", "/users/#{@alice.id}", minimum: 2
    assert_includes body, "Unassigned"
    # key source + assurance: level 3 renders the level-3 label in an ok badge
    assert_includes body, "secure-enclave"
    # level 1 = plain badge (no ok/warn tone), label "unknown"
    assert_select "td .badge:not(.ok):not(.warn):not(.bad)", text: "unknown"
    # level 4 renders "hardware (unverified)"
    assert_includes body, "hardware (unverified)"
    # agent version
    assert_includes body, "0.35.17"
    # last seen: present for the enrolled + revoked rows, honest "never" for pending
    assert_includes body, "never"
    # status badges
    assert_select "span.badge.ok", text: "enrolled"
    assert_select "span.badge.warn", text: "pending"
    assert_select "span.badge.bad", text: "revoked"
  end

  test "index filter segmented links for all/enrolled/pending/revoked" do
    get devices_path
    assert_select ".seg a[href=?][aria-current=page]", "/devices?status=all", true,
                  "the all link must be marked on the unfiltered page"
    %w[enrolled pending revoked].each do |s|
      assert_select ".seg a[href=?]", "/devices?status=#{s}", true,
                    "expected the #{s} filter link"
    end
  end

  test "index status filter narrows rows" do
    get devices_path(status: "enrolled")
    assert_includes response.body, "alice-mbp"
    refute_includes response.body, "fileserver01"
    refute_includes response.body, "laptop1"

    get devices_path(status: "revoked")
    assert_includes response.body, "laptop1"
    refute_includes response.body, "alice-mbp"
  end

  test "index unknown status falls back to all" do
    get devices_path(status: "nonsense")
    assert_includes response.body, "alice-mbp"
    assert_includes response.body, "fileserver01"
  end

  test "index row links to the device page and drawer" do
    get devices_path
    assert_select "tr[data-act=open][data-drawer=?]", "/devices/#{@laptop.id}" do
      assert_select "a[href=?]", "/devices/#{@laptop.id}", minimum: 1
    end
  end

  test "empty state when no devices exist" do
    @zone.devices.destroy_all
    get devices_path
    assert_response :success
    assert_select "tr.empty"
  end

  # ---------------------------------------------------------------- show

  test "show renders identity, owner, assurance and a Revoke form for write admins" do
    get device_path(@laptop)
    assert_response :success
    body = response.body
    # page head
    assert_includes body, "alice-mbp"
    assert_includes body, "alice-mbp.test.ztlp"
    # identity: node id + noise pubkey fingerprints (truncated, not full keys)
    assert_includes body, "ab" * 4
    assert_includes body, "cd" * 4
    # owner links to alice
    assert_select "a[href=?]", user_path(@alice)
    # assurance label with ok tone
    assert_includes body, "device-bound"
    assert_select "span.badge.ok"
    # the revoke form exists and posts to the member route
    assert_select "form[action=?][method=post]", revoke_device_path(@laptop)
    assert_select "form[action=?] input[name=?]", revoke_device_path(@laptop), "reason"
    assert_select "button[type=submit][class*=danger]"
    # copy affordances on the identity values
    assert_select "button[data-act=copy]", minimum: 2
  end

  test "show for a revoked device has no Revoke form and says so" do
    get device_path(@laptop1)
    assert_response :success
    body = response.body
    assert_select "form[action=?]", revoke_device_path(@laptop1), false
    assert_includes body, "Revoked"
  end

  test "show for a device without an owner shows Unassigned and no owner link" do
    get device_path(@server)
    assert_response :success
    assert_includes response.body, "Unassigned"
    assert_select "a[href=?]", user_path(@alice), false
  end

  test "show renders the drawer fragment without layout under X-Drawer: 1" do
    get device_path(@laptop), headers: { "X-Drawer" => "1" }
    assert_response :success
    body = response.body
    assert_includes body, "alice-mbp"
    refute_includes body, "<!DOCTYPE", "the drawer fragment is not a full page"
    refute_includes body, "class=\"rail\"", "the drawer fragment carries no shell chrome"
  end

  test "show 404s for a device in another zone" do
    other = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:23096")
    foreign = other.devices.create!(name: "ghost", node_id_hex: "99" * 16,
                                    noise_pubkey_hex: "88" * 32, status: "pending")
    get device_path(foreign)
    assert_response :not_found
  end

  # ------------------------------------------------------- access control

  test "read_only admin gets 403 on the revoke form endpoint" do
    ro, ro_seed = make_admin(role: "read_only", username: "rory")
    sign_in_as(ro, ro_seed)
    post revoke_device_path(@laptop), params: { reason: "stolen" }
    assert_response :forbidden
    # and the device is untouched
    assert_equal "enrolled", @laptop.reload.status
  end

  # ------------------------------------------------------- revoke (permanent, fail-closed)
  #
  # ONE REVOKE record at revoke.<device ns> listing the device ns name AND its node_id (the NS
  # indexes both; check_revocation refuses any later registration carrying that node_id, so a
  # stolen key cannot re-enroll under a new name). Then the owner's USER record is republished so
  # devices[] drops it (save-and-warn: the revocation itself already happened).

  test "revoke writes one REVOKE with the ns name and node_id, marks revoked, republishes the owner" do
    Ztlp::Publisher.expects(:revoke!)
                   .with { |zone, kw| zone == @zone && kw[:name] == "alice-mbp.test.ztlp" &&
                                      kw[:also] == [ "ab" * 16 ] && kw[:reason] == "stolen" }
                   .returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id }.returns(:ok)
    post revoke_device_path(@laptop), params: { reason: "stolen" }
    assert_equal "revoked", @laptop.reload.status
    refute_nil @laptop.revoked_at
    assert AuditLog.where(action: "device.revoke", status: "ok").any?
  end

  test "revoke requires a reason and changes nothing without one" do
    Ztlp::Publisher.expects(:revoke!).never
    post revoke_device_path(@laptop), params: { reason: "  " }
    assert_response :unprocessable_content
    assert_equal "enrolled", @laptop.reload.status
  end

  test "revoke is fail-closed: an NS refusal changes nothing" do
    Ztlp::Publisher.expects(:revoke!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    Ztlp::Publisher.expects(:publish_user!).never
    post revoke_device_path(@laptop), params: { reason: "stolen" }
    assert_equal "enrolled", @laptop.reload.status
    follow_redirect!
    assert_select "[data-toast]", /NOT revoked.*0x00 no_authority/
  end

  test "revoke still succeeds and warns when only the owner republish fails" do
    Ztlp::Publisher.expects(:revoke!).returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).raises(Ztlp::NsClient::NsError.new(0x0C, "timeout"))
    post revoke_device_path(@laptop), params: { reason: "stolen" }
    assert_equal "revoked", @laptop.reload.status
    follow_redirect!
    assert_select "[data-toast]", /owner.*not republished.*0x0C timeout/i
  end

  test "revoke of an unowned device republishes no user" do
    @server.update!(status: "enrolled")
    Ztlp::Publisher.expects(:revoke!).returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).never
    post revoke_device_path(@server), params: { reason: "decommissioned" }
    assert_equal "revoked", @server.reload.status
  end
end
