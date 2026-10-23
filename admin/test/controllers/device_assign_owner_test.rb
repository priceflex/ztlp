# frozen_string_literal: true

# Slice 8b: Assign owner (spec Slice 8: "Assign owner select (publishes DEVICE +
# both USERs' devices[])"; the queue note: "assign_owner publishes 3 records in
# order: device, old owner user, new owner user").
#
# Fail-closed: if the NS write for the DEVICE record (the first of the three)
# is refused, NOTHING changes in the DB and the NS state is untouched. After
# the device write stands, the two USER republishes are save-and-warn (the
# ownership change already happened; the 6-hourly republish retries).
require "test_helper"

class DeviceAssignOwnerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "user", status: "active")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob Brown",
                               role: "tech", status: "active")
    @laptop = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "secure-enclave",
                                    assurance: 3, status: "enrolled", platform: "macos")
    @server = @zone.devices.create!(name: "fileserver01", user: nil, node_id_hex: "ef" * 16,
                                    noise_pubkey_hex: "aa" * 32, key_source: "file",
                                    assurance: 1, status: "pending", platform: "windows")
  end

  # --------------------------------------------------------- the form

  test "show renders the Assign owner form for write admins" do
    get device_path(@laptop)
    assert_response :success
    assert_select "form[action=?][method=post]", assign_owner_device_path(@laptop) do
      assert_select "select[name=user_id] option[value=?]", @bob.id, text: /Bob Brown/
    end
    assert_select "button[type=submit]"
  end

  test "show renders no assign form for a revoked device" do
    @laptop.update!(status: "revoked", revoked_at: 1.hour.ago)
    get device_path(@laptop)
    assert_select "form[action=?]", assign_owner_device_path(@laptop), false
  end

  test "show renders no assign form for read_only admins" do
    ro, ro_seed = make_admin(role: "read_only", username: "rory")
    sign_in_as(ro, ro_seed)
    get device_path(@laptop)
    assert_select "form[action=?]", assign_owner_device_path(@laptop), false
  end

  test "show renders no assign form for an unassigned device (no one to own it yet)" do
    get device_path(@server)
    assert_select "form[action=?]", assign_owner_device_path(@server), false
  end

  # -------------------------------------------------------- mutations

  test "assigning an owner publishes the device AND both users' records" do
    # mocha cannot pin cross-expectation order; the contract is: ONE device
    # write + ONE user write per affected user, and the device write happens
    # BEFORE the DB change (pinned by the fail-closed test below).
    Ztlp::Publisher.expects(:publish_device!).with { |d, **| d.id == @laptop.id }.returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @bob.id }.returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id }.returns(:ok)

    post assign_owner_device_path(@laptop), params: { user_id: @bob.id }
    assert_equal @bob, @laptop.reload.user
    assert AuditLog.where(action: "device.assign_owner", status: "ok").any?
    follow_redirect!
    assert_select "[data-toast]", /Owner changed: Alice Anderson.*Bob Brown/
  end

  test "assigning without an owner (unassign) publishes the device and only the old owner user" do
    Ztlp::Publisher.expects(:publish_device!).with { |d, **| d.id == @laptop.id }.returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id }.returns(:ok)

    post assign_owner_device_path(@laptop), params: { user_id: "" }
    assert_nil @laptop.reload.user
  end

  test "assigning the current owner is a no-op (nothing published, nothing changed)" do
    Ztlp::Publisher.expects(:publish_device!).never
    Ztlp::Publisher.expects(:publish_user!).never
    post assign_owner_device_path(@laptop), params: { user_id: @alice.id }
    assert_equal @alice, @laptop.reload.user
    follow_redirect!
    assert_select "[data-toast]", /already the owner/
  end

  test "assigning an unknown user id changes nothing" do
    Ztlp::Publisher.expects(:publish_device!).never
    Ztlp::Publisher.expects(:publish_user!).never
    post assign_owner_device_path(@laptop), params: { user_id: 999_999 }
    assert_equal @alice, @laptop.reload.user
    follow_redirect!
    assert_select "[data-toast]", /No such user/
  end

  test "assign is fail-closed: an NS refusal on the device write changes nothing" do
    Ztlp::Publisher.expects(:publish_device!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    Ztlp::Publisher.expects(:publish_user!).never
    post assign_owner_device_path(@laptop), params: { user_id: @bob.id }
    assert_equal @alice, @laptop.reload.user
    assert AuditLog.where(action: "device.assign_owner", status: "failed").any?
    follow_redirect!
    assert_select "[data-toast]", /NOT reassigned.*0x00 no_authority/
  end

  test "assign still succeeds and warns when a user republish fails after the device write" do
    Ztlp::Publisher.expects(:publish_device!).returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @bob.id }.returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id }.raises(
      Ztlp::NsClient::NsError.new(0x0C, "timeout"))
    post assign_owner_device_path(@laptop), params: { user_id: @bob.id }
    assert_equal @bob, @laptop.reload.user
    follow_redirect!
    assert_select "[data-toast]", /not republished.*0x0C timeout/
  end

  test "read_only admin gets 403 and the device is untouched" do
    ro, ro_seed = make_admin(role: "read_only", username: "rory")
    sign_in_as(ro, ro_seed)
    post assign_owner_device_path(@laptop), params: { user_id: @bob.id }
    assert_response :forbidden
    assert_equal @alice, @laptop.reload.user
  end
end
