# frozen_string_literal: true

# Slice 3 of PLAN-services-wizard-and-helpdesk.md: reversible Disable / Enable for users and
# devices (helpdesk may do it), next to the permanent Revoke (operators only). "Add device" on
# the Devices page.
#
# Disable is a DB status change, then a save-and-warn republish so the name server stops
# vouching for the subject (USER role "" + no devices, GROUP members without them, DEVICE owner "").
# An NS failure never 500s and never rolls the DB back: the 6-hourly republish retries.
require "test_helper"

class UserDeviceLifecycleTest < ActionDispatch::IntegrationTest
  setup do
    @zone = Zone.primary
    @alice = @zone.users.create!(username: "alice", display_name: "Alice", status: "active")
    @staff = @zone.groups.create!(name: "staff")
    @staff.group_memberships.create!(user: @alice)
    @pc = @zone.devices.create!(name: "alice-pc", ns_name: "alice-pc.#{@zone.name}", status: "enrolled", user: @alice)
    @pending = @zone.devices.create!(name: "new-pc", status: "pending", user: @alice)
  end

  def as(role)
    admin, seed = make_admin(role: role, username: "#{role.tr('_', '-')}-1")
    sign_in_as(admin, seed)
    admin
  end

  # ------------------------------------------------------------------ users

  test "helpdesk disables a user; the NS is told about the user, their groups and devices" do
    as("helpdesk")
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id && u.status == "disabled" }.returns(:ok)
    Ztlp::Publisher.expects(:publish_group!).with { |g, **| g.id == @staff.id }.returns(:ok)
    Ztlp::Publisher.expects(:publish_device!).with { |d, **| d.id == @pc.id }.returns(:ok)

    post disable_user_path(@alice)
    assert_redirected_to user_path(@alice)
    assert_equal "disabled", @alice.reload.status
    assert AuditLog.exists?(action: "user.disable", target_type: "User", target_id: @alice.id)
  end

  test "enabling a user with an enrolled device makes them active again" do
    @alice.update!(status: "disabled")
    as("helpdesk")
    Ztlp::Publisher.stubs(:publish_user!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_group!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_device!).returns(:ok)
    post enable_user_path(@alice)
    assert_equal "active", @alice.reload.status
    assert AuditLog.exists?(action: "user.enable", target_id: @alice.id)
  end

  test "enabling a user who never enrolled a device puts them back to invited" do
    bob = @zone.users.create!(username: "bob", display_name: "Bob", status: "disabled")
    as("admin")
    Ztlp::Publisher.stubs(:publish_user!).returns(:ok)
    post enable_user_path(bob)
    assert_equal "invited", bob.reload.status
  end

  test "a revoked user cannot be disabled or enabled" do
    @alice.update!(status: "revoked")
    as("admin")
    post enable_user_path(@alice)
    assert_equal "revoked", @alice.reload.status
    post disable_user_path(@alice)
    assert_equal "revoked", @alice.reload.status
  end

  test "an NS failure on disable keeps the DB change and warns instead of erroring" do
    as("helpdesk")
    Ztlp::Publisher.stubs(:publish_user!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    Ztlp::Publisher.stubs(:publish_group!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    Ztlp::Publisher.stubs(:publish_device!).raises(Ztlp::NsClient::NsError.new(0x00, "no_authority"))
    post disable_user_path(@alice)
    assert_redirected_to user_path(@alice)
    assert_equal "disabled", @alice.reload.status
    follow_redirect!
    assert_match(/not published to the name server/, response.body)
  end

  test "read_only cannot disable" do
    as("read_only")
    post disable_user_path(@alice)
    assert_response :forbidden
    assert_equal "active", @alice.reload.status
  end

  test "the user page shows Disable with what it does, and Enable once disabled" do
    as("helpdesk")
    get user_path(@alice)
    assert_select "form[action='#{disable_user_path(@alice)}'] button", text: /Disable/
    assert_match(/Disable is reversible/, response.body)
    @alice.update!(status: "disabled")
    get user_path(@alice)
    assert_select "form[action='#{enable_user_path(@alice)}'] button", text: /Enable/
    assert_select "form[action='#{disable_user_path(@alice)}']", false
  end

  # ------------------------------------------------------------------ devices

  test "helpdesk disables an enrolled device and the NS drops it" do
    as("helpdesk")
    Ztlp::Publisher.expects(:publish_device!).with { |d, **| d.id == @pc.id && d.status == "disabled" }.returns(:ok)
    Ztlp::Publisher.expects(:publish_user!).with { |u, **| u.id == @alice.id }.returns(:ok)
    post disable_device_path(@pc)
    assert_redirected_to device_path(@pc)
    assert_equal "disabled", @pc.reload.status
    assert AuditLog.exists?(action: "device.disable", target_id: @pc.id)
  end

  test "enable puts a disabled device back to enrolled" do
    @pc.update!(status: "disabled")
    as("helpdesk")
    Ztlp::Publisher.stubs(:publish_device!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_user!).returns(:ok)
    post enable_device_path(@pc)
    assert_equal "enrolled", @pc.reload.status
    assert AuditLog.exists?(action: "device.enable", target_id: @pc.id)
  end

  test "pending and revoked devices cannot be disabled" do
    as("admin")
    post disable_device_path(@pending)
    assert_equal "pending", @pending.reload.status
    @pc.update!(status: "revoked")
    post disable_device_path(@pc)
    assert_equal "revoked", @pc.reload.status
  end

  test "the device page shows Disable / Enable" do
    as("helpdesk")
    get device_path(@pc)
    assert_select "form[action='#{disable_device_path(@pc)}'] button", text: /Disable/
    @pc.update!(status: "disabled")
    get device_path(@pc)
    assert_select "form[action='#{enable_device_path(@pc)}'] button", text: /Enable/
  end

  test "the devices list filters disabled devices" do
    @pc.update!(status: "disabled")
    as("read_only")
    get devices_path(status: "disabled")
    assert_response :success
    assert_includes response.body, "alice-pc"
    assert_not_includes response.body, "new-pc"
  end

  test "Add device on the Devices page leads to the enrollment form (helpdesk yes, read_only no)" do
    as("helpdesk")
    get devices_path
    assert_select "a[href='#{new_enrollment_path}']", text: /Add device/
  end

  test "read_only sees no Add device" do
    as("read_only")
    get devices_path
    assert_select "a", text: /Add device/, count: 0
  end
end
