# frozen_string_literal: true

# Helpdesk role (PLAN-services-wizard-and-helpdesk.md, slice 1; spec 4.3).
#
# helpdesk = "managing users, like adding and disabling users and devices" (operator, 2026-10-25):
#   CAN  : read everything; create users (always role user / kind person); edit contact fields;
#          enrollments (= add devices); assign a device owner.
#   CANNOT: change role or kind; revoke (permanent) users or devices; groups; services/services,
#          their rules, registration and gateways; zone publish/reconcile.
# admin keeps every operational function; read_only stays read-only.
require "test_helper"

class HelpdeskRoleTest < ActionDispatch::IntegrationTest
  setup do
    @zone = Zone.primary
    @user = @zone.users.create!(username: "alice", display_name: "Alice", role: "user", kind: "person",
                                status: "active", email: "alice@example.com")
    @group = @zone.groups.create!(name: "staff")
    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @svc = @gw.services.create!(name: "blitz", backend: "127.0.0.1:5200", protocol: "http")
    @device = @zone.devices.create!(name: "alice-pc", ns_name: "alice-pc.#{@zone.name}", status: "enrolled")
    # Publishing needs the zone authority (absent in tests); role checks must happen before any publish.
    Ztlp::Publisher.stubs(:publish_user!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_device!).returns(:ok)
    Ztlp::Publisher.stubs(:publish_group!).returns(:ok)
  end

  def as(role)
    admin, seed = make_admin(role: role, username: "#{role.tr('_', '-')}-1")
    sign_in_as(admin, seed)
    admin
  end

  # ------------------------------------------------------------------ helpdesk: forbidden

  FORBIDDEN = {
    "revoke a user"             => ->(t) { t.post t.revoke_user_path(t.user) },
    "revoke a device"           => ->(t) { t.post t.revoke_device_path(t.device) },
    "create a group"            => ->(t) { t.post t.groups_path, params: { group: { name: "ops" } } },
    "edit a group"              => ->(t) { t.patch t.group_path(t.group), params: { group: { description: "x" } } },
    "delete a group"            => ->(t) { t.delete t.group_path(t.group) },
    "add a group member"        => ->(t) { t.post t.add_member_group_path(t.group), params: { user_id: t.user.id } },
    "remove a group member"     => ->(t) { t.delete t.remove_member_group_path(t.group), params: { user_id: t.user.id } },
    "open new service"      => ->(t) { t.get t.new_service_path },
    "create a service"     => ->(t) { t.post t.services_path, params: { service: { name: "x", gateway_id: t.gw.id } } },
    "edit a service"       => ->(t) { t.patch t.service_path(t.svc), params: { service: { backend: "1.2.3.4:80" } } },
    "disable a service"    => ->(t) { t.post t.disable_service_path(t.svc) },
    "enable a service"     => ->(t) { t.post t.enable_service_path(t.svc) },
    "add an access rule"        => ->(t) { t.post t.service_rules_path(t.svc), params: { rule: { subject_type: "all" } } },
    "register a service"   => ->(t) { t.post t.register_services_path, params: { fqdn: "x.#{t.zone.name}" } },
    "open new gateway"          => ->(t) { t.get t.new_gateway_path },
    "create a gateway"          => ->(t) { t.post t.gateways_path, params: { gateway: { name: "gw2", kind: "rust_listen" } } },
    "change a gateway kind"     => ->(t) { t.post t.update_kind_gateway_path(t.gw), params: { kind: "elixir" } },
    "publish the zone"          => ->(t) { t.post t.zone_publish_path },
    "reconcile the zone"        => ->(t) { t.post t.zone_reconcile_path }
  }.freeze

  attr_reader :user, :group, :gw, :device, :zone

  def svc = @svc

  FORBIDDEN.each do |what, call|
    test "helpdesk cannot #{what}" do
      as("helpdesk")
      before = [ User.pluck(:status, :role), Group.count, GroupMembership.count, Service.count,
                 Service.pluck(:enabled, :backend), PolicyRule.count, Gateway.pluck(:kind), Gateway.count,
                 Device.pluck(:status) ]
      call.call(self)
      assert_response :forbidden, "#{what}: expected 403, got #{response.status}"
      after = [ User.pluck(:status, :role), Group.count, GroupMembership.count, Service.count,
                Service.pluck(:enabled, :backend), PolicyRule.count, Gateway.pluck(:kind), Gateway.count,
                Device.pluck(:status) ]
      assert_equal before, after, "#{what}: state changed"
    end
  end

  # ------------------------------------------------------------------ helpdesk: allowed

  test "helpdesk creates a user, always as role user / kind person" do
    as("helpdesk")
    post users_path, params: { user: { username: "bob", display_name: "Bob", role: "admin", kind: "service",
                                       email: "bob@example.com" } }
    bob = User.find_by!(username: "bob")
    assert_equal "user", bob.role
    assert_equal "person", bob.kind
    assert_redirected_to user_path(bob)
  end

  test "helpdesk edits contact fields but cannot change role or kind" do
    @user.update!(role: "tech")
    as("helpdesk")
    patch user_path(@user), params: { user: { email: "new@example.com", role: "admin", kind: "service" } }
    @user.reload
    assert_equal "new@example.com", @user.email
    assert_equal "tech", @user.role
    assert_equal "person", @user.kind
  end

  test "helpdesk does not see role and kind on the user form" do
    as("helpdesk")
    get new_user_path
    assert_response :success
    assert_select "select[name='user[role]']", false
    assert_select "select[name='user[kind]']", false
  end

  test "helpdesk can open the enrollment (add device) form" do
    as("helpdesk")
    get new_enrollment_path
    assert_response :success
  end

  test "helpdesk can assign a device owner" do
    as("helpdesk")
    post assign_owner_device_path(@device), params: { user_id: @user.id }
    assert_equal @user.id, @device.reload.user_id
  end

  test "helpdesk sees no revoke button on a device or a user" do
    as("helpdesk")
    get device_path(@device)
    assert_select "form[action='#{revoke_device_path(@device)}']", false
    get user_path(@user)
    assert_select "form[action='#{revoke_user_path(@user)}']", false
  end

  test "helpdesk sees no New group / Register service buttons" do
    as("helpdesk")
    get groups_path
    assert_select "a[href='#{new_group_path}']", false
    get services_path
    assert_select "a[href='#{register_services_path}']", false
  end

  # ------------------------------------------------------------------ admin keeps operator powers

  test "admin can set a user's role and create a group" do
    as("admin")
    patch user_path(@user), params: { user: { role: "tech" } }
    assert_equal "tech", @user.reload.role
    post groups_path, params: { group: { name: "ops" } }
    assert Group.exists?(name: "ops")
  end

  test "admin can open new service and new gateway" do
    as("admin")
    get new_service_path
    assert_response :success
    get new_gateway_path
    assert_response :success
  end

  test "read_only still cannot create a user" do
    as("read_only")
    post users_path, params: { user: { username: "carl", display_name: "Carl" } }
    assert_response :forbidden
    assert_not User.exists?(username: "carl")
  end
end
