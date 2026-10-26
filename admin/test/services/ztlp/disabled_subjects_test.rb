# frozen_string_literal: true

# Slice 3: what "disabled" means outside the panel DB.
# - Name server records: a disabled user stops vouching for anything (role "", no devices),
#   GROUP records leave them out, DEVICE records of a disabled device / disabled owner carry
#   no owner -> group:/role: rules (resolved live by the gateway) stop matching.
# - Rendered policy: user/device rules naming a disabled subject render nothing.
require "test_helper"

class DisabledSubjectsTest < ActiveSupport::TestCase
  setup do
    @zone = Zone.primary
    @alice = @zone.users.create!(username: "alice", display_name: "Alice", status: "active", role: "admin")
    @bob = @zone.users.create!(username: "bob", display_name: "Bob", status: "active")
    @staff = @zone.groups.create!(name: "staff")
    [ @alice, @bob ].each { |u| @staff.group_memberships.create!(user: u) }
    @pc = @zone.devices.create!(name: "alice-pc", ns_name: "alice-pc.#{@zone.name}", status: "enrolled", user: @alice)
    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @svc = @gw.services.create!(name: "www", backend: "127.0.0.1:80", protocol: "http")
  end

  test "an active user's records are unchanged" do
    data = Ztlp::Records.user_data(@alice)
    assert_equal "admin", data["role"]
    assert_equal [ @pc.ns_name ], data["devices"]
    assert_equal @alice.ns_name, Ztlp::Records.device_data(@pc)["owner"]
  end

  test "a disabled user publishes no role and no devices, and their devices no owner" do
    @alice.update!(status: "disabled")
    data = Ztlp::Records.user_data(@alice)
    assert_equal "", data["role"]
    assert_equal [], data["devices"]
    assert_equal "", Ztlp::Records.device_data(@pc)["owner"]
  end

  test "groups leave out disabled and revoked users" do
    @alice.update!(status: "disabled")
    assert_equal [ @bob.ns_name ], Ztlp::Records.group_data(@staff)["members"]
    @bob.update!(status: "revoked")
    assert_equal [], Ztlp::Records.group_data(@staff)["members"]
  end

  test "a disabled device publishes no owner and drops out of its user's devices" do
    @pc.update!(status: "disabled")
    assert_equal "", Ztlp::Records.device_data(@pc)["owner"]
    assert_equal [], Ztlp::Records.user_data(@alice)["devices"]
  end

  test "rules naming a disabled user or device render nothing; the rest stay" do
    @svc.policy_rules.create!(subject_type: "user", subject_id: @alice.id, position: 0)
    @svc.policy_rules.create!(subject_type: "device", subject_id: @pc.id, position: 1)
    @svc.policy_rules.create!(subject_type: "user", subject_id: @bob.id, position: 2)
    assert_includes Ztlp::PolicyRenderer.render(@gw), @alice.ns_name

    @alice.update!(status: "disabled")
    out = Ztlp::PolicyRenderer.render(@gw)
    assert_not_includes out, "\"#{@alice.ns_name}\""
    assert_not_includes out, "\"#{@pc.ns_name}\"", "a device of a disabled user must not render either"
    assert_includes out, "\"#{@bob.ns_name}\""
  end

  test "a disabled device's own rule renders nothing" do
    @svc.policy_rules.create!(subject_type: "device", subject_id: @pc.id, position: 0)
    @pc.update!(status: "disabled")
    assert_match(/allow = \[\]/, Ztlp::PolicyRenderer.render(@gw))
  end
end
