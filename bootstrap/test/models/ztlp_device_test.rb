# frozen_string_literal: true

require "test_helper"

class ZtlpDeviceTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @device = ztlp_devices(:alice_laptop)
  end

  test "valid device" do
    assert @device.valid?
  end

  test "requires name" do
    device = ZtlpDevice.new(network: @network, status: "enrolled")
    assert_not device.valid?
    assert_includes device.errors[:name], "can't be blank"
  end

  test "name must be unique within network" do
    duplicate = ZtlpDevice.new(name: "alice-laptop", network: @network, status: "enrolled")
    assert_not duplicate.valid?
    assert_includes duplicate.errors[:name], "has already been taken"
  end

  test "validates status inclusion" do
    @device.status = "unknown"
    assert_not @device.valid?
    assert_includes @device.errors[:status], "is not included in the list"
  end

  test "accepts valid statuses" do
    %w[enrolled revoked].each do |status|
      @device.status = status
      assert @device.valid?, "#{status} should be valid"
    end
  end

  test "revoke! sets status and timestamp" do
    @device.revoke!(reason: "Lost device")
    @device.reload
    assert_equal "revoked", @device.status
    assert_not_nil @device.revoked_at
    assert_equal "Lost device", @device.revocation_reason
  end

  test "enrolled? returns true for enrolled devices" do
    assert @device.enrolled?
    assert_not @device.revoked?
  end

  test "revoked? returns true for revoked devices" do
    revoked = ztlp_devices(:revoked_device)
    assert revoked.revoked?
    assert_not revoked.enrolled?
  end

  test "belongs to network" do
    assert_equal @network, @device.network
  end

  test "belongs to ztlp_user (optional)" do
    assert_equal ztlp_users(:alice), @device.ztlp_user
    unassigned = ztlp_devices(:unassigned_device)
    assert_nil unassigned.ztlp_user
    assert unassigned.valid?
  end

  test "belongs to machine (optional)" do
    assert_equal machines(:ns1), @device.machine
    phone = ztlp_devices(:alice_phone)
    assert_nil phone.machine
    assert phone.valid?
  end

  test "owner_name returns user name or Unassigned" do
    assert_equal "alice", @device.owner_name
    unassigned = ztlp_devices(:unassigned_device)
    assert_equal "Unassigned", unassigned.owner_name
  end

  test "scope enrolled" do
    enrolled = ZtlpDevice.enrolled
    assert_includes enrolled, ztlp_devices(:alice_laptop)
    assert_not_includes enrolled, ztlp_devices(:revoked_device)
  end

  test "scope revoked" do
    revoked = ZtlpDevice.revoked
    assert_includes revoked, ztlp_devices(:revoked_device)
    assert_not_includes revoked, ztlp_devices(:alice_laptop)
  end

  # Online/Offline status tests

  test "online? returns true when last_seen_at is recent" do
    @device.update!(last_seen_at: 2.minutes.ago)
    assert @device.online?
    assert_not @device.offline?
  end

  test "online? returns false when last_seen_at is old" do
    @device.update!(last_seen_at: 10.minutes.ago)
    assert_not @device.online?
    assert @device.offline?
  end

  test "online? returns false when last_seen_at is nil" do
    @device.update!(last_seen_at: nil)
    assert_not @device.online?
    assert @device.offline?
  end

  test "scope online returns recently seen devices" do
    online = ZtlpDevice.online
    # alice_laptop (2 min ago) and bob_desktop (3 min ago) should be online
    assert_includes online, ztlp_devices(:alice_laptop)
    assert_includes online, ztlp_devices(:bob_desktop)
    # alice_phone (1 hour ago) should be offline
    assert_not_includes online, ztlp_devices(:alice_phone)
    # nil last_seen should be offline
    assert_not_includes online, ztlp_devices(:unassigned_device)
  end

  test "scope offline returns old or nil last_seen devices" do
    offline = ZtlpDevice.offline
    assert_includes offline, ztlp_devices(:alice_phone)
    assert_includes offline, ztlp_devices(:unassigned_device)
    assert_not_includes offline, ztlp_devices(:alice_laptop)
  end

  test "scope recently_seen returns devices seen in last 24h" do
    recent = ZtlpDevice.recently_seen
    assert_includes recent, ztlp_devices(:alice_laptop)
    assert_includes recent, ztlp_devices(:alice_phone)
    assert_not_includes recent, ztlp_devices(:unassigned_device)
  end

  test "status_with_presence returns revoked for revoked devices" do
    revoked = ztlp_devices(:revoked_device)
    assert_equal "revoked", revoked.status_with_presence
  end

  test "status_with_presence returns online for online devices" do
    @device.update!(last_seen_at: 2.minutes.ago)
    assert_equal "online", @device.status_with_presence
  end

  test "status_with_presence returns offline for offline devices" do
    @device.update!(last_seen_at: 10.minutes.ago)
    assert_equal "offline", @device.status_with_presence
  end

  test "has_many device_heartbeats" do
    assert_respond_to @device, :device_heartbeats
  end

  test "has_many connection_events" do
    assert_respond_to @device, :connection_events
  end
end
