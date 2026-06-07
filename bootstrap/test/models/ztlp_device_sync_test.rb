# frozen_string_literal: true

require "test_helper"

# Tests for the NS→Bootstrap sync schema/model additions on ZtlpDevice.
# Kept separate from ztlp_device_test.rb to isolate the sync feature surface.
class ZtlpDeviceSyncTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
  end

  def build_device(overrides = {})
    ZtlpDevice.new({
      name: "sync-test-#{SecureRandom.hex(4)}",
      network: @network,
      status: "enrolled"
    }.merge(overrides))
  end

  test "VALID_STATUSES is locked to pending/enrolled/revoked/orphaned" do
    assert_equal %w[pending enrolled revoked orphaned], ZtlpDevice::VALID_STATUSES
  end

  test "VALID_ORIGINS is locked to bootstrap/ns_sync" do
    assert_equal %w[bootstrap ns_sync], ZtlpDevice::VALID_ORIGINS
  end

  test "default origin is bootstrap when not set" do
    device = build_device
    assert device.save, device.errors.full_messages.inspect
    assert_equal "bootstrap", device.reload.origin
  end

  test "orphaned is a valid status" do
    device = build_device(status: "orphaned")
    assert device.valid?, device.errors.full_messages.inspect
  end

  test "unknown status fails validation" do
    device = build_device(status: "totally-bogus")
    refute device.valid?
    assert_includes device.errors[:status].join, "included"
  end

  test "unknown origin fails validation" do
    device = build_device(origin: "rogue")
    refute device.valid?
    assert_includes device.errors[:origin].join, "included"
  end

  test "synced_from_ns? returns true when origin == ns_sync" do
    device = build_device(origin: "ns_sync")
    assert device.synced_from_ns?
    refute build_device(origin: "bootstrap").synced_from_ns?
  end

  test "orphaned? returns true when status == orphaned" do
    assert build_device(status: "orphaned").orphaned?
    refute build_device(status: "enrolled").orphaned?
  end

  test "synced_from_ns scope filters to ns_sync rows only" do
    bs   = build_device(origin: "bootstrap", name: "bs-only-#{SecureRandom.hex(4)}")
    ns   = build_device(origin: "ns_sync",   name: "ns-only-#{SecureRandom.hex(4)}")
    bs.save!
    ns.save!

    scoped_names = ZtlpDevice.synced_from_ns.pluck(:name)
    assert_includes scoped_names, ns.name
    refute_includes scoped_names, bs.name
  end

  test "orphaned scope filters to orphaned status rows only" do
    enrolled = build_device(status: "enrolled", name: "enr-#{SecureRandom.hex(4)}")
    orphan   = build_device(status: "orphaned", name: "orph-#{SecureRandom.hex(4)}")
    enrolled.save!
    orphan.save!

    scoped_names = ZtlpDevice.orphaned.pluck(:name)
    assert_includes scoped_names, orphan.name
    refute_includes scoped_names, enrolled.name
  end
end
