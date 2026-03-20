# frozen_string_literal: true

require "test_helper"

class DeviceHeartbeatTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @device = ztlp_devices(:alice_laptop)
    @heartbeat = device_heartbeats(:alice_laptop_recent)
  end

  test "valid heartbeat" do
    assert @heartbeat.valid?
  end

  test "requires ztlp_device" do
    hb = DeviceHeartbeat.new(network: @network, created_at: Time.current)
    assert_not hb.valid?
    assert_includes hb.errors[:ztlp_device_id], "can't be blank"
  end

  test "requires network" do
    hb = DeviceHeartbeat.new(ztlp_device: @device, created_at: Time.current)
    assert_not hb.valid?
    assert_includes hb.errors[:network_id], "can't be blank"
  end

  test "belongs to ztlp_device" do
    assert_equal @device, @heartbeat.ztlp_device
  end

  test "belongs to network" do
    assert_equal @network, @heartbeat.network
  end

  test "scope recent orders by created_at desc" do
    heartbeats = DeviceHeartbeat.recent
    assert heartbeats.first.created_at >= heartbeats.last.created_at
  end

  test "scope for_device" do
    heartbeats = DeviceHeartbeat.for_device(@device.id)
    assert heartbeats.all? { |hb| hb.ztlp_device_id == @device.id }
  end

  test "scope for_network" do
    heartbeats = DeviceHeartbeat.for_network(@network.id)
    assert heartbeats.all? { |hb| hb.network_id == @network.id }
  end

  test "scope since" do
    heartbeats = DeviceHeartbeat.since(30.minutes.ago)
    assert heartbeats.all? { |hb| hb.created_at > 30.minutes.ago }
  end

  test "aggregate_bandwidth returns totals" do
    result = DeviceHeartbeat.aggregate_bandwidth(@network.id, since: 24.hours.ago)
    assert result.is_a?(Array)
    assert_equal 2, result.length
    assert result[0] >= 0  # bytes_sent
    assert result[1] >= 0  # bytes_received
  end

  test "defaults for bytes_sent and bytes_received" do
    hb = DeviceHeartbeat.new(
      ztlp_device: @device,
      network: @network,
      created_at: Time.current
    )
    assert_equal 0, hb.bytes_sent
    assert_equal 0, hb.bytes_received
    assert_equal 0, hb.active_streams
  end

  test "stores all optional fields" do
    assert_equal "10.0.1.50", @heartbeat.source_ip
    assert_equal 43210, @heartbeat.source_port
    assert_equal "relay-us-west", @heartbeat.relay_name
    assert_equal 15, @heartbeat.latency_ms
    assert_equal "1.2.0", @heartbeat.client_version
    assert_equal "macOS 15.1", @heartbeat.os_info
    assert_equal 3, @heartbeat.active_streams
  end
end
