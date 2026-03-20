# frozen_string_literal: true

require "test_helper"

class ConnectionEventTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @device = ztlp_devices(:alice_laptop)
    @user = ztlp_users(:alice)
    @event = connection_events(:alice_laptop_connected)
  end

  test "valid connection event" do
    assert @event.valid?
  end

  test "requires event_type" do
    event = ConnectionEvent.new(ztlp_device: @device, network: @network, created_at: Time.current)
    assert_not event.valid?
    assert_includes event.errors[:event_type], "can't be blank"
  end

  test "validates event_type inclusion" do
    event = ConnectionEvent.new(
      ztlp_device: @device, network: @network,
      event_type: "invalid", created_at: Time.current
    )
    assert_not event.valid?
    assert_includes event.errors[:event_type], "is not included in the list"
  end

  test "accepts all valid event types" do
    %w[connected disconnected reconnected handshake_failed].each do |type|
      event = ConnectionEvent.new(
        ztlp_device: @device, network: @network,
        event_type: type, created_at: Time.current
      )
      assert event.valid?, "#{type} should be valid"
    end
  end

  test "validates disconnect_reason inclusion" do
    event = ConnectionEvent.new(
      ztlp_device: @device, network: @network,
      event_type: "disconnected", disconnect_reason: "invalid",
      created_at: Time.current
    )
    assert_not event.valid?
    assert_includes event.errors[:disconnect_reason], "is not included in the list"
  end

  test "accepts all valid disconnect reasons" do
    %w[user_initiated timeout revoked network_change].each do |reason|
      event = ConnectionEvent.new(
        ztlp_device: @device, network: @network,
        event_type: "disconnected", disconnect_reason: reason,
        created_at: Time.current
      )
      assert event.valid?, "#{reason} should be valid"
    end
  end

  test "allows nil disconnect_reason" do
    event = ConnectionEvent.new(
      ztlp_device: @device, network: @network,
      event_type: "connected", disconnect_reason: nil,
      created_at: Time.current
    )
    assert event.valid?
  end

  test "belongs to ztlp_device" do
    assert_equal @device, @event.ztlp_device
  end

  test "belongs to network" do
    assert_equal @network, @event.network
  end

  test "belongs to ztlp_user (optional)" do
    assert_equal @user, @event.ztlp_user
    failed = connection_events(:failed_handshake)
    assert_nil failed.ztlp_user
    assert failed.valid?
  end

  test "scope recent orders by created_at desc" do
    events = ConnectionEvent.recent
    assert events.first.created_at >= events.last.created_at
  end

  test "scope for_network" do
    events = ConnectionEvent.for_network(@network.id)
    assert events.all? { |e| e.network_id == @network.id }
  end

  test "scope for_device" do
    events = ConnectionEvent.for_device(@device.id)
    assert events.all? { |e| e.ztlp_device_id == @device.id }
  end

  test "scope for_user" do
    events = ConnectionEvent.for_user(@user.id)
    assert events.all? { |e| e.ztlp_user_id == @user.id }
  end

  test "scope of_type" do
    events = ConnectionEvent.of_type("connected")
    assert events.all? { |e| e.event_type == "connected" }
  end

  test "connected? returns true for connected events" do
    assert @event.connected?
    assert_not @event.disconnected?
  end

  test "disconnected? returns true for disconnected events" do
    event = connection_events(:bob_desktop_disconnected)
    assert event.disconnected?
    assert_not event.connected?
  end

  test "reconnected? returns true for reconnected events" do
    event = connection_events(:alice_laptop_reconnected)
    assert event.reconnected?
  end

  test "handshake_failed? returns true for failed events" do
    event = connection_events(:failed_handshake)
    assert event.handshake_failed?
  end

  test "event_color returns correct colors" do
    assert_equal "green", connection_events(:alice_laptop_connected).event_color
    assert_equal "red", connection_events(:bob_desktop_disconnected).event_color
    assert_equal "yellow", connection_events(:alice_laptop_reconnected).event_color
    assert_equal "gray", connection_events(:failed_handshake).event_color
  end

  test "event_icon returns correct icons" do
    assert_equal "🟢", connection_events(:alice_laptop_connected).event_icon
    assert_equal "🔴", connection_events(:bob_desktop_disconnected).event_icon
    assert_equal "🟡", connection_events(:alice_laptop_reconnected).event_icon
    assert_equal "⚪", connection_events(:failed_handshake).event_icon
  end

  test "stores session duration and disconnect reason" do
    event = connection_events(:bob_desktop_disconnected)
    assert_equal 3600, event.session_duration_seconds
    assert_equal "timeout", event.disconnect_reason
  end

  test "stores details" do
    event = connection_events(:failed_handshake)
    assert_equal "Device certificate revoked", event.details
  end
end
