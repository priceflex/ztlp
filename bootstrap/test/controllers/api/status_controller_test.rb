# frozen_string_literal: true

require "test_helper"

class Api::StatusControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @device = ztlp_devices(:alice_laptop)
    @token = @network.enrollment_secret_ciphertext
  end

  # === Authentication ===

  test "heartbeat requires auth token" do
    post api_heartbeat_path, params: { device_id: @device.id }
    assert_response :unauthorized
    data = JSON.parse(response.body)
    assert_equal "Unauthorized", data["error"]
  end

  test "heartbeat rejects invalid token" do
    post api_heartbeat_path,
      params: { device_id: @device.id },
      headers: { "Authorization" => "Bearer invalid-token" }
    assert_response :unauthorized
  end

  test "event requires auth token" do
    post api_events_path, params: { device_id: @device.id, event_type: "connected" }
    assert_response :unauthorized
  end

  # === Heartbeat Endpoint ===

  test "heartbeat creates record and updates device" do
    assert_difference "DeviceHeartbeat.count", 1 do
      post api_heartbeat_path,
        params: {
          device_id: @device.id,
          source_ip: "10.0.1.100",
          source_port: 44000,
          relay_name: "relay-test",
          latency_ms: 10,
          bytes_sent: 5000,
          bytes_received: 10000,
          active_streams: 2,
          client_version: "2.0.0",
          os_info: "iOS 19.2"
        },
        headers: { "Authorization" => "Bearer #{@token}" }
    end

    assert_response :created
    data = JSON.parse(response.body)
    assert_equal "ok", data["status"]
    assert data["heartbeat_id"].present?

    @device.reload
    assert @device.last_seen_at > 1.minute.ago
    assert_equal "10.0.1.100", @device.last_source_ip
    assert_equal "relay-test", @device.last_relay
    assert_equal "2.0.0", @device.client_version
    assert_equal "iOS 19.2", @device.os_info
  end

  test "heartbeat accepts node_id as identifier" do
    assert_difference "DeviceHeartbeat.count", 1 do
      post api_heartbeat_path,
        params: { node_id: @device.node_id, source_ip: "10.0.1.100" },
        headers: { "Authorization" => "Bearer #{@token}" }
    end
    assert_response :created
  end

  test "heartbeat returns 404 for unknown device" do
    post api_heartbeat_path,
      params: { device_id: 999999 },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :not_found
    data = JSON.parse(response.body)
    assert_equal "Device not found", data["error"]
  end

  test "heartbeat rate limits to 1 per 30 seconds" do
    # First heartbeat succeeds
    post api_heartbeat_path,
      params: { device_id: @device.id, source_ip: "10.0.1.100" },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    # Second heartbeat within 30s should fail
    post api_heartbeat_path,
      params: { device_id: @device.id, source_ip: "10.0.1.100" },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :too_many_requests
    data = JSON.parse(response.body)
    assert_match(/Rate limited/, data["error"])
  end

  test "heartbeat returns 404 when no device_id provided" do
    post api_heartbeat_path,
      params: {},
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :not_found
  end

  # === Event Endpoint ===

  test "event creates connection event record" do
    assert_difference "ConnectionEvent.count", 1 do
      post api_events_path,
        params: {
          device_id: @device.id,
          event_type: "connected",
          source_ip: "10.0.1.100",
          relay_name: "relay-test"
        },
        headers: { "Authorization" => "Bearer #{@token}" }
    end

    assert_response :created
    data = JSON.parse(response.body)
    assert_equal "ok", data["status"]
    assert data["event_id"].present?
  end

  test "event updates device on connect" do
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "connected",
        source_ip: "10.0.1.200",
        relay_name: "relay-new"
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    @device.reload
    assert @device.last_seen_at > 1.minute.ago
    assert_equal "10.0.1.200", @device.last_source_ip
    assert_equal "relay-new", @device.last_relay
  end

  test "event updates device on reconnect" do
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "reconnected",
        source_ip: "10.0.1.201"
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    @device.reload
    assert_equal "10.0.1.201", @device.last_source_ip
  end

  test "event does not update device on disconnect" do
    original_ip = @device.last_source_ip
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "disconnected",
        source_ip: "10.0.1.300",
        disconnect_reason: "timeout",
        session_duration_seconds: 7200
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    @device.reload
    assert_equal original_ip, @device.last_source_ip
  end

  test "event records disconnect details" do
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "disconnected",
        disconnect_reason: "user_initiated",
        session_duration_seconds: 3600,
        details: "User logged out"
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    event = ConnectionEvent.last
    assert_equal "disconnected", event.event_type
    assert_equal "user_initiated", event.disconnect_reason
    assert_equal 3600, event.session_duration_seconds
    assert_equal "User logged out", event.details
  end

  test "event rejects invalid event_type" do
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "invalid_type"
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :unprocessable_entity
  end

  test "event returns 404 for unknown device" do
    post api_events_path,
      params: { device_id: 999999, event_type: "connected" },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :not_found
  end

  test "event associates ztlp_user from device" do
    post api_events_path,
      params: {
        device_id: @device.id,
        event_type: "connected"
      },
      headers: { "Authorization" => "Bearer #{@token}" }
    assert_response :created

    event = ConnectionEvent.last
    assert_equal @device.ztlp_user, event.ztlp_user
  end
end
