# frozen_string_literal: true

require "test_helper"

class StatusControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
    @network = networks(:office)
  end

  test "index loads status page" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Network Status"
    assert_includes response.body, @network.name
  end

  test "index shows online device count" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Online Devices"
  end

  test "index shows device status table" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Device Status"
    assert_includes response.body, "alice-laptop"
    assert_includes response.body, "bob-desktop"
  end

  test "index shows connection timeline" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Connection Timeline"
  end

  test "index shows user sessions panel" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Online Users"
  end

  test "index shows sparkline section" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Connected Devices"
    assert_includes response.body, "Last 24 Hours"
  end

  test "index shows bandwidth stats" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Bytes Received"
    assert_includes response.body, "Bytes Sent"
  end

  test "index includes auto-refresh meta tag" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, 'meta http-equiv="refresh" content="30"'
  end

  test "index filters events by type" do
    get network_status_path(@network, event_type: "connected")
    assert_response :success
    assert_includes response.body, "Connection Timeline"
  end

  test "index supports pagination" do
    get network_status_path(@network, page: 1)
    assert_response :success
  end

  test "index shows connection events" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Connected"
  end

  test "index shows device online status indicators" do
    get network_status_path(@network)
    assert_response :success
    # Should have green pulse dots for online devices
    assert_includes response.body, "bg-green-400 animate-pulse"
  end

  test "index shows offline status for never-seen devices" do
    get network_status_path(@network)
    assert_response :success
    assert_includes response.body, "Never"
  end

  test "requires authentication" do
    reset!  # Clear session
    get network_status_path(@network)
    assert_redirected_to login_path
  end
end
