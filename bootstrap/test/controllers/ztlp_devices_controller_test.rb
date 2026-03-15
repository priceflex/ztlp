# frozen_string_literal: true

require "test_helper"

class ZtlpDevicesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @device = ztlp_devices(:alice_laptop)
  end

  test "index lists devices" do
    get network_ztlp_devices_path(@network)
    assert_response :success
    assert_select "table"
    assert_match "alice-laptop", response.body
    assert_match "bob-desktop", response.body
  end

  test "index filters by status enrolled" do
    get network_ztlp_devices_path(@network, status: "enrolled")
    assert_response :success
    assert_match "alice-laptop", response.body
    assert_no_match(/old-server/, response.body)
  end

  test "index filters by status revoked" do
    get network_ztlp_devices_path(@network, status: "revoked")
    assert_response :success
    assert_match "old-server", response.body
    assert_no_match(/alice-laptop/, response.body)
  end

  test "index filters by user" do
    alice = ztlp_users(:alice)
    get network_ztlp_devices_path(@network, user_id: alice.id)
    assert_response :success
    assert_match "alice-laptop", response.body
    assert_no_match(/bob-desktop/, response.body)
  end

  test "show displays device details" do
    get network_ztlp_device_path(@network, @device)
    assert_response :success
    assert_match "alice-laptop", response.body
    assert_match "node-001", response.body
    assert_match "hw-laptop-001", response.body
  end

  test "show displays owner" do
    get network_ztlp_device_path(@network, @device)
    assert_response :success
    assert_match "alice", response.body
  end

  test "show displays machine" do
    get network_ztlp_device_path(@network, @device)
    assert_response :success
    assert_match "ns1.office", response.body
  end

  test "show unassigned device" do
    unassigned = ztlp_devices(:unassigned_device)
    get network_ztlp_device_path(@network, unassigned)
    assert_response :success
    assert_match "Unassigned", response.body
  end

  test "destroy revokes device" do
    assert_equal "enrolled", @device.status
    delete network_ztlp_device_path(@network, @device)
    assert_redirected_to network_ztlp_devices_path(@network)
    @device.reload
    assert_equal "revoked", @device.status
    assert_not_nil @device.revoked_at
  end

  test "destroy with custom reason" do
    delete network_ztlp_device_path(@network, @device), params: { reason: "Device lost" }
    @device.reload
    assert_equal "Device lost", @device.revocation_reason
  end

  test "destroy records audit log" do
    assert_difference "AuditLog.count", 1 do
      delete network_ztlp_device_path(@network, @device)
    end
    log = AuditLog.last
    assert_equal "ztlp_device_revoke", log.action
  end

  test "show revoked device displays revocation info" do
    revoked = ztlp_devices(:revoked_device)
    get network_ztlp_device_path(@network, revoked)
    assert_response :success
    assert_match "Revoked", response.body
    assert_match "Decommissioned", response.body
  end
end
