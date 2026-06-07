# frozen_string_literal: true

require "test_helper"

class ZtlpDevicesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as_admin
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

  test "index renders sync health banner" do
    # Per-test tmp file — Rails parallelizes workers above 50 runs so the
    # global tmp/ztlp_sync_state.json would otherwise race across forks.
    tmpdir = Dir.mktmpdir("ztlp-devices-sync-state")
    state_path = Pathname.new(File.join(tmpdir, "ztlp_sync_state.json"))
    Ztlp::SyncState.stubs(:state_file).returns(state_path)

    Ztlp::SyncState.record_success!
    get network_ztlp_devices_path(@network)
    assert_response :success
    assert_match(/Last NS sync/, response.body)
    assert_match(/sync-health-banner/, response.body)
  ensure
    FileUtils.remove_entry(tmpdir) if tmpdir && File.exist?(tmpdir)
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

  test "index filters by status when ?status=orphaned" do
    orphan = @network.ztlp_devices.create!(
      name: "ghost-device",
      node_id: "node-orphan-1",
      status: "orphaned",
      origin: "ns_sync",
      last_synced_at: 1.hour.ago
    )
    get network_ztlp_devices_path(@network, status: "orphaned")
    assert_response :success
    assert_match "ghost-device", response.body
    assert_no_match(/alice-laptop/, response.body)
    assert_no_match(/bob-desktop/, response.body)
  ensure
    orphan&.destroy
  end

  test "index ignores invalid status param" do
    get network_ztlp_devices_path(@network, status: "bogus; DROP TABLE")
    assert_response :success
    # falls back to no scoping — all devices shown
    assert_match "alice-laptop", response.body
  end

  test "index renders NS source badge for ns_sync devices" do
    synced = @network.ztlp_devices.create!(
      name: "ns-synced-laptop",
      node_id: "node-synced-1",
      status: "enrolled",
      origin: "ns_sync",
      enrolled_at: 2.hours.ago,
      last_synced_at: 3.minutes.ago
    )
    get network_ztlp_devices_path(@network)
    assert_response :success
    # Must show NS badge for ns_sync device, BS badge for bootstrap-origin
    assert_select "tr", text: /ns-synced-laptop/ do
      assert_select "span.source-badge-ns_sync", text: /NS/
    end
    assert_select "tr", text: /alice-laptop/ do
      assert_select "span.source-badge-bootstrap", text: /BS/
    end
  ensure
    synced&.destroy
  end

  test "index renders last_synced_at humanized for synced devices" do
    synced = @network.ztlp_devices.create!(
      name: "ns-synced-laptop-2",
      node_id: "node-synced-2",
      status: "enrolled",
      origin: "ns_sync",
      enrolled_at: 2.hours.ago,
      last_synced_at: 3.minutes.ago
    )
    get network_ztlp_devices_path(@network)
    assert_response :success
    # ns-synced-laptop has last_synced_at = 3.minutes.ago
    assert_match(/synced.*minute/i, response.body)
  ensure
    synced&.destroy
  end
end
