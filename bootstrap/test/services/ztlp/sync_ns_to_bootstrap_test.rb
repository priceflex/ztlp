# frozen_string_literal: true

require "test_helper"

# Ztlp::SyncNsToBootstrap — central reconciler that pulls device "key"
# records from NS (via Ztlp::NsAdminClient) and mirrors them as
# ZtlpDevice rows in the Bootstrap DB.
#
# Pinned behaviours under test:
#   * Each NS record → one ZtlpDevice with origin="ns_sync", routed to
#     the Network whose `zone` is the LONGEST suffix of the device name.
#   * Re-running is idempotent — second `.call` creates no new rows.
#   * A device that vanishes from NS gets its row's status set to
#     "orphaned" (never deleted).
#   * Rows with origin="bootstrap" are NEVER modified by the sync —
#     hand-entered devices (e.g. hermes-op-z2lsapp1) must survive every
#     sync run unchanged.
#   * Records with no matching network are SKIPPED, not raised.
#   * pubkey_hex from NS lands in the `pubkey` column.
#   * last_synced_at is bumped on create AND update.
#   * On NsAdminClient::TransportError the call returns a Result with
#     status=:error — it does NOT raise out.
#
# All Network rows used here are created in setup with distinct
# `*.example.com` zones so we don't collide with the real prod
# fixtures used by MachinesControllerSharedGuardTest et al.
class Ztlp::SyncNsToBootstrapTest < ActiveSupport::TestCase
  setup do
    # Distinct zones, none used by any other test in the suite.
    @zone_trs  = "test-trs.example.com"
    @zone_adms = "adms.test-trs.example.com"
    @zone_tr   = "tech-rockstars.test-trs.example.com"

    Network.where(zone: [@zone_trs, @zone_adms, @zone_tr]).destroy_all
    @network_trs  = Network.create!(name: "T7 TRS",  zone: @zone_trs,  status: "created")
    @network_adms = Network.create!(name: "T7 ADMS", zone: @zone_adms, status: "created")
    @network_tr   = Network.create!(name: "T7 TR",   zone: @zone_tr,   status: "created")
  end

  # Helper — stub the NS admin client's list_records call.
  def stub_ns(records)
    Ztlp::NsAdminClient.stubs(:list_records).with(type: "key").returns(
      "records" => records,
      "count" => records.length,
      "generated_at" => 0
    )
  end

  def rec(name, pubkey_hex: "aa" * 32, created_at: 1)
    { "name" => name, "type" => "key", "pubkey_hex" => pubkey_hex,
      "ttl" => 86400, "created_at" => created_at, "serial" => 1, "data" => {} }
  end

  # --- Test 1: NS returns 2 keys, both in zone trs.ztlp → both upserted as new.
  test "creates a ZtlpDevice for each NS key record on the matching network" do
    stub_ns([
      rec("TRSDC.test-trs.example.com"),
      rec("box1.test-trs.example.com", pubkey_hex: "bb" * 32)
    ])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?, "expected success, got #{result.inspect}"
    assert_equal 2, result.created
    assert_equal 0, result.updated
    assert_equal 0, result.skipped
    assert ZtlpDevice.exists?(name: "TRSDC.test-trs.example.com", network_id: @network_trs.id, origin: "ns_sync")
    assert ZtlpDevice.exists?(name: "box1.test-trs.example.com",  network_id: @network_trs.id, origin: "ns_sync")
  end

  # --- Test 2: longest-zone-suffix wins for routing.
  test "routes by longest matching zone suffix" do
    stub_ns([
      rec("alice.adms.test-trs.example.com"),                # → ADMS, not TRS
      rec("server.tech-rockstars.test-trs.example.com"),     # → TR
      rec("plain.test-trs.example.com")                       # → TRS
    ])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 3, result.created
    assert ZtlpDevice.exists?(name: "alice.adms.test-trs.example.com",            network_id: @network_adms.id)
    assert ZtlpDevice.exists?(name: "server.tech-rockstars.test-trs.example.com", network_id: @network_tr.id)
    assert ZtlpDevice.exists?(name: "plain.test-trs.example.com",                 network_id: @network_trs.id)
    # And critically NOT routed to the shorter TRS zone:
    refute ZtlpDevice.exists?(name: "alice.adms.test-trs.example.com",            network_id: @network_trs.id)
  end

  # --- Test 3: idempotent — second call creates no new rows.
  test "is idempotent across runs" do
    stub_ns([rec("dev1.test-trs.example.com")])
    Ztlp::SyncNsToBootstrap.call
    assert_no_difference -> { ZtlpDevice.count } do
      result = Ztlp::SyncNsToBootstrap.call
      assert result.success?
      assert_equal 0, result.created
      assert_equal 1, result.updated
    end
  end

  # --- Test 4: vanished device gets orphaned, NOT deleted.
  test "marks previously-synced devices as orphaned when they vanish from NS" do
    stub_ns([rec("ghost.test-trs.example.com")])
    Ztlp::SyncNsToBootstrap.call
    assert ZtlpDevice.exists?(name: "ghost.test-trs.example.com", status: "enrolled")

    # Second run — NS no longer reports the device.
    stub_ns([])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 1, result.orphaned
    row = ZtlpDevice.find_by!(name: "ghost.test-trs.example.com")
    assert_equal "orphaned", row.status
    assert_equal "ns_sync",  row.origin
  end

  # --- Test 5: origin="bootstrap" rows are immune.
  test "never touches rows with origin=bootstrap" do
    hand = ZtlpDevice.create!(
      name: "hermes-op.test-trs.example.com",
      network_id: @network_trs.id,
      origin: "bootstrap",
      status: "enrolled",
      pubkey: "deadbeef"
    )
    stub_ns([])  # NS knows nothing about it
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 0, result.orphaned

    hand.reload
    assert_equal "bootstrap", hand.origin
    assert_equal "enrolled",  hand.status
    assert_equal "deadbeef",  hand.pubkey
  end

  # --- Test 6: name with no matching network → skipped, no row, no raise.
  test "skips records with no matching network" do
    stub_ns([
      rec("nomatch.does-not-exist.example.org"),
      rec("plain.test-trs.example.com")
    ])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 1, result.created
    assert_equal 1, result.skipped
    assert_equal 1, result.errors.length
    assert_equal "no_matching_network", result.errors.first[:reason]
    refute ZtlpDevice.exists?(name: "nomatch.does-not-exist.example.org")
  end

  # --- Test 7: pubkey_hex propagates into the pubkey column.
  test "stores pubkey_hex in the pubkey column" do
    stub_ns([rec("k1.test-trs.example.com", pubkey_hex: "cc" * 32)])
    Ztlp::SyncNsToBootstrap.call
    row = ZtlpDevice.find_by!(name: "k1.test-trs.example.com")
    assert_equal "cc" * 32, row.pubkey
  end

  # --- Test 8: last_synced_at bumped on both create and update.
  test "bumps last_synced_at on create and on subsequent update" do
    stub_ns([rec("ts.test-trs.example.com")])
    t0 = Time.current
    Ztlp::SyncNsToBootstrap.call
    row = ZtlpDevice.find_by!(name: "ts.test-trs.example.com")
    first_synced = row.last_synced_at
    assert_not_nil first_synced
    assert first_synced >= t0 - 5.seconds

    travel 2.seconds do
      Ztlp::SyncNsToBootstrap.call
    end
    row.reload
    assert row.last_synced_at > first_synced, "expected last_synced_at to advance on update"
  end

  # --- Test 9: case-insensitive matching for routing.
  test "matches zone suffix case-insensitively" do
    stub_ns([rec("ALICE.ADMS.TEST-TRS.EXAMPLE.COM")])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 1, result.created
    assert ZtlpDevice.exists?(network_id: @network_adms.id)
  end

  # --- Test 10: TransportError → Result(status: :error), no raise.
  test "returns Result(status: :error) on NsAdminClient::TransportError without raising" do
    Ztlp::NsAdminClient.stubs(:list_records).with(type: "key")
      .raises(Ztlp::NsAdminClient::TransportError.new("connection refused"))
    result = nil
    assert_nothing_raised do
      result = Ztlp::SyncNsToBootstrap.call
    end
    assert result.error?
    refute result.success?
    assert_match(/TransportError/, result.message)
  end

  # --- Test 11 (bonus): previously-orphaned device returning to NS is un-orphaned.
  test "un-orphans a previously-orphaned device when NS reports it again" do
    revenant = ZtlpDevice.create!(
      name: "back.test-trs.example.com",
      network_id: @network_trs.id,
      origin: "ns_sync",
      status: "orphaned",
      pubkey: "old"
    )
    stub_ns([rec("back.test-trs.example.com", pubkey_hex: "new" + "f" * 61)])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 1, result.updated
    revenant.reload
    assert_equal "enrolled", revenant.status
    assert_equal "new" + "f" * 61, revenant.pubkey
  end
end
