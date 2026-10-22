# frozen_string_literal: true

require "test_helper"

# Slice 5b-ii: Ztlp::Reconciler — the 30-minute drift check (spec Slice 5).
# Lists user/device/group records from the NS admin API and compares them to
# the panel rows, storing the result as JSON in system_settings
# `ns_drift_json` (counts + missing/extra names, never record data).
#
# NOTE: mocha BLOCK stubs do not run in this harness (mocha 3.1.0 block form
# not invoked — probed 2026-10-22); expectations and .returns chains work.
# The NS client is the injectable `ns_client:` seam, driven here by a
# hand-written FakeNsClient (the list contract is pinned by ns_client_test.rb
# and the ZTLP_TEST_NS roundtrip).
class ReconcilerTest < ActiveSupport::TestCase
  class FakeNsClient
    def initialize(users: [], devices: [], groups: [])
      @users = users
      @devices = devices
      @groups = groups
    end

    def self.list(*_a, **_kw)
      raise "call an instance"
    end

    def list(_port, _secret, type: nil, zone: nil, **kw)
      case type
      when "user" then @users
      when "device" then @devices
      when "group" then @groups
      else raise ArgumentError, "unexpected list type: #{type.inspect}"
      end
    end
  end

  def ns_record(name)
    { name: name, type: "", data: {}, created_at: 0, ttl: 0, serial: 0 }
  end

  def setup
    seed, pub = Ztlp::Ed25519.generate
    @zone = Zone.create!(name: "test.ztlp", ns_addr: "127.0.0.1:23096", authority_seed_ct: seed,
                         ns_admin_api_secret_ct: "01" * 32)
    @admin = Admin.create!(username: "steve", display_name: "Steve", pubkey_hex: pub,
                           role: "super_admin")
    @user = @zone.users.create!(username: "alice", ns_name: "alice.users.test.ztlp",
                                role: "user", status: "active")
    @device = @zone.devices.create!(name: "alice-mbp", ns_name: "alice-mbp.test.ztlp",
                                    node_id_hex: "ab" * 16, noise_pubkey_hex: "cd" * 32,
                                    assurance: 2, key_source: "file", status: "enrolled",
                                    user: @user)
  end

  def read_drift
    JSON.parse(SystemSetting[("ns_drift_json")])
  end

  def test_stores_drift_json_with_zone_and_checked_at
    client = FakeNsClient.new(users: [ ns_record("alice.users.test.ztlp") ],
                              devices: [ ns_record("alice-mbp.test.ztlp") ])
    Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)

    drift = read_drift
    assert_equal "test.ztlp", drift["zone"]
    assert_kind_of Integer, drift["checked_at"]
  end

  def test_counts_panel_vs_ns_per_type
    client = FakeNsClient.new(users: [ ns_record("alice.users.test.ztlp") ],
                              devices: [ ns_record("alice-mbp.test.ztlp") ])
    Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)

    drift = read_drift
    assert_equal 1, drift.dig("user", "panel")
    assert_equal 1, drift.dig("user", "ns")
    assert_equal 1, drift.dig("device", "panel")
    assert_equal 1, drift.dig("device", "ns")
    assert_equal 0, drift.dig("group", "panel")
    assert_equal 0, drift.dig("group", "ns")
  end

  def test_missing_and_extra_names_are_sorted_and_complete
    client = FakeNsClient.new(users: [ ns_record("zzz.users.test.ztlp") ],
                              devices: [ ns_record("zzz.test.ztlp") ])
    Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)

    drift = read_drift
    # panel has alice user, NS has zzz: alice is missing in NS, zzz is extra.
    assert_equal [ "alice.users.test.ztlp" ], drift.dig("user", "missing_in_ns")
    assert_equal [ "zzz.users.test.ztlp" ], drift.dig("user", "extra_in_ns")
    assert_equal [ "alice-mbp.test.ztlp" ], drift.dig("device", "missing_in_ns")
    assert_equal [ "zzz.test.ztlp" ], drift.dig("device", "extra_in_ns")
    assert_equal [], drift.dig("group", "missing_in_ns")
    assert_equal [], drift.dig("group", "extra_in_ns")
  end

  def test_audit_row_written_with_counts_not_names
    client = FakeNsClient.new(users: [ ns_record("alice.users.test.ztlp") ],
                              devices: [ ns_record("alice-mbp.test.ztlp") ])
    Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)

    row = AuditLog.where(admin_id: @admin.id, action: "ns.reconcile").last
    refute_nil row
    assert_equal "ok", row.status
    details = row.details
    assert_equal 1, details["user_panel"]
    assert_equal 1, details["user_ns"]
    assert_equal 1, details["device_panel"]
    assert_equal 1, details["device_ns"]
    assert_equal 0, details["group_panel"]
    assert_equal 0, details["group_ns"]
    # Names stay in the settings JSON (for the /zone drift table), not audit.
    assert_nil details["user_missing"]
    assert_nil details["device_missing"]
  end

  def test_list_failure_is_recorded_not_raised
    client = Object.new
    client.define_singleton_method(:list) do |*_a, **_kw|
      raise Ztlp::NsClient::NsError.new(0x0C, "timeout")
    end

    assert_equal :failed, Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)
    drift = read_drift
    assert_equal "failed", drift["status"]
    assert_equal "0x0C timeout", drift["error"]
    assert_kind_of Integer, drift["checked_at"]
    assert AuditLog.exists?(action: "ns.reconcile", status: "failed")
  end

  def test_no_admin_api_secret_is_recorded_as_not_configured
    @zone.update!(ns_admin_api_secret_ct: nil)
    client = Object.new
    client.define_singleton_method(:list) { |*_a, **_kw| raise "must not be called" }

    assert_equal :not_configured, Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)
    assert_equal "not_configured", read_drift["status"]
  end

  def test_success_records_status_ok
    client = FakeNsClient.new(users: [ ns_record("alice.users.test.ztlp") ],
                              devices: [ ns_record("alice-mbp.test.ztlp") ])
    assert_equal :ok, Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)
    assert_equal "ok", read_drift["status"]
  end

  def test_unpublished_rows_are_not_counted_as_missing_in_ns
    # invited users and pending/revoked devices are never published (Republisher), so they
    # must not show up as drift.
    @zone.users.create!(username: "bob", ns_name: "bob.users.test.ztlp", role: "user", status: "invited")
    @zone.devices.create!(name: "bob-pc", ns_name: "bob-pc.test.ztlp", node_id_hex: "ee" * 16,
                          noise_pubkey_hex: "ff" * 32, assurance: 1, key_source: "file", status: "pending")
    client = FakeNsClient.new(users: [ ns_record("alice.users.test.ztlp") ],
                              devices: [ ns_record("alice-mbp.test.ztlp") ])
    Ztlp::Reconciler.run(@zone, admin: @admin, ns_client: client)

    drift = read_drift
    assert_equal [], drift.dig("user", "missing_in_ns")
    assert_equal [], drift.dig("device", "missing_in_ns")
    assert_equal 1, drift.dig("user", "panel")
  end

  def test_default_ns_client_is_real_client_seam
    # The service must default to the real Ztlp::NsClient (class), so the
    # /zone "Reconcile now" button works without an inject.
    assert_equal Ztlp::NsClient, Ztlp::Reconciler.default_ns_client
  end
end
