# frozen_string_literal: true

require "test_helper"

# Ztlp::NsImporter copies the NS directory (users, devices, groups of the panel's zone) into the
# panel DB, in the PANEL's naming convention (spec F4 + §12 step 5: "steve@trs.ztlp" becomes user
# "steve" = "steve.users.<zone>"; "blitz@trs.ztlp" becomes group "blitz"). READ-ONLY toward the
# NS: it never publishes, so the existing records stay as they are. Idempotent.
# Fixtures are the real shapes read from the prod NS (trs.ztlp) on 2026-10-24.
class NsImporterTest < ActiveSupport::TestCase
  class FakeNsClient
    attr_reader :calls

    def initialize(users: [], devices: [], groups: [], raise_error: nil)
      @by_type = { "user" => users, "device" => devices, "group" => groups }
      @raise_error = raise_error
      @calls = []
    end

    def list(_port, secret, type: nil, zone: nil, **_kw)
      raise @raise_error if @raise_error

      @calls << [ type, zone, secret.present? ]
      @by_type.fetch(type) { raise ArgumentError, "unexpected type #{type.inspect}" }
    end
  end

  def rec(name, data) = { name: name, type: "", data: data, created_at: 0, ttl: 0, serial: 0 }

  setup do
    @zone = Zone.primary
    @zone.update!(ns_admin_api_secret_ct: "ab" * 32)
    z = @zone.name
    @users = [
      rec("steve@#{z}", { "public_key" => "28" * 32, "email" => "steve@#{z}", "role" => "user", "devices" => [] }),
      rec("admin@#{z}", { "public_key" => "28" * 32, "email" => "steve@techrockstars.com", "role" => "admin" }),
      rec("aipc@aicomputer.#{z}", { "public_key" => "2a" * 32, "email" => "aipc@aicomputer.#{z}", "role" => "user" })
    ]
    @devices = [
      rec("stevens-macbook-pro-2.#{z}", { "assurance" => "software", "hardware_id" => "", "node_id" => "42" * 16,
                                          "owner" => "steve@#{z}", "public_key" => "3a" * 32, "registered_by" => "28" * 32 }),
      rec("stevens-mac-studio.#{z}", { "assurance" => "software", "node_id" => "fc" * 16, "owner" => "steve@#{z}",
                                       "public_key" => "65" * 32 })
    ]
    @groups = [ rec("blitz@#{z}", { "description" => "Comms Blitz users (blitz.#{z})", "members" => [ "steve@#{z}" ] }) ]
    @ns = FakeNsClient.new(users: @users, devices: @devices, groups: @groups)
  end

  test "imports users, devices with owners, and groups with members in the panel convention; publishes nothing" do
    Ztlp::Publisher.expects(:publish_user!).never
    Ztlp::Publisher.expects(:publish_device!).never
    Ztlp::Publisher.expects(:publish_group!).never
    r = Ztlp::NsImporter.run(@zone, ns_client: @ns)
    assert_equal({ "users" => 3, "devices" => 2, "groups" => 1, "memberships" => 1 }, r[:created])
    assert_empty r[:errors]

    steve = @zone.users.find_by!(username: "steve")
    assert_equal "steve.users.#{@zone.name}", steve.ns_name, "panel convention (spec F4)"
    assert_includes steve.notes.to_s, "steve@#{@zone.name}", "the original NS name is kept for reference"
    assert_equal "active", steve.status
    assert_equal "28" * 32, steve.signing_pubkey_hex
    assert_equal "admin", @zone.users.find_by!(username: "admin").role
    assert_includes @zone.users.find_by!(username: "aipc").notes.to_s, "aipc@aicomputer.#{@zone.name}"

    mbp = @zone.devices.find_by!(name: "stevens-macbook-pro-2")
    assert_equal "stevens-macbook-pro-2.#{@zone.name}", mbp.ns_name
    assert_equal steve, mbp.user, "owner steve@<zone> resolves to panel user steve"
    assert_equal "enrolled", mbp.status
    assert_equal "42" * 16, mbp.node_id_hex
    assert_equal "3a" * 32, mbp.noise_pubkey_hex
    assert_equal Ztlp::Assurance.level("software"), mbp.assurance

    blitz = @zone.groups.find_by!(name: "blitz")
    assert_equal [ steve ], blitz.users.to_a
    assert_equal [ [ "user", @zone.name, true ], [ "device", @zone.name, true ], [ "group", @zone.name, true ] ], @ns.calls
    assert AuditLog.exists?(action: "ns.import", status: "ok")
  end

  test "idempotent: a second run creates nothing and reports every record as already present" do
    Ztlp::NsImporter.run(@zone, ns_client: @ns)
    r = Ztlp::NsImporter.run(@zone, ns_client: @ns)
    assert_equal({ "users" => 0, "devices" => 0, "groups" => 0, "memberships" => 0 }, r[:created])
    assert_equal 6, r[:skipped].size
    assert_empty r[:errors]
  end

  test "an existing panel user with the same username is reused, not duplicated or modified" do
    mine = @zone.users.create!(username: "steve", display_name: "Steven Price", kind: "person", role: "admin",
                               status: "active")
    Ztlp::NsImporter.run(@zone, ns_client: @ns)
    assert_equal 1, @zone.users.where(username: "steve").count
    assert_equal "Steven Price", mine.reload.display_name
    assert_equal "admin", mine.role
    assert_equal mine, @zone.devices.find_by!(name: "stevens-mac-studio").user
  end

  test "records outside the panel zone are ignored" do
    ns = FakeNsClient.new(users: [ rec("mallory@evil.ztlp", { "public_key" => "11" * 32, "role" => "admin" }) ],
                          devices: [ rec("box.evil.ztlp", { "node_id" => "11" * 16, "public_key" => "11" * 32 }) ])
    r = Ztlp::NsImporter.run(@zone, ns_client: ns)
    assert_equal 0, r[:created].values.sum
    assert_nil @zone.users.find_by(username: "mallory")
    assert_nil @zone.devices.find_by(name: "box")
  end

  test "a device whose owner is not an NS user still imports, unowned" do
    ns = FakeNsClient.new(devices: [ rec("kiosk.#{@zone.name}", { "node_id" => "77" * 16, "public_key" => "77" * 32,
                                                                   "owner" => "ghost@#{@zone.name}" }) ])
    Ztlp::NsImporter.run(@zone, ns_client: ns)
    assert_nil @zone.devices.find_by!(name: "kiosk").user
  end

  test "not configured (no NS admin API secret) returns :not_configured and touches nothing" do
    @zone.update!(ns_admin_api_secret_ct: nil)
    assert_equal :not_configured, Ztlp::NsImporter.run(@zone, ns_client: @ns)
    assert_equal 0, @zone.users.count
  end

  test "an NS failure is reported, audited, and writes nothing" do
    ns = FakeNsClient.new(raise_error: Ztlp::NsClient::NsError.new(0x05, "unauthorized"))
    r = Ztlp::NsImporter.run(@zone, ns_client: ns)
    assert_match(/0x05/, r[:errors].join)
    assert_equal 0, @zone.users.count
    assert AuditLog.exists?(action: "ns.import", status: "failed")
  end
end
