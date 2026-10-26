# frozen_string_literal: true

require "test_helper"

# Device pickup (docs/admin-panel/PLAN-enrollment-token-trust.md): the client never calls the panel
# back for a binary token, so the panel looks up KEY "<device>.<zone>" on the name server itself.
class DevicePickupTest < ActiveSupport::TestCase
  class FakeNs
    attr_reader :queries

    # Callers pass `FakeNs.new([name, "key"] => rec)`, which Ruby delivers as keywords.
    def initialize(records = nil, raise_error: nil, **by_name_type)
      @records = records || by_name_type
      @raise_error = raise_error
      @queries = []
    end

    def query(_addr, _timeout, name:, type:, **)
      raise @raise_error if @raise_error

      @queries << [ name, type ]
      @records.fetch([ name, type ], :not_found)
    end
  end

  def key_rec(name, node:, pub:, created_at:)
    { name: name, type: "key", data: { "node_id" => node, "algorithm" => "Ed25519", "public_key" => pub },
      created_at: created_at, ttl: 31_536_000, serial: 1 }
  end

  setup do
    @zone = Zone.primary
    @admin = Admin.create!(username: "op", display_name: "Op", pubkey_hex: "aa" * 32, role: "admin")
    @heidy = @zone.users.create!(username: "heidy", display_name: "Heidy", role: "user", status: "invited")
    @enr = @zone.enrollments.create!(kind: "user_device", user: @heidy, device_name: "heidy-mba",
                                     embed_relay_secret: true, max_uses: 1, uses: 0, status: "pending",
                                     expires_at: 1.hour.from_now, created_by_admin: @admin,
                                     token_id: "cc" * 16)
    @name = "heidy-mba.#{@zone.name}"
  end

  test "a KEY published after the token was minted redeems it and creates the enrolled device" do
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i + 30))
    result = Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_equal :redeemed, result
    d = @zone.devices.find_by!(name: "heidy-mba")
    assert_equal "enrolled", d.status
    assert_equal @heidy, d.user
    assert_equal "3f" * 16, d.node_id_hex
    assert_equal "0e" * 32, d.noise_pubkey_hex
    assert_equal @enr.id, d.enrollment_id
    assert_not_nil d.enrolled_at
    @enr.reload
    assert_equal "redeemed", @enr.status
    assert_equal 1, @enr.uses
    assert_equal d, @enr.redeemed_device
    assert_equal "active", @heidy.reload.status, "an invited user becomes active once a device enrolls"
    assert AuditLog.where(action: "enrollment.redeem", target_type: "Enrollment", target_id: @enr.id).exists?
  end

  test "no KEY yet leaves the token pending" do
    assert_equal :pending, Ztlp::DevicePickup.check(@enr, ns_client: FakeNs.new)
    assert_equal "pending", @enr.reload.status
    assert_nil @zone.devices.find_by(name: "heidy-mba")
  end

  test "a KEY older than the token is someone else's earlier enrollment, not this redemption" do
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i - 3600))
    assert_equal :stale_key, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_equal "pending", @enr.reload.status
  end

  test "checking twice is harmless" do
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i + 5))
    Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_equal :not_pending, Ztlp::DevicePickup.check(@enr.reload, ns_client: ns)
    assert_equal 1, @zone.devices.where(name: "heidy-mba").count
  end

  test "re-enrolling an existing device row updates its key instead of failing on the name" do
    old = @zone.devices.create!(name: "heidy-mba", user: @heidy, status: "enrolled",
                                node_id_hex: "11" * 16, noise_pubkey_hex: "22" * 32)
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i + 5))
    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    old.reload
    assert_equal "3f" * 16, old.node_id_hex
    assert_equal "0e" * 32, old.noise_pubkey_hex
    assert_equal @enr.id, old.enrollment_id
  end

  test "an expired or revoked token is not picked up" do
    @enr.update!(status: "revoked")
    assert_equal :not_pending, Ztlp::DevicePickup.check(@enr, ns_client: FakeNs.new)
  end

  test "a token without a device name cannot be picked up" do
    @enr.update_columns(device_name: nil)
    assert_equal :no_device_name, Ztlp::DevicePickup.check(@enr, ns_client: FakeNs.new)
  end

  test "an NS error is reported, not raised, so one bad lookup does not stop the job" do
    ns = FakeNs.new(raise_error: Ztlp::NsClient::NsError.new(0x05, "timeout"))
    assert_equal :ns_error, Ztlp::DevicePickup.check(@enr, ns_client: ns)
  end

  test "the job checks every pending token that has a device name and is not expired" do
    other = @zone.enrollments.create!(kind: "device_only", status: "pending", expires_at: 1.hour.from_now,
                                      token_id: "dd" * 16, created_by_admin: @admin)
    old = @zone.enrollments.create!(kind: "user_device", user: @heidy, device_name: "old-pc", status: "pending",
                                    expires_at: 1.hour.ago, token_id: "ee" * 16, created_by_admin: @admin)
    ns = FakeNs.new
    EnrollmentPickupJob.new.perform(ns_client: ns)
    names = ns.queries.map(&:first)
    assert_includes names, @name
    refute_includes names, "old-pc.#{@zone.name}"
    assert other && old
  end

  # --- adopt an already-enrolled device by name (no re-key) -----------------------------------
  test "adopt creates the device from its existing KEY record for the given user" do
    ns = FakeNs.new([ "heidys-macbook-air-2.#{@zone.name}", "key" ] =>
                      key_rec("heidys-macbook-air-2.#{@zone.name}", node: "3f" * 16, pub: "0e" * 32, created_at: 1))
    d = Ztlp::DevicePickup.adopt!(@zone, @heidy, "heidys-macbook-air-2", ns_client: ns, admin: @admin)
    assert d.persisted?
    assert_equal "enrolled", d.status
    assert_equal @heidy, d.user
    assert_equal "0e" * 32, d.noise_pubkey_hex
    assert AuditLog.where(action: "device.adopt").exists?
  end

  test "adopt refuses a name with no KEY record" do
    err = assert_raises(Ztlp::DevicePickup::NotFound) do
      Ztlp::DevicePickup.adopt!(@zone, @heidy, "ghost", ns_client: FakeNs.new, admin: @admin)
    end
    assert_match(/ghost\./, err.message)
  end

  test "adopt refuses a full name or a bad label" do
    [ "heidy.#{@zone.name}", "Bad Name", "" ].each do |bad|
      assert_raises(ActiveRecord::RecordInvalid, Ztlp::DevicePickup::NotFound, bad) do
        Ztlp::DevicePickup.adopt!(@zone, @heidy, bad, ns_client: FakeNs.new, admin: @admin)
      end
    end
  end
end
