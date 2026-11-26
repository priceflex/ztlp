# frozen_string_literal: true

require "test_helper"

# Device pickup (docs/admin-panel/PLAN-enrollment-token-trust.md): the client never calls the panel
# back for a binary token, so the panel looks up KEY "<device>.<zone>" on the name server itself.
class DevicePickupTest < ActiveSupport::TestCase
  class FakeNs
    attr_reader :queries, :trusted

    # Callers pass `FakeNs.new([name, "key"] => rec)`, which Ruby delivers as keywords.
    attr_reader :registered

    def initialize(records = nil, raise_error: nil, register_error: nil, **by_name_type)
      @records = records || by_name_type
      @raise_error = raise_error
      @register_error = register_error
      @queries = []
      @registered = []
    end

    # Publisher's NS write seam (register(ns_addr, timeout, name:, type:, data:, seed:)).
    def register(_addr, _timeout, name:, type:, data:, **)
      raise @register_error if @register_error

      @registered << { name: name, type: type, data: data }
      :ok
    end

    # Pickup must only accept answers signed by the zone's NS key (NsClient.query_verified).
    def query_verified(_addr, _timeout, name:, type:, trusted_keys:, **)
      raise @raise_error if @raise_error

      @queries << [ name, type ]
      @trusted = trusted_keys
      @records.fetch([ name, type ], :not_found)
    end

    # NS admin API listing (NsClient.list): every record of a type in a zone.
    def list(_port, _secret, type:, zone:, **)
      raise @raise_error if @raise_error

      @records.select { |(n, t), r| t == type && r.is_a?(Hash) && n.end_with?(".#{zone}") }.values
    end
  end

  def key_rec(name, node:, pub:, created_at:)
    { name: name, type: "key", data: { "node_id" => node, "algorithm" => "Ed25519", "public_key" => pub },
      created_at: created_at, ttl: 31_536_000, serial: 1 }
  end

  NS_KEY = "58" * 32

  setup do
    @zone = Zone.primary
    @zone.update!(ns_pubkey_hex: NS_KEY)
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
    assert_not_nil @enr.redeemed_at, "redeemed_at is set like the other redemption paths"
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

  test "the lookup trusts only the zone's NS key" do
    ns = FakeNs.new
    Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_equal [ NS_KEY ], ns.trusted
  end

  test "a zone without an NS key cannot pick devices up (an unsigned answer proves nothing)" do
    @zone.update!(ns_pubkey_hex: nil)
    ns = FakeNs.new
    assert_equal :no_ns_key, Ztlp::DevicePickup.check(@enr.reload, ns_client: ns)
    assert_empty ns.queries, "nothing is even asked"
  end

  test "an answer that fails verification leaves the token pending" do
    ns = FakeNs.new(raise_error: Ztlp::NsClient::UntrustedAnswer.new("untrusted signer"))
    assert_equal :untrusted, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_equal "pending", @enr.reload.status
  end

  test "a revoked user's pending token is not picked up" do
    @heidy.update!(status: "revoked")
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i + 5))
    assert_equal :revoked_user, Ztlp::DevicePickup.check(@enr.reload, ns_client: ns)
    assert_nil @zone.devices.find_by(name: "heidy-mba")
  end

  test "the job keeps going when one token's pickup fails with a database error" do
    second = @zone.enrollments.create!(kind: "user_device", user: @heidy, device_name: "heidy-ipad", status: "pending",
                                       expires_at: 1.hour.from_now, token_id: "ab" * 16, created_by_admin: @admin)
    seen = []
    original = Ztlp::DevicePickup.method(:check)
    Ztlp::DevicePickup.define_singleton_method(:check) do |enr, **|
      seen << enr.id
      raise ActiveRecord::RecordNotUnique, "dup node id" if enr.id == @enr_id_to_fail

      :pending
    end
    Ztlp::DevicePickup.instance_variable_set(:@enr_id_to_fail, @enr.id)
    results = EnrollmentPickupJob.new.perform(ns_client: FakeNs.new)
    assert_includes seen, second.id, "the later token is still checked"
    assert_equal :error, results[@enr.code]
    assert_equal :pending, results[second.code]
  ensure
    Ztlp::DevicePickup.define_singleton_method(:check, original) if original
    Ztlp::DevicePickup.remove_instance_variable(:@enr_id_to_fail) if Ztlp::DevicePickup.instance_variable_defined?(:@enr_id_to_fail)
  end

  # --- owner published the moment the device is picked up (whoami works right away) --------
  def authority!
    seed, = Ztlp::Ed25519.generate
    @zone.update!(authority_seed_ct: seed)
  end

  def fresh_key_ns(**kw)
    FakeNs.new({ [ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                     created_at: @enr.created_at.to_i + 30) }, **kw)
  end

  test "pickup publishes the DEVICE record with the owner immediately, not at the next republish" do
    authority!
    ns = fresh_key_ns
    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    dev = ns.registered.find { |r| r[:type] == "device" }
    assert dev, "a DEVICE record is written during pickup"
    assert_equal @name, dev[:name]
    assert_equal @heidy.reload.ns_name, dev[:data]["owner"], "the owner is the token's user"
    assert_equal "0e" * 32, dev[:data]["public_key"]
    assert_not_nil @zone.devices.find_by!(name: "heidy-mba").ns_published_at
  end

  test "a failed owner publish does not undo the redemption (the job retries it)" do
    authority!
    ns = fresh_key_ns(register_error: Ztlp::NsClient::NsError.new(0x05, "timeout"))
    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    d = @zone.devices.find_by!(name: "heidy-mba")
    assert_equal "enrolled", d.status
    assert_equal @heidy, d.user
    assert_nil d.ns_published_at, "left unpublished so the next job run retries"
    assert_equal "redeemed", @enr.reload.status
  end

  test "a device-only token (no user) publishes nothing" do
    authority!
    @enr.update_columns(user_id: nil, kind: "device_only")
    ns = fresh_key_ns
    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr.reload, ns_client: ns)
    assert_empty ns.registered
  end

  test "the job re-publishes an owned device whose owner never reached the name server" do
    authority!
    stuck = @zone.devices.create!(name: "heidy-pc", user: @heidy, status: "enrolled", node_id_hex: "44" * 16,
                                  noise_pubkey_hex: "55" * 32, enrolled_at: 10.minutes.ago, ns_published_at: nil)
    rekeyed = @zone.devices.create!(name: "heidy-pc2", user: @heidy, status: "enrolled", node_id_hex: "46" * 16,
                                    noise_pubkey_hex: "57" * 32, enrolled_at: 2.minutes.ago,
                                    ns_published_at: 1.hour.ago)
    done = @zone.devices.create!(name: "heidy-old", user: @heidy, status: "enrolled", node_id_hex: "66" * 16,
                                 noise_pubkey_hex: "77" * 32, enrolled_at: 1.hour.ago,
                                 ns_published_at: 30.minutes.ago)
    unowned = @zone.devices.create!(name: "spare-pc", status: "enrolled", node_id_hex: "88" * 16,
                                    noise_pubkey_hex: "99" * 32, enrolled_at: 5.minutes.ago)
    ns = FakeNs.new
    EnrollmentPickupJob.new.perform(ns_client: ns)
    names = ns.registered.select { |r| r[:type] == "device" }.map { |r| r[:name] }
    assert_includes names, stuck.ns_name
    assert_includes names, rekeyed.ns_name, "re-enrolled after its last publish"
    refute_includes names, done.ns_name
    refute_includes names, unowned.ns_name
    assert_not_nil stuck.reload.ns_published_at
  end

  test "the retry skips zones without an authority (nothing could be published there)" do
    @zone.update!(authority_seed_ct: nil)
    @zone.devices.create!(name: "heidy-pc", user: @heidy, status: "enrolled", node_id_hex: "44" * 16,
                          noise_pubkey_hex: "55" * 32, enrolled_at: 10.minutes.ago)
    ns = FakeNs.new
    EnrollmentPickupJob.new.perform(ns_client: ns)
    assert_empty ns.registered
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

  test "adopt refuses when the zone has no NS key" do
    @zone.update!(ns_pubkey_hex: nil)
    assert_raises(Ztlp::DevicePickup::NotFound) do
      Ztlp::DevicePickup.adopt!(@zone.reload, @heidy, "heidys-macbook-air-2", ns_client: FakeNs.new, admin: @admin)
    end
  end

  test "adopt refuses a revoked user" do
    @heidy.update!(status: "revoked")
    assert_raises(Ztlp::DevicePickup::NotFound) do
      Ztlp::DevicePickup.adopt!(@zone, @heidy, "heidys-macbook-air-2", ns_client: FakeNs.new, admin: @admin)
    end
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

  # ── token fingerprint (enrollment_ref): the client picks its own device name ──

  def ref_rec(name, ref, created_at:)
    r = key_rec(name, node: "4a" * 16, pub: "5b" * 32, created_at: created_at)
    r[:data]["enrollment_ref"] = ref
    r
  end

  test "the token's fingerprint finds the device under the name the client chose" do
    @zone.update!(ns_admin_api_secret_ct: "01" * 32)
    ref = Enrollment.token_ref_for("\x07" * 16)
    @enr.update!(token_ref: ref)
    chosen = "heidy-mba-heidy-smith.#{@zone.name}"
    ns = FakeNs.new([ chosen, "key" ] => ref_rec(chosen, ref, created_at: @enr.created_at.to_i + 30))

    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    d = @zone.devices.find_by!(name: "heidy-mba-heidy-smith")
    assert_equal "enrolled", d.status
    assert_equal @heidy, d.user
    assert_equal "redeemed", @enr.reload.status
    assert_equal "active", @heidy.reload.status
    assert_includes ns.queries, [ chosen, "key" ], "the listing hit is confirmed with a signed query"
  end

  test "a listed fingerprint the signed answer does not carry is ignored" do
    @zone.update!(ns_admin_api_secret_ct: "01" * 32)
    ref = Enrollment.token_ref_for("\x08" * 16)
    @enr.update!(token_ref: ref)
    chosen = "imposter.#{@zone.name}"
    listed = ref_rec(chosen, ref, created_at: @enr.created_at.to_i + 30)
    signed = key_rec(chosen, node: "4a" * 16, pub: "5b" * 32, created_at: @enr.created_at.to_i + 30)
    ns = FakeNs.new([ chosen, "key" ] => listed)
    ns.define_singleton_method(:query_verified) { |*_a, name:, type:, **| name == chosen ? signed : :not_found }

    assert_equal :pending, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert_nil @zone.devices.find_by(name: "imposter")
  end

  test "the fingerprint wins over an older record that has the typed name" do
    @zone.update!(ns_admin_api_secret_ct: "01" * 32)
    ref = Enrollment.token_ref_for("\x09" * 16)
    @enr.update!(token_ref: ref)
    chosen = "heidy-mba-2.#{@zone.name}"
    ns = FakeNs.new([ @name, "key" ] => key_rec(@name, node: "3f" * 16, pub: "0e" * 32,
                                                       created_at: @enr.created_at.to_i - 86_400),
                    [ chosen, "key" ] => ref_rec(chosen, ref, created_at: @enr.created_at.to_i + 30))

    assert_equal :redeemed, Ztlp::DevicePickup.check(@enr, ns_client: ns)
    assert @zone.devices.exists?(name: "heidy-mba-2")
  end

  test "token_ref_for matches the name server's enrollment_ref (first 16 bytes of SHA-256, hex)" do
    assert_equal Digest::SHA256.hexdigest("\x01" * 16)[0, 32], Enrollment.token_ref_for("\x01" * 16)
    assert_equal 32, Enrollment.token_ref_for(SecureRandom.random_bytes(16)).length
  end
end
