# frozen_string_literal: true

require "test_helper"

# Real-wire roundtrip against a live local NS (ztlp-ns:v0.35.20).
#
# The unit fixtures in ns_client_test.rb were built from the Elixir source,
# not from a live NS. This test is the real proof: it runs Ztlp::NsClient
# against a running NS started by scripts/test-ns.sh and asserts the full
# wire path works end to end — signed 0x09 register (0x06 ack), 0x01 query
# (0x02 reply with the DEVICE's assurance), /admin/records list, and the
# authorization enforcement (a GROUP write signed by a NON-authority seed is
# rejected 0x05).
#
# Gated on ZTLP_TEST_NS: when unset the whole suite skips (CI / default dev
# runs are hermetic). scripts/test-ns.sh up sets ZTLP_TEST_NS=1 and writes
# the throwaway env (addr, admin port, admin secret) to a file this test
# reads. The NS is stopped by scripts/test-ns.sh down in the same tick.
#
# Gating is done with `raise Minitest::Skip` inside before_setup: a single
# guard that Minitest converts to a skip for every test in the class, without
# a conditional method definition (which the Ruby parser rejects inside a
# bare `unless` block at class level).
class NsRoundtripTest < ActiveSupport::TestCase
  def self.enabled?
    ENV["ZTLP_TEST_NS"] == "1"
  end

  def setup
    unless self.class.enabled?
      raise Minitest::Skip, "set ZTLP_TEST_NS=1 and run scripts/test-ns.sh up first"
    end
  end

  ZONE = "test.ztlp".freeze
  NS_ADDR = ENV.fetch("ZTLP_TEST_NS_ADDR", "127.0.0.1:23196")
  ADMIN_PORT = ENV.fetch("ZTLP_TEST_NS_ADMIN_API_PORT", "9203").to_i
  TIMEOUT = 5

  # A throwaway admin-API secret for THIS test's own HMAC calls. The roundtrip
  # uses it for list; the NS was started with its own secret (in the env file),
  # so read it from the same file the script wrote, never print it.
  def self.admin_secret
    @admin_secret ||= ENV["ZTLP_TEST_NS_ADMIN_API_SECRET"].to_s
  end

  # Register the zone-authority delegation KEY exactly once per process.
  # Memoized so the 5 tests in this class share a single KEY registration
  # (the NS rate-limits the first registration of a fresh KEY per {name,type}).
  def self._ensure_zone_authority(ns_addr, timeout, zone_name, public_key:)
    @_zone_authority ||= begin
      data = {
        "algorithm" => "Ed25519",
        "node_id" => "zone:#{zone_name}",
        "public_key" => public_key,
        "delegation" => true,
        "role" => "zone-authority"
      }
      Ztlp::NsClient.register(ns_addr, timeout, name: zone_name, type: "key", data: data, seed: AUTHORITY[0])
      zone_name
    end
  end

  # Fresh unique suffix per run so re-runs against a persistent NS (or a
  # same-tick re-run) don't collide with earlier records or hit the NS's
  # per-{name,type} 60s rate limit.
  RUN = format("%x", Random.bytes(8).unpack1("Q>")).freeze

  # Zone authority key — registers a KEY record at the zone name with
  # delegation: true so it can write user/group/device records.
  AUTHORITY = Ztlp::Ed25519.generate.freeze
  # A non-authority key, for the negative GROUP write.
  INTRUDER = Ztlp::Ed25519.generate.freeze

  def self.authority_pubkey_hex = AUTHORITY[1]

  def client = Ztlp::NsClient
  def zone = ZONE

  # ── helpers ────────────────────────────────────────────────────────

  # Register the zone authority KEY record (delegation: true) at the zone
  # name. This is what makes the authority seed a valid zone signer for the
  # rest of the test.
  #
  # The NS rate-limits per {name,type} (60s window); the FIRST registration of
  # a fresh KEY is rate-limited because the KEY doesn't exist yet (the
  # zone-authority bypass only kicks in once check_zone_authority finds the
  # delegation KEY). Minitest runs each test in a fresh instance, so memoize
  # at class level: the KEY is registered ONCE per process (first test to
  # call it) and the zone name is returned to every test after. A fresh RUN
  # suffix per run keeps re-runs from colliding with a prior run's record.
  def ensure_zone_authority
    self.class._ensure_zone_authority(NS_ADDR, TIMEOUT, "#{zone}-#{RUN}",
                                       public_key: AUTHORITY[1])
  end

  # Distinct record names per test (suffixed) so no two tests register the
  # same {name,type} within the NS's 60s rate-limit window. The zone name
  # carries the per-run RUN suffix; the record names carry a per-test tag.
  def names(zone_name, tag)
    {
      user: "u#{tag}.users.#{zone_name}",
      group: "g#{tag}.groups.#{zone_name}",
      device: "d#{tag}.#{zone_name}"
    }
  end

  def user_data(user_ns_name, devices_ns_names)
    { "public_key" => AUTHORITY[1], "role" => "user", "devices" => devices_ns_names, "email" => "" }
  end

  def group_data(member_ns_names)
    { "members" => member_ns_names, "description" => "" }
  end

  def device_data(owner_ns_name, node_id_hex, noise_pub_hex)
    {
      "node_id" => node_id_hex,
      "public_key" => noise_pub_hex,
      "owner" => owner_ns_name,
      "assurance" => "device-bound",
      "key_source" => "tpm"
    }
  end

  def assert_ns_error(code)
    err = assert_raises(client::NsError) { yield }
    assert_equal code, err.code, "expected NS rejection code 0x#{code.to_s(16)}, got 0x#{err.code.to_s(16)} (#{err.reason})"
  end

  # ── tests ──────────────────────────────────────────────────────────

  test "register the zone authority KEY at the zone → 0x06 (:ok)" do
    zn = ensure_zone_authority
    # ensure_zone_authority returns the zone name (a String) on a 0x06 ack;
    # it raises NsError on any rejection. Re-registering the same name is
    # rate-limited, so assert the returned name matches our RUN suffix.
    assert_kind_of String, zn
    assert_match(/\A#{zone}-#{RUN}\z/, zn)
  end

  test "register USER, GROUP and DEVICE signed by the authority → 0x06" do
    zn = ensure_zone_authority
    ns = names(zn, "2")

    # USER
    client.register(NS_ADDR, TIMEOUT, name: ns[:user], type: "user",
                                           data: user_data(ns[:user], [ ns[:device] ]), seed: AUTHORITY[0])
    # GROUP (members = the user's ns name)
    client.register(NS_ADDR, TIMEOUT, name: ns[:group], type: "group",
                                           data: group_data([ ns[:user] ]), seed: AUTHORITY[0])
    # DEVICE (owned by the user, assurance device-bound)
    node_id_hex = format("%064x", Random.bytes(32).unpack1("Q>"))[0, 64]
    noise_pub_hex = format("%064x", Random.bytes(32).unpack1("Q>"))[0, 64]
    client.register(NS_ADDR, TIMEOUT, name: ns[:device], type: "device",
                                            data: device_data(ns[:user], node_id_hex, noise_pub_hex), seed: AUTHORITY[0])

    # Each register returned :ok (no NsError raised). A query back proves the
    # device persisted with its assurance — the real wire-format check.
    reply = client.query(NS_ADDR, TIMEOUT, name: ns[:device], type: "device")
    refute_equal :not_found, reply, "device should be present after register"
    assert_equal "device-bound", reply[:data]["assurance"],
                 "query should round-trip the device assurance field"
  end

  test "query returns the device with its assurance (real 0x02 parse)" do
    zn = ensure_zone_authority
    ns = names(zn, "3")
    node_id_hex = format("%064x", Random.bytes(32).unpack1("Q>"))[0, 64]
    noise_pub_hex = format("%064x", Random.bytes(32).unpack1("Q>"))[0, 64]
    data = device_data(ns[:user], node_id_hex, noise_pub_hex)
    client.register(NS_ADDR, TIMEOUT, name: ns[:device], type: "device", data: data, seed: AUTHORITY[0])

    reply = client.query(NS_ADDR, TIMEOUT, name: ns[:device], type: "device")
    assert_kind_of Hash, reply, "0x02 reply should parse to a Hash, got #{reply.inspect}"
    assert_equal ns[:device], reply[:name]
    assert_equal "device", reply[:type]
    assert_equal "device-bound", reply[:data]["assurance"]
    assert_equal "tpm", reply[:data]["key_source"]
    assert_equal node_id_hex, reply[:data]["node_id"]
    assert_kind_of Integer, reply[:serial], "parsed reply should carry a serial"
  end

  test "list(type: group) via /admin/records includes the authority-written group" do
    zn = ensure_zone_authority
    ns = names(zn, "4")
    client.register(NS_ADDR, TIMEOUT, name: ns[:group], type: "group",
                                           data: group_data([ ns[:user] ]), seed: AUTHORITY[0])

    secret = self.class.admin_secret
    refute secret.empty?, "admin API secret missing — run scripts/test-ns.sh up"
    recs = client.list(ADMIN_PORT, secret, type: "group")
    group_names = recs.map { |r| r[:name] }
    assert_includes group_names, ns[:group],
                    "list(type: group) should include the authority-written group #{ns[:group]}"
  end

  test "a GROUP write signed by a NON-authority seed → NsError 0x05 (unauthorized)" do
    zn = ensure_zone_authority
    ns = names(zn, "5")
    # Register the authority's own group first so the zone exists, then try to
    # write a DIFFERENT group name signed by the intruder key. GROUP records
    # do not allow self-registration (registration_auth.ex: group →
    # :zone_authority_required), so a non-authority signature must be rejected
    # 0x05 unauthorized.
    client.register(NS_ADDR, TIMEOUT, name: ns[:group], type: "group",
                                           data: group_data([ ns[:user] ]), seed: AUTHORITY[0])
    intruder_group = "intruder.groups.#{zn}"
    assert_ns_error(0x05) do
      client.register(NS_ADDR, TIMEOUT, name: intruder_group, type: "group",
                                            data: group_data([]), seed: INTRUDER[0])
    end
  end
end
