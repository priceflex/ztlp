# frozen_string_literal: true

require "test_helper"

# Slice 4c-i: Ztlp::Publisher. The single seam between panel rows and the NS:
# calls NsClient with the zone's authority seed, sets ns_published_at, audits
# `ns.publish` with {name, type, result} — NEVER the record data (spec §6.2,
# audit rule: "never data"). NsClient is mocked (mocha); the real wire format
# is covered by ns_client_test.rb and the 4c-ii roundtrip.
class PublisherTest < ActiveSupport::TestCase
  class FakeAdmin
    def id = 99
    def to_param = "99"
  end

  class FakeNs
    attr_reader :calls

    def initialize(throw: nil)
      @throw = throw
      @calls = []
    end

    # The registered seam method: Publisher calls this with the exact
    # NsClient.register keyword contract.
    def register(ns_addr, timeout, name:, type:, data:, seed:)
      @calls << { ns_addr: ns_addr, timeout: timeout, name: name, type: type,
                  data: data, seed: seed }
      raise @throw if @throw
      :ok
    end
  end

  def setup
    # authority_seed_ct holds the 64-hex Ed25519 seed exactly as identity.json's
    # signing_key_seed (the form NsClient.register(seed:) and Ed25519.sign take).
    @seed_hex, @authority_pub = Ztlp::Ed25519.generate
    @zone = Zone.create!(name: "test.ztlp", ns_addr: "127.0.0.1:23096", authority_seed_ct: @seed_hex)
    @user = @zone.users.create!(username: "alice", ns_name: "alice.users.test.ztlp",
                                role: "user", status: "active",
                                signing_pubkey_hex: "00" * 32)
    @group = @zone.groups.create!(name: "eng", ns_name: "eng.groups.test.ztlp")
    @device = @zone.devices.create!(name: "alice-mbp", ns_name: "alice-mbp.test.ztlp",
                                    node_id_hex: "ab" * 16, noise_pubkey_hex: "cd" * 32,
                                    assurance: 2, key_source: "file", status: "enrolled",
                                    user: @user)
    @fake = FakeNs.new
  end

  def audit_for(entity)
    AuditLog.where(action: "ns.publish",
                   target_type: entity.class.name, target_id: entity.id).order(:id)
  end

  # The Publisher takes the NS client as a seam so these tests stay hermetic
  # (mocha stubs cannot capture args into a per-test object).
  def publish_user(user, fake = @fake, **opts)
    Ztlp::Publisher.publish_user!(user, ns_client: fake, **opts)
  end

  def publish_group(group, fake = @fake, **opts)
    Ztlp::Publisher.publish_group!(group, ns_client: fake, **opts)
  end

  def publish_device(device, fake = @fake, **opts)
    Ztlp::Publisher.publish_device!(device, ns_client: fake, **opts)
  end

  def revoke(zone, fake = @fake, **opts)
    Ztlp::Publisher.revoke!(zone, ns_client: fake, **opts)
  end

  test "publish_user! registers USER under ns_name with the zone authority seed, stamps, audits ok" do
    result = publish_user(@user)

    assert_equal :ok, result
    call = @fake.calls.pop
    assert_equal @zone.ns_addr, call[:ns_addr]
    assert_equal "alice.users.test.ztlp", call[:name]
    assert_equal "user", call[:type]
    assert_equal Ztlp::Records.user_data(@user), call[:data]
    assert_equal @seed_hex, call[:seed]
    assert_match(/\A\h{64}\z/, call[:seed])
    assert_not_nil @user.reload.ns_published_at
    row = audit_for(@user).last
    assert_equal "ok", row.status
    assert_equal({ "name" => "alice.users.test.ztlp", "type" => "user", "result" => "ok" }, row.details)
  end

  test "publish_group! registers the GROUP and records the user member list" do
    @group.users << @user

    publish_group(@group)

    call = @fake.calls.pop
    assert_equal "eng.groups.test.ztlp", call[:name]
    assert_equal "group", call[:type]
    assert_equal({ "members" => [ "alice.users.test.ztlp" ], "description" => "" }, call[:data])
    row = audit_for(@group).last
    assert_equal({ "name" => "eng.groups.test.ztlp", "type" => "group", "result" => "ok" }, row.details)
  end

  test "publish_device! registers the DEVICE with the wire assurance value" do
    publish_device(@device)

    call = @fake.calls.pop
    assert_equal "alice-mbp.test.ztlp", call[:name]
    assert_equal "device", call[:type]
    assert_equal "software", call[:data]["assurance"]
    assert_equal "alice.users.test.ztlp", call[:data]["owner"]
  end

  test "publish_* never puts record data into the audit details" do
    publish_user(@user)
    publish_group(@group)
    publish_device(@device)

    AuditLog.where(action: "ns.publish").find_each do |row|
      details = row.details
      refute_includes details.to_json, "00" * 32, "pubkey leaked into audit"
      refute_includes details.to_json, "ab" * 16, "node id leaked into audit"
      assert_equal Set["name", "type", "result"], details.keys.to_set
    end
  end

  test "publish_user! surfaces NS failure as NsError and audits failed without data" do
    boom = Ztlp::NsClient::NsError.new(0x05, "unauthorized")
    failing = FakeNs.new(throw: boom)

    assert_raises(Ztlp::NsClient::NsError) { publish_user(@user, failing) }

    assert_nil @user.reload.ns_published_at
    row = audit_for(@user).last
    assert_equal "failed", row.status
    assert_equal({ "name" => "alice.users.test.ztlp", "type" => "user", "result" => "0x05 unauthorized" },
                 row.details)
  end

  test "revoke! writes a REVOKE record for the ns name, never republishing the entity" do
    result = revoke(@zone, name: "alice-mbp.test.ztlp",
                    target: @device, reason: "stolen")

    assert_equal :ok, result
    call = @fake.calls.pop
    assert_equal "revoke", call[:type]
    # REVOKE records live at "revoke.<name>" (ztlp-cli.rs:11293 admin revoke).
    assert_equal "revoke.alice-mbp.test.ztlp", call[:name]
    assert_match(/\A\h{64}\z/, call[:seed])
    assert_equal({ "revoked_ids" => [ "alice-mbp.test.ztlp" ], "reason" => "stolen",
                   "effective_at" => "now" }, call[:data])
    assert_nil @device.reload.ns_published_at
    row = audit_for(@device).last
    assert_equal "ok", row.status
    assert_equal "revoke", row.details["type"]
    refute_includes row.details.to_json, "ab" * 16, "node id leaked into audit"
  end

  test "revoke! with also: lists every id in ONE record named for the primary name" do
    assert_equal :ok, revoke(@zone, name: "alice.users.test.ztlp", also: [ "alice-mbp.test.ztlp", "alice-pc.test.ztlp" ],
                                    reason: "user revoked")
    call = @fake.calls.pop
    assert_equal "revoke.alice.users.test.ztlp", call[:name]
    assert_equal [ "alice.users.test.ztlp", "alice-mbp.test.ztlp", "alice-pc.test.ztlp" ], call[:data]["revoked_ids"]
    assert_empty @fake.calls, "one REVOKE record, not one per id"
  end

  test "a zone without an authority seed raises before any NS call" do
    bare = Zone.create!(name: "empty.ztlp", ns_addr: "127.0.0.1:23096")
    u = bare.users.create!(username: "bob", ns_name: "bob.users.empty.ztlp",
                           role: "user", status: "active", signing_pubkey_hex: "11" * 32)

    assert_raises(Ztlp::NsClient::NsError) { publish_user(u) }
    assert_empty @fake.calls
  end
end
