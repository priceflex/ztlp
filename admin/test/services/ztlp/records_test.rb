# frozen_string_literal: true

require "test_helper"

# Mapping contract for panel rows → NS record data.
#
# THE PII TEST (spec §3, decision 10): `user_data` MUST NOT include
# display_name, email, phone, first_name, last_name or attributes.
# The NS is the authentication authority (Service A); PII lives only in
# the panel DB (Service B).
class ZtlpRecordsTest < ActiveSupport::TestCase
  def zone
    @zone ||= Zone.create!(name: "test.ztlp", ns_addr: "127.0.0.1:23196")
  end

  def make_user(overrides = {})
    @user ||= zone.users.create!(
      {
        username: "steve",
        kind: "person",
        role: "user",
        status: "active",
        display_name: "Steve Price",
        first_name: "Steve",
        last_name: "Price",
        email: "steve@techrockstars.com",
        phone: "+1-555-000-1234",
        sms_opt_in: true,
        signing_pubkey_hex: "ab" * 32
      }.merge(overrides)
    )
  end

  def make_device(user, name, overrides = {})
    zone.devices.create!(
      {
        name: name,
        node_id_hex: format("%032x", rand(0xFFFFFFFFFFFF)),
        noise_pubkey_hex: format("%064x", rand(0xFFFFFFFFFFFF)),
        key_source: "file",
        assurance: 2,
        status: "enrolled",
        user: user
      }.merge(overrides)
    )
  end

  def make_device_unowned(name, overrides = {})
    zone.devices.create!(
      {
        name: name,
        node_id_hex: format("%032x", rand(0xFFFFFFFFFFFF)),
        noise_pubkey_hex: format("%064x", rand(0xFFFFFFFFFFFF)),
        key_source: "unknown",
        assurance: 1,
        status: "pending"
      }.merge(overrides)
    )
  end

  test "user record carries no PII" do
    user = make_user
    data = Ztlp::Records.user_data(user)

    # The NS record must be opaque identifiers + keys + roles only.
    # Exact §4 shape: no extra keys (username/ns_name are the record NAME, not data).
    assert_equal %w[devices email public_key role], data.keys.sort
    assert_equal "user", data["role"]
    assert_equal "ab" * 32, data["public_key"]
    assert_equal "", data["email"]   # always "" per spec (G7)
    assert_equal [], data["devices"]

    # None of the PII fields may appear in the encoded CBOR bytes.
    cbor = Ztlp::Cbor.encode(data)
    refute_includes cbor, "Steve Price".b
    refute_includes cbor, "steve@techrockstars.com".b
    refute_includes cbor, "+1-555-000-1234".b
    refute_includes cbor, "display_name".b
    refute_includes cbor, "first_name".b
    refute_includes cbor, "last_name".b
    refute_includes cbor, "phone".b
    refute_includes cbor, "sms_opt_in".b
    refute_includes cbor, "attributes".b
  end

  test "user_data includes owned devices as ns names" do
    user = make_user
    device = make_device(user, "mbp-1")
    data = Ztlp::Records.user_data(user)
    assert_equal [ "mbp-1.test.ztlp" ], data["devices"]
    assert_equal device.ns_name, data["devices"].first
  end

  test "group record carries no description text from panel" do
    group = zone.groups.create!(name: "admins")
    member = make_user
    group.users << member

    data = Ztlp::Records.group_data(group)
    assert_equal [ "steve.users.test.ztlp" ], data["members"]
    # description is panel-only (spec §6.3: "description is panel-only too")
    assert_equal "", data["description"]
  end

  test "device record carries node_id, public_key, owner, assurance, key_source" do
    user = make_user
    device = make_device(user, "mbp-1", key_source: "tpm", assurance: 3)

    data = Ztlp::Records.device_data(device)
    assert_equal device.node_id_hex, data["node_id"]
    assert_equal device.noise_pubkey_hex, data["public_key"]
    assert_equal "steve.users.test.ztlp", data["owner"]
    assert_equal "device-bound", data["assurance"]   # level 3 → "device-bound"
    assert_equal "tpm", data["key_source"]
  end

  test "device record without owner has empty owner" do
    device = make_device_unowned("headless-1")

    data = Ztlp::Records.device_data(device)
    assert_equal "", data["owner"]
    assert_equal "unknown", data["assurance"]
  end

  test "authority_data for a zone" do
    seed_hex, pub_hex = Ztlp::Ed25519.generate
    zone.authority_seed_ct = seed_hex
    zone.save!

    data = Ztlp::Records.authority_data(zone)
    assert_equal "zone:test.ztlp", data["node_id"]
    assert_equal true, data["delegation"]
    assert_equal "zone-authority", data["role"]
    assert_equal "Ed25519", data["algorithm"]
    # public_key is the authority pubkey (32 bytes hex); no "zone" key —
    # the zone name IS the record name, not part of the data payload.
    assert_equal pub_hex, data["public_key"]
    refute data.key?("zone")
  end

  test "authority_data raises when no seed is configured" do
    fresh_zone = Zone.create!(name: "empty.ztlp", ns_addr: "127.0.0.1:23196")
    assert_raises(Ztlp::Records::Error) { Ztlp::Records.authority_data(fresh_zone) }
  end

  test "revoke_data" do
    data = Ztlp::Records.revoke_data("steve.users.test.ztlp", "user disabled")
    assert_equal [ "steve.users.test.ztlp" ], data["revoked_ids"]
    assert_equal "user disabled", data["reason"]
    assert_equal "now", data["effective_at"]
  end

  test "assurance level maps to the NS wire value, never the display label" do
    user = make_user
    [
      [ 1, "unknown" ],
      [ 2, "software" ],
      [ 3, "device-bound" ],
      [ 4, "hardware" ] # display says "hardware (unverified)"; the record carries the level
    ].each do |level, label|
      device = make_device(user, "dev-#{level}", assurance: level,
                                    node_id_hex: format("%032x", level),
                                    noise_pubkey_hex: format("%064x", level * 2))
      data = Ztlp::Records.device_data(device)
      assert_equal label, data["assurance"], "level #{level} should map to #{label}"
      assert_includes Ztlp::Assurance::LEVELS.keys, data["assurance"]
    end
  end
end
