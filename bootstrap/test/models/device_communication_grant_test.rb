# frozen_string_literal: true

require "test_helper"

# Unit tests for DeviceCommunicationGrant — the table that records
# which ZtlpDevice may initiate communication to which.
#
# BS-PR-5. Coverage:
#
#   * Validation: source != target, same network, unique pair
#   * Default granted_at populated on create
#   * revoke! is idempotent + writes an audit log row
#   * Scopes: active / revoked / between(src, tgt)
class DeviceCommunicationGrantTest < ActiveSupport::TestCase
  setup do
    @alice_laptop = ztlp_devices(:alice_laptop)
    @alice_phone  = ztlp_devices(:alice_phone)
    @bob_desktop  = ztlp_devices(:bob_desktop)
  end

  # ── Happy path ──────────────────────────────────────────────────

  test "creates a grant between two devices in the same network" do
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop,
      target_device: @bob_desktop
    )
    assert grant.persisted?
    assert grant.active?
    refute grant.revoked?
  end

  test "auto-populates granted_at when not provided" do
    pre = Time.current
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop,
      target_device: @bob_desktop
    )
    assert grant.granted_at >= pre
    assert grant.granted_at <= Time.current + 1.second
  end

  test "honors explicit granted_at" do
    explicit = 1.day.ago.change(usec: 0)
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop,
      target_device: @bob_desktop,
      granted_at: explicit
    )
    assert_equal explicit.to_i, grant.granted_at.to_i
  end

  # ── Validations ─────────────────────────────────────────────────

  test "rejects source == target (self-grant is meaningless)" do
    grant = DeviceCommunicationGrant.new(
      source_device: @alice_laptop,
      target_device: @alice_laptop
    )
    refute grant.valid?
    assert_match(/differ from source device/, grant.errors.full_messages.join)
  end

  test "rejects cross-network grants" do
    # Build a Network + ZtlpDevice in a separate network on the fly
    # so we don't have to extend the fixture file.
    other_network = Network.create!(
      name: "Other Network",
      zone: "other.acme.ztlp",
      status: "created",
      enrollment_secret_ciphertext: "0" * 64
    )
    foreign_device = ZtlpDevice.create!(
      name: "foreign-device",
      network: other_network,
      node_id: "node-foreign-001",
      status: "enrolled"
    )

    grant = DeviceCommunicationGrant.new(
      source_device: @alice_laptop,
      target_device: foreign_device
    )
    refute grant.valid?
    assert_match(/same network/, grant.errors.full_messages.join)
  end

  test "(source, target) pair is unique" do
    DeviceCommunicationGrant.create!(
      source_device: @alice_laptop,
      target_device: @bob_desktop
    )
    dup = DeviceCommunicationGrant.new(
      source_device: @alice_laptop,
      target_device: @bob_desktop
    )
    refute dup.valid?
    assert_match(/already has a grant/, dup.errors.full_messages.join)
  end

  test "reverse direction is a SEPARATE grant" do
    # A → B and B → A are independent rows. Operators may want to
    # authorize one direction without the other.
    a_to_b = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    b_to_a = DeviceCommunicationGrant.create!(
      source_device: @bob_desktop, target_device: @alice_laptop
    )
    refute_equal a_to_b, b_to_a
    assert a_to_b.persisted?
    assert b_to_a.persisted?
  end

  # ── revoke! ─────────────────────────────────────────────────────

  test "revoke! soft-deletes by setting revoked_at" do
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    assert grant.revoke!
    assert grant.revoked?
    refute grant.active?
    assert grant.revoked_at.present?
  end

  test "revoke! is idempotent — second call returns false, no change" do
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    grant.revoke!
    first_revoked_at = grant.revoked_at

    refute grant.revoke!
    grant.reload
    assert_equal first_revoked_at.to_i, grant.revoked_at.to_i
  end

  test "revoke! writes a device_grant.revoked audit log entry" do
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )

    assert_difference -> { AuditLog.where(action: "device_grant.revoked").count }, 1 do
      grant.revoke!(admin_user: admin_users(:super_admin))
    end

    entry = AuditLog.where(action: "device_grant.revoked").last
    details = entry.parsed_details
    assert_equal @alice_laptop.id, details["source_device_id"]
    assert_equal @bob_desktop.id,  details["target_device_id"]
    assert_equal admin_users(:super_admin).id, details["revoked_by_admin_user_id"]
  end

  test "revoke! no-op does NOT write an audit log entry" do
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    grant.revoke!

    assert_no_difference -> { AuditLog.where(action: "device_grant.revoked").count } do
      grant.revoke!  # already revoked → no-op
    end
  end

  # ── Scopes ──────────────────────────────────────────────────────

  test "active scope returns only non-revoked grants" do
    g1 = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    g2 = DeviceCommunicationGrant.create!(
      source_device: @alice_phone, target_device: @bob_desktop
    )
    g2.revoke!

    assert_includes DeviceCommunicationGrant.active, g1
    refute_includes DeviceCommunicationGrant.active, g2
  end

  test "revoked scope returns only revoked grants" do
    g1 = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    g2 = DeviceCommunicationGrant.create!(
      source_device: @alice_phone, target_device: @bob_desktop
    )
    g2.revoke!

    refute_includes DeviceCommunicationGrant.revoked, g1
    assert_includes DeviceCommunicationGrant.revoked, g2
  end

  test "between(src, tgt) scope finds a specific ordered pair" do
    g = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    found = DeviceCommunicationGrant.between(@alice_laptop.id, @bob_desktop.id)
    assert_includes found, g

    not_found = DeviceCommunicationGrant.between(@bob_desktop.id, @alice_laptop.id)
    refute_includes not_found, g
  end
end
