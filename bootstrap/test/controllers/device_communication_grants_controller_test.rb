# frozen_string_literal: true

require "test_helper"

# Integration tests for DeviceCommunicationGrantsController — the
# dashboard UI for the device-to-device permissions table BS-PR-5
# introduced.
#
# Coverage:
#
#   * Authorization: signed-in admin required (any role; not just super)
#   * Index: lists grants scoped to the network's devices
#   * Create: valid params → grant + audit log
#   * Create: rejects same-source-and-target and cross-network grants
#   * Revoke: soft-deletes + audit log; idempotent
#   * Destroy: hard-deletes + audit log
#   * Network-scoped lookup: cannot touch a grant from another network
#     via URL-walking
class DeviceCommunicationGrantsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network      = networks(:office)
    @admin        = admin_users(:regular_admin)
    @alice_laptop = ztlp_devices(:alice_laptop)
    @alice_phone  = ztlp_devices(:alice_phone)
    @bob_desktop  = ztlp_devices(:bob_desktop)
  end

  def sign_in_as(admin_user)
    post login_path, params: { email: admin_user.email, password: "password123" }
  end

  # ── Authorization ───────────────────────────────────────────────

  test "unauthenticated user is redirected to login" do
    get network_device_communication_grants_path(@network)
    assert_redirected_to login_path
  end

  # ── Index ───────────────────────────────────────────────────────

  test "index lists grants whose source belongs to this network" do
    sign_in_as(@admin)

    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )

    get network_device_communication_grants_path(@network)
    assert_response :success
    assert_match @alice_laptop.name, response.body
    assert_match @bob_desktop.name, response.body
    assert_includes response.body, "→"
  end

  test "index shows empty-state when no grants exist" do
    sign_in_as(@admin)
    DeviceCommunicationGrant.delete_all

    get network_device_communication_grants_path(@network)
    assert_response :success
    assert_match(/No grants yet/i, response.body)
  end

  # ── Create ──────────────────────────────────────────────────────

  test "creates a grant with valid params" do
    sign_in_as(@admin)

    assert_difference -> { DeviceCommunicationGrant.count }, 1 do
      assert_difference -> { AuditLog.where(action: "device_grant.created").count }, 1 do
        post network_device_communication_grants_path(@network), params: {
          device_communication_grant: {
            source_device_id: @alice_laptop.id,
            target_device_id: @bob_desktop.id,
            notes: "Allow alice's laptop to ssh to bob's desktop"
          }
        }
      end
    end

    follow_redirect!
    assert_match(/Grant created/i, response.body)
  end

  test "rejects a self-grant (source == target)" do
    sign_in_as(@admin)

    assert_no_difference -> { DeviceCommunicationGrant.count } do
      post network_device_communication_grants_path(@network), params: {
        device_communication_grant: {
          source_device_id: @alice_laptop.id,
          target_device_id: @alice_laptop.id
        }
      }
    end

    assert_response :unprocessable_entity
    assert_match(/differ from source device/i, response.body)
  end

  test "rejects a cross-network grant" do
    sign_in_as(@admin)
    other_network = Network.create!(
      name: "Cross Net", zone: "other.acme.ztlp", status: "created",
      enrollment_secret_ciphertext: "0" * 64
    )
    foreign = ZtlpDevice.create!(
      name: "foreign", network: other_network, node_id: "node-foreign-1",
      status: "enrolled"
    )

    assert_no_difference -> { DeviceCommunicationGrant.count } do
      post network_device_communication_grants_path(@network), params: {
        device_communication_grant: {
          source_device_id: @alice_laptop.id,
          target_device_id: foreign.id
        }
      }
    end

    assert_response :unprocessable_entity
    assert_match(/same network/i, response.body)
  end

  # ── Revoke ──────────────────────────────────────────────────────

  test "revoke soft-deletes and writes an audit log" do
    sign_in_as(@admin)
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )

    assert_difference -> { AuditLog.where(action: "device_grant.revoked").count }, 1 do
      post revoke_network_device_communication_grant_path(@network, grant)
    end

    assert grant.reload.revoked?
  end

  test "revoke is idempotent — second call returns alert, no double audit" do
    sign_in_as(@admin)
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )
    grant.revoke!

    assert_no_difference -> { AuditLog.where(action: "device_grant.revoked").count } do
      post revoke_network_device_communication_grant_path(@network, grant)
    end

    follow_redirect!
    assert_match(/already revoked/i, response.body)
  end

  # ── Destroy ─────────────────────────────────────────────────────

  test "destroy removes the row and writes an audit log" do
    sign_in_as(@admin)
    grant = DeviceCommunicationGrant.create!(
      source_device: @alice_laptop, target_device: @bob_desktop
    )

    assert_difference -> { DeviceCommunicationGrant.count }, -1 do
      assert_difference -> { AuditLog.where(action: "device_grant.deleted").count }, 1 do
        delete network_device_communication_grant_path(@network, grant)
      end
    end
  end

  # ── Cross-network URL walking ───────────────────────────────────

  test "cannot touch a grant whose source belongs to a different network" do
    sign_in_as(@admin)

    # Create a grant in a SECOND network. URL-walking from /networks/<office>/...
    # MUST 404 (not 403, not 200) — the set_grant filter scopes the
    # lookup to this network's devices.
    other_network = Network.create!(
      name: "Cross Net 2", zone: "second.acme.ztlp", status: "created",
      enrollment_secret_ciphertext: "0" * 64
    )
    src = ZtlpDevice.create!(name: "src", network: other_network, node_id: "n-1", status: "enrolled")
    tgt = ZtlpDevice.create!(name: "tgt", network: other_network, node_id: "n-2", status: "enrolled")
    other_grant = DeviceCommunicationGrant.create!(source_device: src, target_device: tgt)

    # Walk the URL from the OFFICE network to the OTHER network's grant.
    # The controller's set_grant filter scopes the lookup to this
    # network's device IDs, so this MUST 404 (not 200, not silently
    # operate on the foreign row).
    post revoke_network_device_communication_grant_path(@network, other_grant)
    assert_response :not_found
  end
end
