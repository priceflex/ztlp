# frozen_string_literal: true

# Creates `device_communication_grants`, which records that one ZtlpDevice
# is permitted to talk to another ZtlpDevice on the ZTLP overlay.
#
# Per Steve's 2026-05-23 brief: *"Create an easy-to-use dashboard
# interface for managing: Networks, Devices, Device-to-device
# communication permissions, Users assigned to devices."*
#
# This table is the **device-to-device communication permissions**
# slice. The dashboard layer reads/writes it; a future gateway-side
# enforcement point will consult it when forwarding QUIC streams.
# Today the table is dashboard-only — landing the schema + model +
# UI now means the gateway consumer can be added in a separate
# follow-up PR without a coordinated migration.
#
# Why a dedicated table (not piggybacking on ZtlpGroup membership):
# group membership semantically means "this device belongs to this
# team", which is orthogonal to "this device is permitted to
# communicate with this other device." Two devices in the same group
# may legitimately have no need to talk to each other; two devices in
# different groups may need an explicit cross-team grant. Encoding
# both meanings on one association would conflate them.
#
# Columns:
#
#   * `source_device_id`        — the device initiating the connection
#   * `target_device_id`        — the device being contacted
#   * `granted_by_admin_user_id` — provenance for audit
#   * `granted_at`              — when the grant was created (defaults to created_at)
#   * `revoked_at`              — soft-delete; nil = active, non-nil = revoked
#   * `notes`                   — free-text annotation
#
# Uniqueness: `(source_device_id, target_device_id)` is unique. A
# grant is intentionally directional — A → B is separate from B → A
# because operators may want to authorize one direction without the
# other (e.g., a monitoring agent contacts services, but services
# should not initiate back).
#
# A grant references devices, not (source, target) pairs of devices
# from the same network. Cross-network grants are rejected by the
# model layer (BS-PR-5 model validations) — see
# `DeviceCommunicationGrant#same_network`.
class CreateDeviceCommunicationGrants < ActiveRecord::Migration[7.1]
  def change
    create_table :device_communication_grants do |t|
      t.references :source_device, null: false,
                                   foreign_key: { to_table: :ztlp_devices },
                                   index: true
      t.references :target_device, null: false,
                                   foreign_key: { to_table: :ztlp_devices },
                                   index: true
      t.integer :granted_by_admin_user_id
      t.datetime :granted_at, null: false
      t.datetime :revoked_at
      t.text :notes

      t.timestamps
    end

    add_index :device_communication_grants,
              [:source_device_id, :target_device_id],
              unique: true,
              name: "idx_dcg_unique_pair"

    add_index :device_communication_grants, :revoked_at
  end
end
