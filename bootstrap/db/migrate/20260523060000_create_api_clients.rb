# frozen_string_literal: true

# Creates `api_clients`, the allowlist of trusted external systems that
# may talk to the ZTLP Bootstrap API via the ZTLP-secured header chain.
#
# Each row represents one trusted system (Z2LS is the first concrete
# consumer). The HMAC secret used for request signing is NOT stored in
# this table — it lives in the per-zone secret store
# (`ZTLP_HMAC_SECRET_<ZONE>`), the same one the relay and gateway use.
# `api_clients` is the allowlist that says "this `(zone, name)` pair is
# permitted to call us at all"; the HMAC verification proves the
# request actually came from that party.
#
# Columns:
#
#   * `name`           — human-readable label, unique per zone
#                        (e.g. "z2ls.techrockstars")
#   * `zone`           — the ZTLP zone this client signs against
#                        (matches the relay/gateway zone-id convention)
#   * `ed25519_pubkey` — RESERVED for a future Ed25519-signed variant
#                        (BS-PR-7+). Nullable in v1; the v1 auth layer
#                        uses HMAC only.
#   * `notes`          — free-text annotation
#   * `active`         — soft-delete flag. Inactive rows fail auth.
#   * `created_by_admin_user_id` — provenance for audit
#   * `last_used_at`   — bumped by `ApiClient#touch_last_used!` on
#                        each successful auth. Useful for spotting
#                        dormant credentials.
#
# A `(zone, name)` pair is unique — two clients with the same name in
# different zones are intentionally separate rows (different tenants
# have their own Z2LS instances).
class CreateApiClients < ActiveRecord::Migration[7.1]
  def change
    create_table :api_clients do |t|
      t.string  :name,           null: false
      t.string  :zone,           null: false
      t.binary  :ed25519_pubkey, null: true
      t.text    :notes
      t.boolean :active,         null: false, default: true
      t.integer :created_by_admin_user_id
      t.datetime :last_used_at

      t.timestamps
    end

    add_index :api_clients, [:zone, :name], unique: true
    add_index :api_clients, :active
  end
end
