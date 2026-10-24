# frozen_string_literal: true

# Per-admin default zone for the rail zone switcher (PLAN-multizone-and-app-registration.md, Phase A).
class AddDefaultZoneToAdmins < ActiveRecord::Migration[7.1]
  def change
    add_column :admins, :default_zone_id, :bigint, null: true
    add_index :admins, :default_zone_id, name: "idx_admins_default_zone"
    add_foreign_key :admins, :zones, column: :default_zone_id, on_delete: :nullify
  end
end
