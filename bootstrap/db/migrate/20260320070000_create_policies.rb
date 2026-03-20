# frozen_string_literal: true

class CreatePolicies < ActiveRecord::Migration[7.1]
  def change
    create_table :policies do |t|
      t.integer :network_id, null: false
      t.string :name, null: false
      t.text :description
      t.string :policy_type, null: false       # "access", "time_based", "network_segment"
      t.string :priority, default: "normal"    # "high", "normal", "low"
      t.boolean :enabled, default: true

      # Who this policy applies to
      t.string :subject_type, null: false       # "user", "group", "role", "everyone"
      t.string :subject_value                   # user name, group name, role name, or null for everyone

      # What they can access
      t.string :resource_type, null: false      # "service", "zone", "ip_range"
      t.string :resource_value, null: false     # "*.internal", "erp.acme.ztlp", "10.42.0.0/16"

      # Action
      t.string :action, null: false, default: "allow"  # "allow", "deny"

      # Time constraints (optional)
      t.string :time_schedule                   # cron-like: "MON-FRI 09:00-17:00" or null for always
      t.string :timezone, default: "UTC"

      # Metadata
      t.integer :created_by_id                  # AdminUser who created it (future-proof)
      t.datetime :expires_at                    # Optional auto-expiry

      t.timestamps
    end

    add_index :policies, [:network_id, :enabled]
    add_index :policies, [:network_id, :subject_type, :subject_value], name: "index_policies_on_network_subject"
    add_index :policies, :policy_type
  end
end
