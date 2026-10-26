# frozen_string_literal: true

class CreateDirectoryTables < ActiveRecord::Migration[7.1]
  def change
    create_table :users, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :zone_id, null: false
      t.string :username, null: false
      t.string :ns_name
      t.string :kind, null: false, default: "person"
      t.string :display_name
      t.string :first_name
      t.string :last_name
      t.text :email
      t.text :phone
      t.boolean :sms_opt_in, null: false, default: false
      t.string :role, null: false, default: "user"
      t.string :status, null: false, default: "invited"
      t.string :signing_pubkey_hex
      t.text :attrs_json
      t.text :notes
      t.datetime :ns_published_at
      t.bigint :created_by_admin_id
      t.timestamps
    end
    add_index :users, %i[zone_id username], unique: true, name: "idx_users_zone_username"
    add_index :users, :ns_name, unique: true, name: "idx_users_ns_name"
    add_index :users, :zone_id, name: "idx_users_zone"

    create_table :groups, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :zone_id, null: false
      t.string :name, null: false
      t.string :ns_name
      t.string :description
      t.datetime :ns_published_at
      t.timestamps
    end
    add_index :groups, %i[zone_id name], unique: true, name: "idx_groups_zone_name"
    add_index :groups, :ns_name, unique: true, name: "idx_groups_ns_name"
    add_index :groups, :zone_id, name: "idx_groups_zone"

    create_table :group_memberships, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :group_id, null: false
      t.bigint :user_id, null: false
      t.bigint :added_by_admin_id
      t.timestamps
    end
    add_index :group_memberships, %i[group_id user_id], unique: true, name: "idx_group_memberships_pair"
    add_index :group_memberships, :user_id, name: "idx_group_memberships_user"

    create_table :devices, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :zone_id, null: false
      t.string :name, null: false
      t.string :ns_name
      t.bigint :user_id
      t.string :node_id_hex
      t.string :noise_pubkey_hex
      t.string :signing_pubkey_hex
      t.string :platform
      t.string :key_source, null: false, default: "unknown"
      t.integer :assurance, null: false, default: 1
      t.string :agent_version
      t.string :status, null: false, default: "pending"
      t.datetime :enrolled_at
      t.datetime :last_seen_at
      t.bigint :enrollment_id
      t.datetime :ns_published_at
      t.datetime :revoked_at
      t.string :revocation_reason
      t.timestamps
    end
    add_index :devices, %i[zone_id name], unique: true, name: "idx_devices_zone_name"
    add_index :devices, :ns_name, unique: true, name: "idx_devices_ns_name"
    add_index :devices, :node_id_hex, unique: true, name: "idx_devices_node_id"
    add_index :devices, :zone_id, name: "idx_devices_zone"
    add_index :devices, :user_id, name: "idx_devices_owner"

    create_table :enrollments, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :zone_id, null: false
      t.string :token_id, null: false
      t.string :kind, null: false, default: "device_only"
      t.bigint :user_id
      t.string :device_name
      t.boolean :embed_relay_secret, null: false, default: false
      t.integer :max_uses
      t.integer :uses, null: false, default: 0
      t.datetime :expires_at
      t.string :status, null: false, default: "pending"
      t.string :code
      t.text :token_uri_ct
      t.datetime :redeemed_at
      t.bigint :redeemed_device_id
      t.bigint :created_by_admin_id
      t.datetime :revoked_at
      t.timestamps
    end
    add_index :enrollments, :token_id, unique: true, name: "idx_enrollments_token"
    add_index :enrollments, :code, unique: true, name: "idx_enrollments_code"
    add_index :enrollments, :zone_id, name: "idx_enrollments_zone"
    add_index :enrollments, :user_id, name: "idx_enrollments_user"

    create_table :gateways, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :zone_id, null: false
      t.string :name, null: false
      t.string :ns_name
      t.string :kind, null: false, default: "rust_listen"
      t.string :host_note
      t.string :node_id_hex
      t.string :signing_pubkey_hex
      t.string :status, null: false, default: "planned"
      t.datetime :last_svc_seen_at
      t.text :addresses
      t.datetime :policy_rendered_at
      t.timestamps
    end
    add_index :gateways, %i[zone_id name], unique: true, name: "idx_gateways_zone_name"
    add_index :gateways, :zone_id, name: "idx_gateways_zone"

    create_table :applications, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :gateway_id, null: false
      t.string :name, null: false
      t.string :backend
      t.string :protocol
      t.integer :min_assurance, null: false, default: 1
      t.boolean :enabled, null: false, default: true
      t.text :description
      t.timestamps
    end
    add_index :applications, %i[gateway_id name], unique: true, name: "idx_applications_gw_name"

    create_table :policy_rules, charset: "utf8mb4", collation: "utf8mb4_unicode_ci" do |t|
      t.bigint :application_id, null: false
      t.string :subject_type, null: false
      t.bigint :subject_id
      t.string :subject_value
      t.integer :position, null: false, default: 0
      t.timestamps
    end
    add_index :policy_rules, :application_id, name: "idx_policy_rules_app"
    add_index :policy_rules, %i[application_id position], unique: true, name: "idx_policy_rules_pos"

    add_index :admins, :user_id, name: "idx_admins_user"
  end
end
