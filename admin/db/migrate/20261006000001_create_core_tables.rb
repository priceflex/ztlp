# frozen_string_literal: true

class CreateCoreTables < ActiveRecord::Migration[7.1]
  def change
    create_table :zones do |t|
      t.string :name, null: false
      t.string :ns_addr, null: false
      t.string :ns_admin_base_url
      t.text :relay_addrs
      t.string :gateway_addr
      t.text :authority_seed_ct
      t.string :authority_pubkey_hex
      t.text :enrollment_secret_ct
      t.text :relay_secret_ct
      t.text :ns_admin_api_secret_ct
      t.datetime :last_reconciled_at
      t.timestamps
    end
    add_index :zones, :name, unique: true, name: 'idx_zones_name'

    create_table :admins do |t|
      t.string :username, null: false
      t.string :display_name, null: false
      t.string :email
      t.string :role, null: false, default: 'admin'
      t.string :pubkey_hex, null: false
      t.bigint :user_id
      t.datetime :last_login_at
      t.string :last_login_ip
      t.datetime :disabled_at
      t.timestamps
    end
    add_index :admins, :username, unique: true, name: 'idx_admins_username'
    add_index :admins, :pubkey_hex, unique: true, name: 'idx_admins_pubkey'

    create_table :login_challenges do |t|
      t.bigint :admin_id, null: false
      t.string :nonce, null: false
      t.datetime :expires_at, null: false
      t.datetime :used_at
      t.timestamps
    end
    add_index :login_challenges, :nonce, unique: true, name: 'idx_login_challenges_nonce'
    add_index :login_challenges, :admin_id, name: 'idx_login_challenges_admin'

    create_table :session_tokens do |t|
      t.bigint :admin_id, null: false
      t.string :token_digest, null: false
      t.datetime :expires_at, null: false
      t.datetime :used_at
      t.timestamps
    end
    add_index :session_tokens, :token_digest, unique: true, name: 'idx_session_tokens_digest'

    create_table :audit_logs do |t|
      t.bigint :admin_id
      t.string :action, null: false
      t.string :target_type
      t.bigint :target_id
      t.string :status, null: false, default: 'ok'
      t.text :details
      t.string :ip
      t.datetime :created_at, null: false
    end
    add_index :audit_logs, :action, name: 'idx_audit_action'
    add_index :audit_logs, :created_at, name: 'idx_audit_created'
    add_index :audit_logs, %i[target_type target_id], name: 'idx_audit_target'

    create_table :system_settings, id: false do |t|
      t.string :key, null: false, primary_key: true
      t.text :value_ct
      t.datetime :updated_at, null: false
    end
  end
end
