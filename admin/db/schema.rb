# frozen_string_literal: true

# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.1].define(version: 20_261_006_000_001) do
  create_table 'admins', charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci', force: :cascade do |t|
    t.string 'username', null: false
    t.string 'display_name', null: false
    t.string 'email'
    t.string 'role', default: 'admin', null: false
    t.string 'pubkey_hex', null: false
    t.bigint 'user_id'
    t.datetime 'last_login_at'
    t.string 'last_login_ip'
    t.datetime 'disabled_at'
    t.datetime 'created_at', null: false
    t.datetime 'updated_at', null: false
    t.index ['pubkey_hex'], name: 'idx_admins_pubkey', unique: true
    t.index ['username'], name: 'idx_admins_username', unique: true
  end

  create_table 'audit_logs', charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci', force: :cascade do |t|
    t.bigint 'admin_id'
    t.string 'action', null: false
    t.string 'target_type'
    t.bigint 'target_id'
    t.string 'status', default: 'ok', null: false
    t.text 'details'
    t.string 'ip'
    t.datetime 'created_at', null: false
    t.index ['action'], name: 'idx_audit_action'
    t.index ['created_at'], name: 'idx_audit_created'
    t.index %w[target_type target_id], name: 'idx_audit_target'
  end

  create_table 'login_challenges', charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci', force: :cascade do |t|
    t.bigint 'admin_id', null: false
    t.string 'nonce', null: false
    t.datetime 'expires_at', null: false
    t.datetime 'used_at'
    t.datetime 'created_at', null: false
    t.datetime 'updated_at', null: false
    t.index ['admin_id'], name: 'idx_login_challenges_admin'
    t.index ['nonce'], name: 'idx_login_challenges_nonce', unique: true
  end

  create_table 'session_tokens', charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci', force: :cascade do |t|
    t.bigint 'admin_id', null: false
    t.string 'token_digest', null: false
    t.datetime 'expires_at', null: false
    t.datetime 'used_at'
    t.datetime 'created_at', null: false
    t.datetime 'updated_at', null: false
    t.index ['token_digest'], name: 'idx_session_tokens_digest', unique: true
  end

  create_table 'system_settings', primary_key: 'key', id: :string, charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci',
                                  force: :cascade do |t|
    t.text 'value_ct'
    t.datetime 'updated_at', null: false
  end

  create_table 'zones', charset: 'utf8mb4', collation: 'utf8mb4_unicode_ci', force: :cascade do |t|
    t.string 'name', null: false
    t.string 'ns_addr', null: false
    t.string 'ns_admin_base_url'
    t.text 'relay_addrs'
    t.string 'gateway_addr'
    t.text 'authority_seed_ct'
    t.string 'authority_pubkey_hex'
    t.text 'enrollment_secret_ct'
    t.text 'relay_secret_ct'
    t.text 'ns_admin_api_secret_ct'
    t.datetime 'last_reconciled_at'
    t.datetime 'created_at', null: false
    t.datetime 'updated_at', null: false
    t.index ['name'], name: 'idx_zones_name', unique: true
  end
end
