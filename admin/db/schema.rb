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

ActiveRecord::Schema[7.1].define(version: 2026_10_21_000001) do
  create_table "admins", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "username", null: false
    t.string "display_name", null: false
    t.string "email"
    t.string "role", default: "admin", null: false
    t.string "pubkey_hex", null: false
    t.bigint "user_id"
    t.datetime "last_login_at"
    t.string "last_login_ip"
    t.datetime "disabled_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["pubkey_hex"], name: "idx_admins_pubkey", unique: true
    t.index ["user_id"], name: "idx_admins_user"
    t.index ["username"], name: "idx_admins_username", unique: true
  end

  create_table "applications", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "gateway_id", null: false
    t.string "name", null: false
    t.string "backend"
    t.string "protocol"
    t.integer "min_assurance", default: 1, null: false
    t.boolean "enabled", default: true, null: false
    t.text "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["gateway_id", "name"], name: "idx_applications_gw_name", unique: true
  end

  create_table "audit_logs", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "admin_id"
    t.string "action", null: false
    t.string "target_type"
    t.bigint "target_id"
    t.string "status", default: "ok", null: false
    t.text "details"
    t.string "ip"
    t.datetime "created_at", null: false
    t.index ["action"], name: "idx_audit_action"
    t.index ["created_at"], name: "idx_audit_created"
    t.index ["target_type", "target_id"], name: "idx_audit_target"
  end

  create_table "devices", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "zone_id", null: false
    t.string "name", null: false
    t.string "ns_name"
    t.bigint "user_id"
    t.string "node_id_hex"
    t.string "noise_pubkey_hex"
    t.string "signing_pubkey_hex"
    t.string "platform"
    t.string "key_source", default: "unknown", null: false
    t.integer "assurance", default: 1, null: false
    t.string "agent_version"
    t.string "status", default: "pending", null: false
    t.datetime "enrolled_at"
    t.datetime "last_seen_at"
    t.bigint "enrollment_id"
    t.datetime "ns_published_at"
    t.datetime "revoked_at"
    t.string "revocation_reason"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["node_id_hex"], name: "idx_devices_node_id", unique: true
    t.index ["ns_name"], name: "idx_devices_ns_name", unique: true
    t.index ["user_id"], name: "idx_devices_owner"
    t.index ["zone_id", "name"], name: "idx_devices_zone_name", unique: true
    t.index ["zone_id"], name: "idx_devices_zone"
  end

  create_table "enrollments", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "zone_id", null: false
    t.string "token_id", null: false
    t.string "kind", default: "device_only", null: false
    t.bigint "user_id"
    t.string "device_name"
    t.boolean "embed_relay_secret", default: false, null: false
    t.integer "max_uses"
    t.integer "uses", default: 0, null: false
    t.datetime "expires_at"
    t.string "status", default: "pending", null: false
    t.string "code"
    t.text "token_uri_ct"
    t.datetime "redeemed_at"
    t.bigint "redeemed_device_id"
    t.bigint "created_by_admin_id"
    t.datetime "revoked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["code"], name: "idx_enrollments_code", unique: true
    t.index ["token_id"], name: "idx_enrollments_token", unique: true
    t.index ["user_id"], name: "idx_enrollments_user"
    t.index ["zone_id"], name: "idx_enrollments_zone"
  end

  create_table "gateways", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "zone_id", null: false
    t.string "name", null: false
    t.string "ns_name"
    t.string "kind", default: "rust_listen", null: false
    t.string "host_note"
    t.string "node_id_hex"
    t.string "signing_pubkey_hex"
    t.string "status", default: "planned", null: false
    t.datetime "last_svc_seen_at"
    t.text "addresses"
    t.datetime "policy_rendered_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["zone_id", "name"], name: "idx_gateways_zone_name", unique: true
    t.index ["zone_id"], name: "idx_gateways_zone"
  end

  create_table "group_memberships", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "group_id", null: false
    t.bigint "user_id", null: false
    t.bigint "added_by_admin_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["group_id", "user_id"], name: "idx_group_memberships_pair", unique: true
    t.index ["user_id"], name: "idx_group_memberships_user"
  end

  create_table "groups", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "zone_id", null: false
    t.string "name", null: false
    t.string "ns_name"
    t.string "description"
    t.datetime "ns_published_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["ns_name"], name: "idx_groups_ns_name", unique: true
    t.index ["zone_id", "name"], name: "idx_groups_zone_name", unique: true
    t.index ["zone_id"], name: "idx_groups_zone"
  end

  create_table "login_challenges", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "admin_id", null: false
    t.string "nonce", null: false
    t.datetime "expires_at", null: false
    t.datetime "used_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["admin_id"], name: "idx_login_challenges_admin"
    t.index ["nonce"], name: "idx_login_challenges_nonce", unique: true
  end

  create_table "policy_rules", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "application_id", null: false
    t.string "subject_type", null: false
    t.bigint "subject_id"
    t.string "subject_value"
    t.integer "position", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id", "position"], name: "idx_policy_rules_pos", unique: true
    t.index ["application_id"], name: "idx_policy_rules_app"
  end

  create_table "session_tokens", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "admin_id", null: false
    t.string "token_digest", null: false
    t.datetime "expires_at", null: false
    t.datetime "used_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["token_digest"], name: "idx_session_tokens_digest", unique: true
  end

  create_table "system_settings", primary_key: "key", id: :string, charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.text "value_ct"
    t.datetime "updated_at", null: false
  end

  create_table "users", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "zone_id", null: false
    t.string "username", null: false
    t.string "ns_name"
    t.string "kind", default: "person", null: false
    t.string "display_name"
    t.string "first_name"
    t.string "last_name"
    t.text "email"
    t.text "phone"
    t.boolean "sms_opt_in", default: false, null: false
    t.string "role", default: "user", null: false
    t.string "status", default: "invited", null: false
    t.string "signing_pubkey_hex"
    t.text "attrs_json"
    t.text "notes"
    t.datetime "ns_published_at"
    t.bigint "created_by_admin_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["ns_name"], name: "idx_users_ns_name", unique: true
    t.index ["zone_id", "username"], name: "idx_users_zone_username", unique: true
    t.index ["zone_id"], name: "idx_users_zone"
  end

  create_table "zones", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "name", null: false
    t.string "ns_addr", null: false
    t.string "ns_admin_base_url"
    t.text "relay_addrs"
    t.string "gateway_addr"
    t.text "authority_seed_ct"
    t.string "authority_pubkey_hex"
    t.text "enrollment_secret_ct"
    t.text "relay_secret_ct"
    t.text "ns_admin_api_secret_ct"
    t.datetime "last_reconciled_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "idx_zones_name", unique: true
  end

end
