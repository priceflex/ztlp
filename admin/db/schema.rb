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

ActiveRecord::Schema[7.1].define(version: 2026_10_27_000003) do
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
    t.bigint "default_zone_id"
    t.index ["default_zone_id"], name: "idx_admins_default_zone"
    t.index ["pubkey_hex"], name: "idx_admins_pubkey", unique: true
    t.index ["user_id"], name: "idx_admins_user"
    t.index ["username"], name: "idx_admins_username", unique: true
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
    t.integer "bind_port", default: 23097, null: false
    t.integer "max_sessions", default: 100, null: false
    t.boolean "punch", default: true, null: false
    t.boolean "inject_headers", default: false, null: false
    t.text "header_secret_ct"
    t.text "subject_map"
    t.boolean "policy_file"
    t.string "ns_server"
    t.string "relay_addr"
    t.string "image_tag"
    t.datetime "install_shown_at"
    t.string "quic_cert_sha256", limit: 64
    t.boolean "quic_cert_verified", default: false, null: false
    t.string "quic_cert_status", limit: 16
    t.datetime "quic_cert_seen_at"
    t.string "quic_cert_previous_sha256", limit: 64
    t.datetime "quic_cert_changed_at"
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
    t.bigint "service_id", null: false
    t.string "subject_type", null: false
    t.bigint "subject_id"
    t.string "subject_value"
    t.integer "position", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["service_id", "position"], name: "idx_policy_rules_pos", unique: true
    t.index ["service_id"], name: "idx_policy_rules_service"
  end

  create_table "services", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "gateway_id", null: false
    t.string "name", null: false
    t.string "backend"
    t.string "protocol"
    t.integer "min_assurance", default: 1, null: false
    t.boolean "enabled", default: true, null: false
    t.text "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["gateway_id", "name"], name: "idx_services_gw_name", unique: true
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

  create_table "solid_queue_batch_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.bigint "batch_id", null: false
    t.datetime "created_at", null: false
    t.index ["batch_id"], name: "index_solid_queue_batch_executions_on_batch_id"
    t.index ["job_id"], name: "index_solid_queue_batch_executions_on_job_id", unique: true
  end

  create_table "solid_queue_batches", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "active_job_batch_id"
    t.string "description"
    t.text "on_finish"
    t.text "on_success"
    t.text "on_failure"
    t.text "metadata"
    t.integer "total_jobs", default: 0, null: false
    t.integer "completed_jobs", default: 0, null: false
    t.integer "failed_jobs", default: 0, null: false
    t.datetime "enqueued_at"
    t.datetime "finished_at"
    t.datetime "failed_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["active_job_batch_id"], name: "index_solid_queue_batches_on_active_job_batch_id", unique: true
    t.index ["finished_at"], name: "index_solid_queue_batches_on_finished_at"
  end

  create_table "solid_queue_blocked_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.string "concurrency_key", null: false
    t.datetime "expires_at", null: false
    t.datetime "created_at", null: false
    t.index ["concurrency_key", "priority", "job_id"], name: "index_solid_queue_blocked_executions_for_release"
    t.index ["expires_at", "concurrency_key"], name: "index_solid_queue_blocked_executions_for_maintenance"
    t.index ["job_id"], name: "index_solid_queue_blocked_executions_on_job_id", unique: true
  end

  create_table "solid_queue_claimed_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.bigint "process_id"
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_claimed_executions_on_job_id", unique: true
    t.index ["process_id", "job_id"], name: "index_solid_queue_claimed_executions_on_process_id_and_job_id"
  end

  create_table "solid_queue_failed_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.text "error"
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_failed_executions_on_job_id", unique: true
  end

  create_table "solid_queue_jobs", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "queue_name", null: false
    t.string "class_name", null: false
    t.text "arguments"
    t.integer "priority", default: 0, null: false
    t.string "active_job_id"
    t.datetime "scheduled_at"
    t.datetime "finished_at"
    t.string "concurrency_key"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.bigint "batch_id"
    t.index ["active_job_id"], name: "index_solid_queue_jobs_on_active_job_id"
    t.index ["batch_id"], name: "index_solid_queue_jobs_on_batch_id"
    t.index ["class_name"], name: "index_solid_queue_jobs_on_class_name"
    t.index ["finished_at"], name: "index_solid_queue_jobs_on_finished_at"
    t.index ["queue_name", "finished_at"], name: "index_solid_queue_jobs_for_filtering"
    t.index ["scheduled_at", "finished_at"], name: "index_solid_queue_jobs_for_alerting"
  end

  create_table "solid_queue_pauses", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "queue_name", null: false
    t.datetime "created_at", null: false
    t.index ["queue_name"], name: "index_solid_queue_pauses_on_queue_name", unique: true
  end

  create_table "solid_queue_processes", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "kind", null: false
    t.datetime "last_heartbeat_at", null: false
    t.bigint "supervisor_id"
    t.integer "pid", null: false
    t.string "hostname"
    t.text "metadata"
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.index ["last_heartbeat_at"], name: "index_solid_queue_processes_on_last_heartbeat_at"
    t.index ["name", "supervisor_id"], name: "index_solid_queue_processes_on_name_and_supervisor_id", unique: true
    t.index ["supervisor_id"], name: "index_solid_queue_processes_on_supervisor_id"
  end

  create_table "solid_queue_ready_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_ready_executions_on_job_id", unique: true
    t.index ["priority", "job_id"], name: "index_solid_queue_poll_all"
    t.index ["queue_name", "priority", "job_id"], name: "index_solid_queue_poll_by_queue"
  end

  create_table "solid_queue_recurring_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "task_key", null: false
    t.datetime "run_at", null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_recurring_executions_on_job_id", unique: true
    t.index ["task_key", "run_at"], name: "index_solid_queue_recurring_executions_on_task_key_and_run_at", unique: true
  end

  create_table "solid_queue_recurring_tasks", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "key", null: false
    t.string "schedule", null: false
    t.string "command", limit: 2048
    t.string "class_name"
    t.text "arguments"
    t.string "queue_name"
    t.integer "priority", default: 0
    t.boolean "static", default: true, null: false
    t.text "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_solid_queue_recurring_tasks_on_key", unique: true
    t.index ["static"], name: "index_solid_queue_recurring_tasks_on_static"
  end

  create_table "solid_queue_scheduled_executions", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.datetime "scheduled_at", null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_scheduled_executions_on_job_id", unique: true
    t.index ["scheduled_at", "priority", "job_id"], name: "index_solid_queue_dispatch_all"
  end

  create_table "solid_queue_semaphores", charset: "utf8mb4", collation: "utf8mb4_unicode_ci", force: :cascade do |t|
    t.string "key", null: false
    t.integer "value", default: 1, null: false
    t.datetime "expires_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_solid_queue_semaphores_on_expires_at"
    t.index ["key", "value"], name: "index_solid_queue_semaphores_on_key_and_value"
    t.index ["key"], name: "index_solid_queue_semaphores_on_key", unique: true
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
    t.string "ns_pubkey_hex", limit: 64
    t.text "device_relay_secret_ct"
    t.index ["name"], name: "idx_zones_name", unique: true
  end

  add_foreign_key "admins", "zones", column: "default_zone_id", on_delete: :nullify
  add_foreign_key "solid_queue_batch_executions", "solid_queue_batches", column: "batch_id", on_delete: :cascade
  add_foreign_key "solid_queue_batch_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_blocked_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_claimed_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_failed_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_ready_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_recurring_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_scheduled_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
end
