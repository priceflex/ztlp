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

ActiveRecord::Schema[7.1].define(version: 2026_03_22_010000) do
  create_table "admin_users", force: :cascade do |t|
    t.string "email", null: false
    t.string "name", null: false
    t.string "password_digest", null: false
    t.string "role", default: "admin", null: false
    t.string "totp_secret"
    t.boolean "totp_enabled", default: false
    t.datetime "last_login_at"
    t.string "last_login_ip"
    t.integer "failed_login_attempts", default: 0
    t.datetime "locked_until"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_admin_users_on_email", unique: true
  end

  create_table "alerts", force: :cascade do |t|
    t.integer "network_id", null: false
    t.integer "machine_id", null: false
    t.string "component", null: false
    t.string "severity", default: "warning", null: false
    t.text "message", null: false
    t.boolean "acknowledged", default: false, null: false
    t.datetime "acknowledged_at"
    t.datetime "resolved_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["acknowledged"], name: "index_alerts_on_acknowledged"
    t.index ["machine_id", "component"], name: "index_alerts_on_machine_id_and_component"
    t.index ["machine_id"], name: "index_alerts_on_machine_id"
    t.index ["network_id"], name: "index_alerts_on_network_id"
    t.index ["resolved_at"], name: "index_alerts_on_resolved_at"
    t.index ["severity"], name: "index_alerts_on_severity"
  end

  create_table "audit_logs", force: :cascade do |t|
    t.string "action", null: false
    t.string "target_type"
    t.integer "target_id"
    t.string "status", default: "success", null: false
    t.text "details"
    t.string "ip_address"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["action"], name: "index_audit_logs_on_action"
    t.index ["created_at"], name: "index_audit_logs_on_created_at"
    t.index ["target_type", "target_id"], name: "index_audit_logs_on_target_type_and_target_id"
  end

  create_table "certificates", force: :cascade do |t|
    t.integer "network_id", null: false
    t.string "hostname", null: false
    t.string "serial", null: false
    t.string "subject"
    t.string "issuer"
    t.string "status", default: "active", null: false
    t.string "assurance_level", default: "software"
    t.string "key_source"
    t.datetime "issued_at", null: false
    t.datetime "expires_at", null: false
    t.datetime "revoked_at"
    t.string "revocation_reason"
    t.text "pem_data"
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_certificates_on_expires_at"
    t.index ["network_id", "hostname"], name: "index_certificates_on_network_id_and_hostname"
    t.index ["network_id"], name: "index_certificates_on_network_id"
    t.index ["serial"], name: "index_certificates_on_serial", unique: true
    t.index ["status"], name: "index_certificates_on_status"
  end

  create_table "connection_events", force: :cascade do |t|
    t.integer "ztlp_device_id", null: false
    t.integer "network_id", null: false
    t.integer "ztlp_user_id"
    t.string "event_type", null: false
    t.string "source_ip"
    t.string "relay_name"
    t.string "disconnect_reason"
    t.integer "session_duration_seconds"
    t.text "details"
    t.datetime "created_at", null: false
    t.index ["network_id", "created_at"], name: "index_connection_events_on_network_id_and_created_at"
    t.index ["ztlp_device_id", "created_at"], name: "index_connection_events_on_ztlp_device_id_and_created_at"
    t.index ["ztlp_user_id", "created_at"], name: "index_connection_events_on_ztlp_user_id_and_created_at"
  end

  create_table "deployments", force: :cascade do |t|
    t.integer "machine_id", null: false
    t.string "status", default: "pending", null: false
    t.string "component", null: false
    t.text "log"
    t.text "config_generated"
    t.string "docker_image"
    t.string "container_id"
    t.datetime "started_at"
    t.datetime "finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["machine_id", "component"], name: "index_deployments_on_machine_id_and_component"
    t.index ["machine_id"], name: "index_deployments_on_machine_id"
    t.index ["status"], name: "index_deployments_on_status"
  end

  create_table "device_heartbeats", force: :cascade do |t|
    t.integer "ztlp_device_id", null: false
    t.integer "network_id", null: false
    t.string "source_ip"
    t.integer "source_port"
    t.string "relay_name"
    t.integer "latency_ms"
    t.integer "bytes_sent", default: 0
    t.integer "bytes_received", default: 0
    t.integer "active_streams", default: 0
    t.string "client_version"
    t.string "os_info"
    t.datetime "created_at", null: false
    t.index ["network_id", "created_at"], name: "index_device_heartbeats_on_network_id_and_created_at"
    t.index ["ztlp_device_id", "created_at"], name: "index_device_heartbeats_on_ztlp_device_id_and_created_at"
  end

  create_table "enrollment_tokens", force: :cascade do |t|
    t.integer "network_id", null: false
    t.string "token_id", null: false
    t.string "token_uri"
    t.text "qr_svg"
    t.integer "max_uses", default: 1, null: false
    t.integer "current_uses", default: 0, null: false
    t.datetime "expires_at", null: false
    t.string "status", default: "active", null: false
    t.string "allowed_roles"
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["network_id", "status"], name: "index_enrollment_tokens_on_network_id_and_status"
    t.index ["network_id"], name: "index_enrollment_tokens_on_network_id"
    t.index ["status"], name: "index_enrollment_tokens_on_status"
    t.index ["token_id"], name: "index_enrollment_tokens_on_token_id", unique: true
  end

  create_table "group_memberships", force: :cascade do |t|
    t.integer "ztlp_group_id", null: false
    t.integer "ztlp_user_id", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["ztlp_group_id", "ztlp_user_id"], name: "index_group_memberships_on_ztlp_group_id_and_ztlp_user_id", unique: true
    t.index ["ztlp_group_id"], name: "index_group_memberships_on_ztlp_group_id"
    t.index ["ztlp_user_id"], name: "index_group_memberships_on_ztlp_user_id"
  end

  create_table "health_checks", force: :cascade do |t|
    t.integer "machine_id", null: false
    t.string "component", null: false
    t.string "status", default: "unknown", null: false
    t.text "metrics"
    t.string "container_state"
    t.text "error_message"
    t.integer "response_time_ms"
    t.datetime "checked_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["checked_at"], name: "index_health_checks_on_checked_at"
    t.index ["machine_id", "component", "checked_at"], name: "index_health_checks_on_machine_component_time"
    t.index ["machine_id", "component"], name: "index_health_checks_on_machine_id_and_component"
    t.index ["machine_id"], name: "index_health_checks_on_machine_id"
    t.index ["status"], name: "index_health_checks_on_status"
  end

  create_table "identity_providers", force: :cascade do |t|
    t.integer "network_id", null: false
    t.string "name", null: false
    t.string "provider_type", null: false
    t.string "client_id", null: false
    t.text "client_secret_ciphertext"
    t.string "issuer_url"
    t.string "allowed_domains"
    t.boolean "auto_create_users", default: false, null: false
    t.string "role_default", default: "user", null: false
    t.boolean "enabled", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["network_id", "provider_type"], name: "index_identity_providers_on_network_and_type"
    t.index ["network_id"], name: "index_identity_providers_on_network_id"
  end

  create_table "machines", force: :cascade do |t|
    t.integer "network_id", null: false
    t.string "hostname", null: false
    t.string "ip_address", null: false
    t.integer "ssh_port", default: 22, null: false
    t.string "ssh_user", default: "root", null: false
    t.text "ssh_private_key_ciphertext"
    t.string "ssh_auth_method", default: "key", null: false
    t.text "ssh_password_ciphertext"
    t.string "roles", default: "", null: false
    t.string "status", default: "pending", null: false
    t.text "last_error"
    t.datetime "last_health_check_at"
    t.boolean "docker_installed", default: false, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.boolean "ztlp_tunnel_reachable", default: false
    t.integer "ztlp_tunnel_latency_ms"
    t.string "ztlp_tunnel_error"
    t.datetime "ztlp_tunnel_checked_at"
    t.text "gateway_backends"
    t.text "gateway_policies"
    t.index ["network_id", "hostname"], name: "index_machines_on_network_id_and_hostname", unique: true
    t.index ["network_id", "ip_address"], name: "index_machines_on_network_id_and_ip_address", unique: true
    t.index ["network_id"], name: "index_machines_on_network_id"
  end

  create_table "networks", force: :cascade do |t|
    t.string "name", null: false
    t.string "zone", null: false
    t.text "enrollment_secret_ciphertext"
    t.text "zone_key_ciphertext"
    t.string "status", default: "created", null: false
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "index_networks_on_name", unique: true
    t.index ["zone"], name: "index_networks_on_zone", unique: true
  end

  create_table "notification_channels", force: :cascade do |t|
    t.integer "network_id"
    t.string "name", null: false
    t.string "channel_type", null: false
    t.text "config_json", null: false
    t.boolean "enabled", default: true
    t.string "severity_filter", default: "all"
    t.string "event_filter"
    t.datetime "last_sent_at"
    t.integer "send_count", default: 0
    t.text "last_error"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["channel_type", "enabled"], name: "index_notification_channels_on_channel_type_and_enabled"
    t.index ["network_id"], name: "index_notification_channels_on_network_id"
  end

  create_table "notification_logs", force: :cascade do |t|
    t.integer "notification_channel_id", null: false
    t.string "event_type", null: false
    t.string "subject"
    t.text "body"
    t.string "status", default: "pending", null: false
    t.text "error_message"
    t.datetime "sent_at"
    t.datetime "created_at", null: false
    t.index ["notification_channel_id", "created_at"], name: "idx_on_notification_channel_id_created_at_3c34eeb0ae"
    t.index ["status"], name: "index_notification_logs_on_status"
  end

  create_table "policies", force: :cascade do |t|
    t.integer "network_id", null: false
    t.string "name", null: false
    t.text "description"
    t.string "policy_type", null: false
    t.string "priority", default: "normal"
    t.boolean "enabled", default: true
    t.string "subject_type", null: false
    t.string "subject_value"
    t.string "resource_type", null: false
    t.string "resource_value", null: false
    t.string "action", default: "allow", null: false
    t.string "time_schedule"
    t.string "timezone", default: "UTC"
    t.integer "created_by_id"
    t.datetime "expires_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "auth_mode", default: "passthrough"
    t.string "min_assurance"
    t.index ["network_id", "enabled"], name: "index_policies_on_network_id_and_enabled"
    t.index ["network_id", "subject_type", "subject_value"], name: "index_policies_on_network_subject"
    t.index ["policy_type"], name: "index_policies_on_policy_type"
  end

  create_table "policy_templates", force: :cascade do |t|
    t.string "name", null: false
    t.text "description"
    t.string "category", null: false
    t.text "rules_json", null: false
    t.boolean "built_in", default: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "ztlp_devices", force: :cascade do |t|
    t.string "name", null: false
    t.integer "network_id", null: false
    t.integer "ztlp_user_id"
    t.integer "machine_id"
    t.string "node_id"
    t.text "pubkey"
    t.string "hardware_id"
    t.string "status", default: "enrolled", null: false
    t.datetime "enrolled_at"
    t.datetime "revoked_at"
    t.string "revocation_reason"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.datetime "last_seen_at"
    t.string "last_source_ip"
    t.string "last_relay"
    t.string "client_version"
    t.string "os_info"
    t.string "assurance_level", default: "software"
    t.string "cert_serial"
    t.datetime "cert_expires_at"
    t.index ["last_seen_at"], name: "index_ztlp_devices_on_last_seen_at"
    t.index ["machine_id"], name: "index_ztlp_devices_on_machine_id"
    t.index ["network_id", "name"], name: "index_ztlp_devices_on_network_id_and_name", unique: true
    t.index ["network_id"], name: "index_ztlp_devices_on_network_id"
    t.index ["ztlp_user_id"], name: "index_ztlp_devices_on_ztlp_user_id"
  end

  create_table "ztlp_groups", force: :cascade do |t|
    t.string "name", null: false
    t.integer "network_id", null: false
    t.text "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["network_id", "name"], name: "index_ztlp_groups_on_network_id_and_name", unique: true
    t.index ["network_id"], name: "index_ztlp_groups_on_network_id"
  end

  create_table "ztlp_users", force: :cascade do |t|
    t.string "name", null: false
    t.integer "network_id", null: false
    t.text "pubkey"
    t.string "email"
    t.string "role", default: "user", null: false
    t.string "status", default: "active", null: false
    t.datetime "revoked_at"
    t.string "revocation_reason"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "external_id"
    t.string "idp_issuer"
    t.datetime "last_login_at"
    t.datetime "suspended_at"
    t.index ["network_id", "external_id", "idp_issuer"], name: "index_ztlp_users_on_network_external_idp", unique: true, where: "external_id IS NOT NULL"
    t.index ["network_id", "name"], name: "index_ztlp_users_on_network_id_and_name", unique: true
    t.index ["network_id"], name: "index_ztlp_users_on_network_id"
  end

  add_foreign_key "alerts", "machines"
  add_foreign_key "alerts", "networks"
  add_foreign_key "certificates", "networks"
  add_foreign_key "deployments", "machines"
  add_foreign_key "enrollment_tokens", "networks"
  add_foreign_key "group_memberships", "ztlp_groups"
  add_foreign_key "group_memberships", "ztlp_users"
  add_foreign_key "health_checks", "machines"
  add_foreign_key "identity_providers", "networks"
  add_foreign_key "machines", "networks"
  add_foreign_key "ztlp_devices", "machines"
  add_foreign_key "ztlp_devices", "networks"
  add_foreign_key "ztlp_devices", "ztlp_users"
  add_foreign_key "ztlp_groups", "networks"
  add_foreign_key "ztlp_users", "networks"
end
