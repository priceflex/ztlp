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

ActiveRecord::Schema[7.1].define(version: 2026_03_12_030001) do
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

  add_foreign_key "alerts", "machines"
  add_foreign_key "alerts", "networks"
  add_foreign_key "deployments", "machines"
  add_foreign_key "enrollment_tokens", "networks"
  add_foreign_key "health_checks", "machines"
  add_foreign_key "machines", "networks"
end
