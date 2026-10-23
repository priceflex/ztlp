# frozen_string_literal: true

# Slice 9b sub-slice 6: gateway minimal CRUD inline from the application form
# (spec Slice 9: "New gateway" inline: name, kind, host_note).
#
# Gateways are the objects that front zone services and stamp ZTLP identity
# headers; an application always lives ON a gateway, so the panel needs a way
# to add the zone's gateway rows from inside the application flow (the gateway
# select on the application form) rather than a separate top-level page.
#
# Endpoints:
#   GET  /apps/new_gateway   — the inline "New gateway" form (name, kind, host_note)
#   POST /gateways           — create a gateway on the current zone
#   POST /gateways/:id/update_kind — minimal edit (kind + host_note only; name is
#                                   immutable — it drives ns_name <name>.<zone> and
#                                   the rendered service entry)
#
# Access: write-gated (read_only 403s). No NS publish: creating a gateway row is
# panel-local; the operator deploys the rendered policy and restarts the gateway.
require "test_helper"

class GatewaysCrudControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
    @existing_gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
  end

  # ---- GET /apps/new_gateway ----------------------------------------------

  test "new_gateway renders the inline form with name, kind and host_note fields" do
    get "/apps/new_gateway"
    assert_response :success
    assert_select "form[action=?]", gateways_path, count: 1
    # name + kind + host_note inputs present
    assert_select "input[name=?]", "gateway[name]", count: 1
    assert_select "select[name=?]", "gateway[kind]", count: 1
    assert_select "input[name=?]", "gateway[host_note]", count: 1
  end

  # ---- POST /gateways (create) --------------------------------------------

  test "create a gateway with name, kind rust_listen and host_note" do
    post gateways_path, params: { gateway: { name: "prod-gw", kind: "rust_listen",
                                             host_note: "10.42.42.91:23095" } }
    assert_redirected_to applications_path
    gw = @zone.gateways.find_by(name: "prod-gw")
    assert gw, "gateway should be created on the zone"
    assert_equal "prod-gw.#{Zone.primary.name}", gw.ns_name
    assert_equal "rust_listen", gw.kind
    assert_equal "10.42.42.91:23095", gw.host_note
    assert_equal "planned", gw.status
  end

  test "create a gateway with kind elixir" do
    post gateways_path, params: { gateway: { name: "elix-gw", kind: "elixir" } }
    assert_redirected_to applications_path
    gw = @zone.gateways.find_by(name: "elix-gw")
    assert gw
    assert_equal "elixir", gw.kind
    assert_nil gw.host_note
  end

  test "create with invalid kind 422s and does not persist" do
    post gateways_path, params: { gateway: { name: "bad", kind: "unknown_kind" } }
    assert_response :unprocessable_content
    assert_nil @zone.gateways.find_by(name: "bad")
  end

  test "create with duplicate name in same zone 422s" do
    post gateways_path, params: { gateway: { name: "gw1", kind: "elixir" } }
    assert_response :unprocessable_content
    assert_equal 1, @zone.gateways.where(name: "gw1").count
  end

  test "create with blank name 422s" do
    post gateways_path, params: { gateway: { name: "  ", kind: "elixir" } }
    assert_response :unprocessable_content
  end

  test "create normalizes an uppercase name to a lowercase DNS label" do
    # Gateway#normalize_name downcases before validation, so "BadGw" becomes
    # "badgw" — a valid label. This pins the normalization contract.
    post gateways_path, params: { gateway: { name: "BadGw", kind: "elixir" } }
    assert_redirected_to applications_path
    gw = @zone.gateways.find_by(name: "badgw")
    assert gw, "name should be normalized to lowercase"
    assert_equal "badgw", gw.name
    assert_equal "badgw.#{Zone.primary.name}", gw.ns_name
  end

  test "create with a name that has a leading hyphen (invalid label) 422s" do
    post gateways_path, params: { gateway: { name: "-bad", kind: "elixir" } }
    assert_response :unprocessable_content
    assert_nil @zone.gateways.find_by(name: "-bad")
  end

  test "create audits gateway.create with the gateway as target" do
    post gateways_path, params: { gateway: { name: "audited-gw", kind: "elixir" } }
    row = AuditLog.where(action: "gateway.create").last
    assert row
    assert_equal "Gateway", row.target_type
    assert_equal @zone.gateways.find_by(name: "audited-gw")&.id, row.target_id
    assert_equal "ok", row.status
    assert_equal @admin.id, row.admin_id
  end

  test "read_only admin gets 403 on POST /gateways" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "ro-user")
    sign_in_as(ro_admin, ro_seed)

    post gateways_path, params: { gateway: { name: "secret", kind: "elixir" } }
    assert_response :forbidden
    assert_nil @zone.gateways.find_by(name: "secret")
  end

  # ---- POST /gateways/:id/update_kind (minimal edit) -----------------------

  test "update_kind changes kind and host_note but not name" do
    post update_kind_gateway_path(@existing_gw),
         params: { kind: "elixir", host_note: "new-note" }
    assert_redirected_to applications_path
    @existing_gw.reload
    assert_equal "elixir", @existing_gw.kind
    assert_equal "new-note", @existing_gw.host_note
    assert_equal "gw1", @existing_gw.name # name immutable
  end

  test "update_kind with invalid kind 422s and does not change the row" do
    post update_kind_gateway_path(@existing_gw),
         params: { kind: "bogus" }
    assert_response :unprocessable_content
    assert_equal "rust_listen", @existing_gw.reload.kind
  end

  test "update_kind cross-zone gateway 404s" do
    other = Zone.create!(name: "elsewhere.ztlp", ns_addr: "10.0.0.1:23095")
    other_gw = other.gateways.create!(name: "gw2", kind: "elixir", status: "planned")

    post update_kind_gateway_path(other_gw), params: { kind: "rust_listen" }
    assert_response :not_found
    assert_equal "elixir", other_gw.reload.kind
  end

  test "read_only admin gets 403 on update_kind" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "ro-user")
    sign_in_as(ro_admin, ro_seed)

    post update_kind_gateway_path(@existing_gw), params: { kind: "elixir" }
    assert_response :forbidden
    assert_equal "rust_listen", @existing_gw.reload.kind
  end

  # ---- the application new form shows the inline gateway form link ---------

  test "the application new form includes a link to the inline gateway form" do
    get new_application_path
    assert_response :success
    assert_select "a[href=?]", "/apps/new_gateway", count: 1
  end
end
