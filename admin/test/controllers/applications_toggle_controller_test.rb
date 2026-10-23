# frozen_string_literal: true

# Slice 9b sub-slice 5: application enable/disable (POST /apps/:id/enable|disable).
#
# The rendered gateway policy only lists `[[services]]` for ENABLED
# applications (Ztlp::PolicyRenderer skips disabled ones), so toggling an
# application is how an operator takes a service off the allow-list without
# deleting its rules. Same contract as the rest of Slice 9b: nothing is
# published to the NS — the operator deploys the rendered policy and restarts
# the gateway for the change to take effect.
#
# Access: require_write_access (read_only admin 403s on both verbs); both
# actions are zone-scoped (a foreign application id 404s).
require "test_helper"

class ApplicationsToggleControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @app = @gw.applications.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2,
                                    description: "Blitz terminal")
  end

  test "disable removes the service from the rendered policy and shows disabled" do
    assert @app.enabled
    assert_includes Ztlp::PolicyRenderer.render(@gw), "name = \"comms-blitz\""

    post enable_application_path(@app) # wrong verb on an enabled app: no-op redirect
    assert_redirected_to application_path(@app)
    assert @app.reload.enabled

    post disable_application_path(@app)
    assert_redirected_to application_path(@app)
    assert_not @app.reload.enabled

    get application_path(@app)
    assert_response :success
    assert_select "span.bad", text: "disabled"
    rendered = Ztlp::PolicyRenderer.render(@gw)
    assert_not_includes rendered, "comms-blitz"
  end

  test "enable puts the service back in the rendered policy" do
    @app.update!(enabled: false)
    assert_not_includes Ztlp::PolicyRenderer.render(@gw), "comms-blitz"

    post disable_application_path(@app) # wrong verb on a disabled app: no-op
    assert_not @app.reload.enabled

    post enable_application_path(@app)
    assert @app.reload.enabled
    assert_includes Ztlp::PolicyRenderer.render(@gw), "name = \"comms-blitz\""

    get application_path(@app)
    assert_select "span.ok", text: "enabled"
  end

  test "toggling writes one audit row each with the application as target" do
    post disable_application_path(@app)
    row = AuditLog.where(action: "application.disable").last
    assert row
    assert_equal "Application", row.target_type
    assert_equal @app.id, row.target_id
    assert_equal "ok", row.status
    assert_equal @admin.id, row.admin_id

    post enable_application_path(@app)
    assert AuditLog.where(action: "application.enable", target_id: @app.id).exists?
  end

  test "cross-zone application id 404s on enable and disable" do
    other = Zone.create!(name: "elsewhere.ztlp", ns_addr: "10.0.0.1:23095")
    other_gw = other.gateways.create!(name: "gw2", kind: "elixir", status: "planned")
    other_app = other_gw.applications.create!(name: "secret", protocol: "http", min_assurance: 1)

    post enable_application_path(other_app)
    assert_response :not_found
    post disable_application_path(other_app)
    assert_response :not_found
    assert other_app.reload.enabled # nothing changed
  end

  test "read_only admin gets 403 on enable and disable" do
    ro_admin, ro_seed = make_admin(role: "read_only", username: "ro-user")
    sign_in_as(ro_admin, ro_seed)

    post enable_application_path(@app)
    assert_response :forbidden
    post disable_application_path(@app)
    assert_response :forbidden
    assert @app.reload.enabled
  end

  test "show page renders the right verb button and the disable button confirms" do
    get application_path(@app)
    assert_response :success
    assert_select "form[action=?]", disable_application_path(@app), count: 1
    assert_select "form[action=?]", enable_application_path(@app), count: 0

    @app.update!(enabled: false)
    get application_path(@app)
    assert_select "form[action=?]", enable_application_path(@app), count: 1
    assert_select "form[action=?]", disable_application_path(@app), count: 0
  end

  test "drawer fragment renders the toggle buttons without layout" do
    post disable_application_path(@app)
    get application_path(@app), headers: { "X-Drawer" => "1" }
    assert_response :success
    assert_select "form[action=?]", enable_application_path(@app), count: 1
  end
end
