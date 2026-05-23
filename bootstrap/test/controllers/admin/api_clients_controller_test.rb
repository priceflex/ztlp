# frozen_string_literal: true

require "test_helper"

# Integration tests for Admin::ApiClientsController — the dashboard
# CRUD UI for the `api_clients` allowlist surfaced in BS-PR-5.
#
# Coverage:
#
#   * Authorization: only super admins may access
#   * CRUD round-trip: create / edit / update / delete
#   * Deactivate / reactivate (the kill switch from BS-PR-2)
#   * Audit log on every mutation
#   * Validation errors render the new/edit page with status 422
class Admin::ApiClientsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @super  = admin_users(:super_admin)
    @admin  = admin_users(:regular_admin)
    @client = api_clients(:z2ls_office)
  end

  def sign_in_as(admin_user)
    # Sessions controller will set session[:admin_user_id]
    post login_path, params: { email: admin_user.email, password: "password123" }
  end

  # ── Authorization ───────────────────────────────────────────────

  test "unauthenticated user is redirected to login" do
    get admin_api_clients_path
    assert_redirected_to login_path
  end

  test "non-super_admin is forbidden" do
    sign_in_as(@admin)
    get admin_api_clients_path
    # require_super_admin redirects with an alert when not super
    refute_equal 200, response.status
  end

  test "super_admin can see the index" do
    sign_in_as(@super)
    get admin_api_clients_path
    assert_response :success
    assert_match @client.name, response.body
    assert_match @client.zone, response.body
  end

  # ── Create ──────────────────────────────────────────────────────

  test "creates a new api_client with valid params" do
    sign_in_as(@super)

    assert_difference -> { ApiClient.count }, 1 do
      assert_difference -> { AuditLog.where(action: "api_client.created").count }, 1 do
        post admin_api_clients_path, params: {
          api_client: { name: "z2ls.prod", zone: "prod.acme.ztlp", notes: "Production Z2LS" }
        }
      end
    end

    follow_redirect!
    assert_match(/created/i, response.body)
  end

  test "rejects an api_client missing the zone" do
    sign_in_as(@super)

    assert_no_difference -> { ApiClient.count } do
      post admin_api_clients_path, params: {
        api_client: { name: "broken", zone: "" }
      }
    end

    assert_response :unprocessable_entity
  end

  test "rejects an api_client whose (zone, name) collides" do
    sign_in_as(@super)

    assert_no_difference -> { ApiClient.count } do
      post admin_api_clients_path, params: {
        api_client: { name: @client.name, zone: @client.zone }
      }
    end

    assert_response :unprocessable_entity
    assert_match(/unique per zone/i, response.body)
  end

  # ── Update ──────────────────────────────────────────────────────

  test "updates notes via PATCH" do
    sign_in_as(@super)

    patch admin_api_client_path(@client), params: {
      api_client: { notes: "Updated note from BS-PR-5 test" }
    }
    assert_redirected_to admin_api_clients_path

    assert_equal "Updated note from BS-PR-5 test", @client.reload.notes
  end

  # ── Deactivate / Reactivate (kill switch) ───────────────────────

  test "deactivate flips active to false and writes audit log" do
    sign_in_as(@super)

    assert_difference -> { AuditLog.where(action: "api_client.deactivated").count }, 1 do
      post deactivate_admin_api_client_path(@client)
    end

    refute @client.reload.active
  end

  test "reactivate flips active to true and writes audit log" do
    @client.update!(active: false)
    sign_in_as(@super)

    assert_difference -> { AuditLog.where(action: "api_client.reactivated").count }, 1 do
      post reactivate_admin_api_client_path(@client)
    end

    assert @client.reload.active
  end

  # ── Destroy ─────────────────────────────────────────────────────

  test "destroy removes the row and writes an audit log" do
    sign_in_as(@super)

    assert_difference -> { ApiClient.count }, -1 do
      assert_difference -> { AuditLog.where(action: "api_client.deleted").count }, 1 do
        delete admin_api_client_path(@client)
      end
    end
  end
end
