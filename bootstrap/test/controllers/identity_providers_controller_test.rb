# frozen_string_literal: true

require "test_helper"

class IdentityProvidersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @google_idp = identity_providers(:google_idp)
  end

  # --- Index ---

  test "index lists identity providers" do
    get network_identity_providers_path(@network)
    assert_response :success
    assert_match "Identity Providers", response.body
    assert_match @google_idp.name, response.body
  end

  # --- Show ---

  test "show displays provider details" do
    get network_identity_provider_path(@network, @google_idp)
    assert_response :success
    assert_match @google_idp.name, response.body
    assert_match @google_idp.client_id, response.body
  end

  # --- New ---

  test "new renders form" do
    get new_network_identity_provider_path(@network)
    assert_response :success
    assert_match "Add Identity Provider", response.body
  end

  # --- Create ---

  test "create with valid params" do
    assert_difference "IdentityProvider.count", 1 do
      post network_identity_providers_path(@network), params: {
        identity_provider: {
          name: "New Google IdP",
          provider_type: "google_oauth2",
          client_id: "new-client-id",
          client_secret: "new-secret",
          allowed_domains: "newdomain.com",
          auto_create_users: true,
          role_default: "user"
        }
      }
    end
    assert_redirected_to network_identity_provider_path(@network, IdentityProvider.last)
    follow_redirect!
    assert_match "New Google IdP", response.body
  end

  test "create records audit log" do
    assert_difference "AuditLog.count", 1 do
      post network_identity_providers_path(@network), params: {
        identity_provider: {
          name: "Audit Test",
          provider_type: "google_oauth2",
          client_id: "audit-client-id",
          client_secret: "audit-secret"
        }
      }
    end
  end

  test "create with invalid params renders new" do
    assert_no_difference "IdentityProvider.count" do
      post network_identity_providers_path(@network), params: {
        identity_provider: {
          name: "",
          provider_type: "google_oauth2",
          client_id: "x",
          client_secret: "x"
        }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create openid_connect without issuer_url fails" do
    assert_no_difference "IdentityProvider.count" do
      post network_identity_providers_path(@network), params: {
        identity_provider: {
          name: "Bad OIDC",
          provider_type: "openid_connect",
          client_id: "x",
          client_secret: "x"
        }
      }
    end
    assert_response :unprocessable_entity
  end

  # --- Edit ---

  test "edit renders form" do
    get edit_network_identity_provider_path(@network, @google_idp)
    assert_response :success
    assert_match @google_idp.name, response.body
  end

  # --- Update ---

  test "update with valid params" do
    patch network_identity_provider_path(@network, @google_idp), params: {
      identity_provider: { name: "Updated Google" }
    }
    assert_redirected_to network_identity_provider_path(@network, @google_idp)
    @google_idp.reload
    assert_equal "Updated Google", @google_idp.name
  end

  test "update with blank secret keeps existing secret" do
    original_secret = @google_idp.client_secret_ciphertext
    patch network_identity_provider_path(@network, @google_idp), params: {
      identity_provider: { name: "Keep Secret", client_secret: "" }
    }
    assert_redirected_to network_identity_provider_path(@network, @google_idp)
    @google_idp.reload
    assert_equal original_secret, @google_idp.client_secret_ciphertext
  end

  test "update with invalid params renders edit" do
    patch network_identity_provider_path(@network, @google_idp), params: {
      identity_provider: { name: "" }
    }
    assert_response :unprocessable_entity
  end

  # --- Destroy ---

  test "destroy removes provider" do
    assert_difference "IdentityProvider.count", -1 do
      delete network_identity_provider_path(@network, @google_idp)
    end
    assert_redirected_to network_identity_providers_path(@network)
  end

  test "destroy records audit log" do
    assert_difference "AuditLog.count", 1 do
      delete network_identity_provider_path(@network, @google_idp)
    end
  end
end
