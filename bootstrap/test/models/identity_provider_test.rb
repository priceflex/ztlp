# frozen_string_literal: true

require "test_helper"

class IdentityProviderTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @google_idp = identity_providers(:google_idp)
    @oidc_idp = identity_providers(:oidc_idp)
  end

  # --- Validations ---

  test "valid google_oauth2 provider" do
    idp = @network.identity_providers.new(
      name: "Test Google",
      provider_type: "google_oauth2",
      client_id: "test-client-id",
      client_secret: "test-secret"
    )
    assert idp.valid?, idp.errors.full_messages.join(", ")
  end

  test "valid openid_connect provider" do
    idp = @network.identity_providers.new(
      name: "Test OIDC",
      provider_type: "openid_connect",
      client_id: "test-client-id",
      client_secret: "test-secret",
      issuer_url: "https://login.microsoftonline.com/tenant/v2.0"
    )
    assert idp.valid?, idp.errors.full_messages.join(", ")
  end

  test "requires name" do
    idp = @network.identity_providers.new(
      provider_type: "google_oauth2",
      client_id: "x",
      client_secret: "x"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:name], "can't be blank"
  end

  test "requires client_id" do
    idp = @network.identity_providers.new(
      name: "Test",
      provider_type: "google_oauth2",
      client_secret: "x"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:client_id], "can't be blank"
  end

  test "requires client_secret_ciphertext" do
    idp = @network.identity_providers.new(
      name: "Test",
      provider_type: "google_oauth2",
      client_id: "x"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:client_secret_ciphertext], "can't be blank"
  end

  test "requires valid provider_type" do
    idp = @network.identity_providers.new(
      name: "Test",
      provider_type: "invalid_type",
      client_id: "x",
      client_secret: "x"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:provider_type], "is not included in the list"
  end

  test "openid_connect requires issuer_url" do
    idp = @network.identity_providers.new(
      name: "Test OIDC",
      provider_type: "openid_connect",
      client_id: "x",
      client_secret: "x"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:issuer_url], "can't be blank"
  end

  test "google_oauth2 does not require issuer_url" do
    idp = @network.identity_providers.new(
      name: "Test Google",
      provider_type: "google_oauth2",
      client_id: "x",
      client_secret: "x"
    )
    assert idp.valid?
  end

  test "requires valid role_default" do
    idp = @network.identity_providers.new(
      name: "Test",
      provider_type: "google_oauth2",
      client_id: "x",
      client_secret: "x",
      role_default: "superadmin"
    )
    assert_not idp.valid?
    assert_includes idp.errors[:role_default], "is not included in the list"
  end

  # --- Domain checking ---

  test "domain_allowed? returns true when no domains configured" do
    idp = IdentityProvider.new(allowed_domains: nil)
    assert idp.domain_allowed?("user@anything.com")
  end

  test "domain_allowed? returns true when empty string" do
    idp = IdentityProvider.new(allowed_domains: "")
    assert idp.domain_allowed?("user@anything.com")
  end

  test "domain_allowed? checks against allowed domains" do
    assert @google_idp.domain_allowed?("user@example.com")
    assert @google_idp.domain_allowed?("user@acme.com")
    assert_not @google_idp.domain_allowed?("user@evil.com")
  end

  test "domain_allowed? is case insensitive" do
    assert @google_idp.domain_allowed?("user@EXAMPLE.COM")
    assert @google_idp.domain_allowed?("user@Example.Com")
  end

  # --- Helpers ---

  test "allowed_domain_list parses comma-separated domains" do
    assert_equal ["example.com", "acme.com"], @google_idp.allowed_domain_list
  end

  test "allowed_domain_list returns empty array for nil" do
    idp = IdentityProvider.new(allowed_domains: nil)
    assert_equal [], idp.allowed_domain_list
  end

  test "client_secret virtual attribute" do
    idp = IdentityProvider.new
    idp.client_secret = "my-secret"
    assert_equal "my-secret", idp.client_secret
    assert_equal "my-secret", idp.client_secret_ciphertext
  end

  test "google? returns true for google_oauth2" do
    assert @google_idp.google?
    assert_not @oidc_idp.google?
  end

  test "openid_connect? returns true for openid_connect" do
    assert @oidc_idp.openid_connect?
    assert_not @google_idp.openid_connect?
  end

  test "display_type returns human-readable type" do
    assert_equal "Google Workspace", @google_idp.display_type
    assert_match "OIDC", @oidc_idp.display_type
  end

  test "omniauth_strategy returns provider_type" do
    assert_equal "google_oauth2", @google_idp.omniauth_strategy
    assert_equal "openid_connect", @oidc_idp.omniauth_strategy
  end

  # --- Scopes ---

  test "enabled scope returns only enabled providers" do
    enabled = @network.identity_providers.enabled
    assert_includes enabled, @google_idp
    assert_includes enabled, @oidc_idp
    assert_not_includes enabled, identity_providers(:disabled_idp)
  end

  # --- Associations ---

  test "belongs to network" do
    assert_equal @network, @google_idp.network
  end

  test "network has many identity_providers" do
    assert_includes @network.identity_providers, @google_idp
  end

  test "destroying network destroys identity_providers" do
    network = Network.create!(name: "Temp Net", zone: "temp.ztlp", status: "created")
    network.identity_providers.create!(
      name: "Temp IdP",
      provider_type: "google_oauth2",
      client_id: "x",
      client_secret: "x"
    )
    assert_difference "IdentityProvider.count", -1 do
      network.destroy!
    end
  end
end
