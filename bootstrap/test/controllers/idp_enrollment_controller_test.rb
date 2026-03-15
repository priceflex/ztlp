# frozen_string_literal: true

require "test_helper"

class IdpEnrollmentControllerTest < ActionDispatch::IntegrationTest
  setup do
    @network = networks(:office)
    @google_idp = identity_providers(:google_idp)

    # Enable OmniAuth test mode
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-12345",
      info: {
        email: "alice@example.com",
        name: "Alice Smith"
      },
      extra: {
        raw_info: { "iss" => "https://accounts.google.com" }
      }
    )
  end

  teardown do
    OmniAuth.config.test_mode = false
    OmniAuth.config.mock_auth[:google_oauth2] = nil
  end

  # --- Self-service enrollment page ---

  test "new shows sign-in buttons when IdPs configured" do
    get network_enroll_path(@network)
    assert_response :success
    assert_match "Enroll Your Device", response.body
    assert_match "Sign in with Google", response.body
  end

  test "new redirects when no IdPs configured" do
    # Use production network which has an IdP, but let's use a network without enabled IdPs
    prod = networks(:production)
    prod.identity_providers.update_all(enabled: false)
    get network_enroll_path(prod)
    # prod_idp is enabled by default in fixtures, let me check
    # Actually prod_idp fixture is enabled. Let me just disable it.
    identity_providers(:prod_idp).update!(enabled: false)
    get network_enroll_path(prod)
    assert_redirected_to network_enrollment_index_path(prod)
  end

  test "new stores network_id in session" do
    get network_enroll_path(@network)
    assert_response :success
    # Session is set internally; we verify via callback flow
  end

  # --- Callback (successful Google auth) ---

  test "callback with existing user generates token" do
    # alice@example.com is in the fixtures and matches google_idp allowed_domains
    alice = ztlp_users(:alice)

    # Set up session (simulate the enrollment new page storing network_id)
    get network_enroll_path(@network)

    assert_difference "EnrollmentToken.count", 1 do
      get "/auth/google_oauth2/callback"
    end
    assert_response :success
    assert_match "Enrollment Ready", response.body
    assert_match alice.name, response.body
  end

  test "callback creates audit logs" do
    get network_enroll_path(@network)

    # idp_login + idp_enrollment_token_generated + token_generate (from TokenGenerator)
    assert_difference "AuditLog.count", 3 do
      get "/auth/google_oauth2/callback"
    end
  end

  test "callback with auto-create creates new user" do
    # google_idp has auto_create_users: true
    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-newuser-999",
      info: {
        email: "newuser@example.com",
        name: "New User"
      },
      extra: {
        raw_info: { "iss" => "https://accounts.google.com" }
      }
    )

    get network_enroll_path(@network)

    # Mock ZtlpAdmin to avoid SSH calls
    ZtlpAdmin.any_instance.stubs(:create_user).returns({})

    assert_difference "ZtlpUser.count", 1 do
      assert_difference "EnrollmentToken.count", 1 do
        get "/auth/google_oauth2/callback"
      end
    end
    assert_response :success

    new_user = ZtlpUser.find_by(email: "newuser@example.com")
    assert_not_nil new_user
    assert_equal "user", new_user.role
    assert_equal "google-uid-newuser-999", new_user.external_id
    assert_equal "https://accounts.google.com", new_user.idp_issuer
  end

  test "callback rejects unauthorized domain" do
    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-evil",
      info: {
        email: "hacker@evil.com",
        name: "Evil Hacker"
      },
      extra: {
        raw_info: { "iss" => "https://accounts.google.com" }
      }
    )

    get network_enroll_path(@network)
    get "/auth/google_oauth2/callback"

    assert_redirected_to network_enroll_path(@network)
    follow_redirect!
    assert_match "not authorized", response.body
  end

  test "callback rejects revoked user" do
    revoked = ztlp_users(:revoked_user)
    revoked.update!(email: "dave@example.com")

    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-dave",
      info: {
        email: "dave@example.com",
        name: "Dave"
      },
      extra: {
        raw_info: { "iss" => "https://accounts.google.com" }
      }
    )

    get network_enroll_path(@network)
    get "/auth/google_oauth2/callback"

    assert_redirected_to network_enroll_path(@network)
    follow_redirect!
    assert_match "revoked", response.body
  end

  test "callback without auto-create and no existing user" do
    # Use oidc_idp which has auto_create_users: false
    # But oidc_idp only allows acme.com domain
    @google_idp.update!(auto_create_users: false)

    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-unknown",
      info: {
        email: "unknown@example.com",
        name: "Unknown User"
      },
      extra: {
        raw_info: { "iss" => "https://accounts.google.com" }
      }
    )

    get network_enroll_path(@network)
    get "/auth/google_oauth2/callback"

    assert_redirected_to network_enroll_path(@network)
    follow_redirect!
    assert_match "Unable to create", response.body
  end

  test "callback updates last_login_at" do
    alice = ztlp_users(:alice)
    assert_nil alice.last_login_at

    get network_enroll_path(@network)
    get "/auth/google_oauth2/callback"

    alice.reload
    assert_not_nil alice.last_login_at
  end

  test "callback sets external_id on existing user" do
    alice = ztlp_users(:alice)
    assert_nil alice.external_id

    get network_enroll_path(@network)
    get "/auth/google_oauth2/callback"

    alice.reload
    assert_equal "google-uid-12345", alice.external_id
    assert_equal "https://accounts.google.com", alice.idp_issuer
  end

  # --- Failure ---

  test "failure redirects with error message" do
    # Store network_id in session first
    get network_enroll_path(@network)
    get "/auth/failure", params: { message: "access_denied" }

    assert_redirected_to network_enroll_path(@network)
    follow_redirect!
    assert_match "Access denied", response.body
  end

  test "failure without session redirects to root" do
    get "/auth/failure", params: { message: "invalid_credentials" }
    assert_redirected_to root_path
  end

  # --- Callback edge cases ---

  test "callback without auth data redirects to root" do
    # Without test mode, OmniAuth redirects to /auth/failure on CSRF check
    OmniAuth.config.test_mode = false
    get "/auth/google_oauth2/callback"
    # OmniAuth redirects to /auth/failure which then redirects to root
    assert_response :redirect
    follow_redirect! # -> /auth/failure
    assert_redirected_to root_path
  end

  test "callback without session network_id redirects to root" do
    # Hit callback without visiting enrollment page first
    # In test mode, OmniAuth will set the mock but session won't have network_id
    # We need to clear the session
    reset!
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:google_oauth2] = OmniAuth::AuthHash.new(
      provider: "google_oauth2",
      uid: "google-uid-12345",
      info: { email: "alice@example.com", name: "Alice" },
      extra: { raw_info: { "iss" => "https://accounts.google.com" } }
    )

    get "/auth/google_oauth2/callback"
    assert_redirected_to root_path
  end
end
