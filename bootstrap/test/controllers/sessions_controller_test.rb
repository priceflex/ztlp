# frozen_string_literal: true

require "test_helper"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin = admin_users(:super_admin)
  end

  # --- GET /login ---

  test "new renders login page" do
    get login_path
    assert_response :success
    assert_includes response.body, "ZTLP Bootstrap"
    assert_includes response.body, "Sign In"
  end

  test "new redirects to root if already signed in" do
    sign_in(@admin)
    get login_path
    assert_redirected_to root_path
  end

  # --- POST /login ---

  test "create with valid credentials signs in and redirects to root" do
    post login_path, params: { email: @admin.email, password: "password123" }
    assert_redirected_to root_path
    follow_redirect!
    assert_response :success
  end

  test "create sets session" do
    post login_path, params: { email: @admin.email, password: "password123" }
    # Verify by accessing a protected page
    get root_path
    assert_response :success
  end

  test "create records login in audit log" do
    assert_difference "AuditLog.count" do
      post login_path, params: { email: @admin.email, password: "password123" }
    end
    assert_equal "admin_login", AuditLog.last.action
  end

  test "create with invalid password shows error" do
    post login_path, params: { email: @admin.email, password: "wrongpassword" }
    assert_response :unprocessable_entity
    assert_includes response.body, "Invalid email or password"
  end

  test "create with nonexistent email shows error" do
    post login_path, params: { email: "nobody@example.com", password: "password123" }
    assert_response :unprocessable_entity
    assert_includes response.body, "Invalid email or password"
  end

  test "create with case-insensitive email works" do
    post login_path, params: { email: @admin.email.upcase, password: "password123" }
    assert_redirected_to root_path
  end

  test "create increments failed login attempts" do
    initial = @admin.failed_login_attempts
    post login_path, params: { email: @admin.email, password: "wrong" }
    @admin.reload
    assert_equal initial + 1, @admin.failed_login_attempts
  end

  test "create locks account after 5 failed attempts" do
    @admin.update!(failed_login_attempts: 4)
    post login_path, params: { email: @admin.email, password: "wrong" }
    @admin.reload
    assert @admin.locked?
    assert_includes response.body, "Account locked"
  end

  test "create rejects login for locked account" do
    locked = admin_users(:locked_admin)
    post login_path, params: { email: locked.email, password: "password123" }
    assert_response :unprocessable_entity
    assert_includes response.body, "Account locked"
  end

  test "create redirects to intended URL after login" do
    get networks_path
    assert_redirected_to login_path
    post login_path, params: { email: @admin.email, password: "password123" }
    assert_redirected_to networks_path
  end

  # --- DELETE /logout ---

  test "destroy clears session and redirects to login" do
    sign_in(@admin)
    delete logout_path
    assert_redirected_to login_path
    # Should not be able to access protected pages
    get root_path
    assert_redirected_to login_path
  end

  private

  def sign_in(admin)
    post login_path, params: { email: admin.email, password: "password123" }
  end
end
