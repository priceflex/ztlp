# frozen_string_literal: true

require "test_helper"

class Admin::UsersControllerTest < ActionDispatch::IntegrationTest
  setup do
    @super_admin = admin_users(:super_admin)
    @regular_admin = admin_users(:regular_admin)
    @locked_admin = admin_users(:locked_admin)
    sign_in(@super_admin)
  end

  # --- Authorization ---

  test "non-super_admin cannot access admin users" do
    sign_in(@regular_admin)
    get admin_users_path
    assert_redirected_to root_path
    assert_equal "Not authorized.", flash[:alert]
  end

  test "read_only admin cannot access admin users" do
    sign_in(admin_users(:read_only_admin))
    get admin_users_path
    assert_redirected_to root_path
  end

  test "unauthenticated user redirects to login" do
    delete logout_path
    get admin_users_path
    assert_redirected_to login_path
  end

  # --- Index ---

  test "index lists admin users" do
    get admin_users_path
    assert_response :success
    assert_includes response.body, "Admin Users"
    assert_includes response.body, @super_admin.name
    assert_includes response.body, @regular_admin.name
  end

  # --- New ---

  test "new renders form" do
    get new_admin_user_path
    assert_response :success
    assert_includes response.body, "New Admin User"
  end

  # --- Create ---

  test "create adds a new admin user" do
    assert_difference "AdminUser.count" do
      post admin_users_path, params: {
        admin_user: {
          email: "new@example.com",
          name: "New Admin",
          password: "securepass123",
          password_confirmation: "securepass123",
          role: "admin"
        }
      }
    end
    assert_redirected_to admin_users_path
    assert_equal "Admin user created successfully.", flash[:notice]
  end

  test "create logs audit event" do
    assert_difference "AuditLog.count" do
      post admin_users_path, params: {
        admin_user: {
          email: "audit@example.com",
          name: "Audit Test",
          password: "securepass123",
          password_confirmation: "securepass123",
          role: "admin"
        }
      }
    end
    assert_equal "admin_created", AuditLog.last.action
  end

  test "create with invalid data re-renders form" do
    assert_no_difference "AdminUser.count" do
      post admin_users_path, params: {
        admin_user: { email: "", name: "", password: "", role: "admin" }
      }
    end
    assert_response :unprocessable_entity
  end

  # --- Edit ---

  test "edit renders form" do
    get edit_admin_user_path(@regular_admin)
    assert_response :success
    assert_includes response.body, "Edit Admin User"
  end

  # --- Update ---

  test "update changes admin user" do
    patch admin_user_path(@regular_admin), params: {
      admin_user: { name: "Updated Name", email: @regular_admin.email, role: "admin" }
    }
    assert_redirected_to admin_users_path
    @regular_admin.reload
    assert_equal "Updated Name", @regular_admin.name
  end

  test "update without password keeps existing password" do
    patch admin_user_path(@regular_admin), params: {
      admin_user: { name: "Same Pass", email: @regular_admin.email, password: "", role: "admin" }
    }
    assert_redirected_to admin_users_path
    @regular_admin.reload
    assert @regular_admin.authenticate("password123")
  end

  test "update logs audit event" do
    assert_difference "AuditLog.count" do
      patch admin_user_path(@regular_admin), params: {
        admin_user: { name: "Audit Update", email: @regular_admin.email, role: "admin" }
      }
    end
    assert_equal "admin_updated", AuditLog.last.action
  end

  # --- Destroy ---

  test "destroy deletes admin user" do
    assert_difference "AdminUser.count", -1 do
      delete admin_user_path(@regular_admin)
    end
    assert_redirected_to admin_users_path
    assert_equal "Admin user deleted.", flash[:notice]
  end

  test "destroy prevents self-deletion" do
    assert_no_difference "AdminUser.count" do
      delete admin_user_path(@super_admin)
    end
    assert_redirected_to admin_users_path
    assert_equal "You cannot delete your own account.", flash[:alert]
  end

  test "destroy logs audit event" do
    assert_difference "AuditLog.count" do
      delete admin_user_path(@regular_admin)
    end
    assert_equal "admin_deleted", AuditLog.last.action
  end

  # --- Unlock ---

  test "unlock clears lock on admin user" do
    assert @locked_admin.locked?
    post unlock_admin_user_path(@locked_admin)
    assert_redirected_to admin_users_path
    @locked_admin.reload
    assert_not @locked_admin.locked?
    assert_equal 0, @locked_admin.failed_login_attempts
  end

  test "unlock logs audit event" do
    assert_difference "AuditLog.count" do
      post unlock_admin_user_path(@locked_admin)
    end
    assert_equal "admin_unlocked", AuditLog.last.action
  end

  private

  def sign_in(admin)
    post login_path, params: { email: admin.email, password: "password123" }
  end
end
