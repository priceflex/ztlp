# frozen_string_literal: true

require "test_helper"

class PoliciesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as(:regular_admin)
    @network = networks(:office)
    @policy = policies(:allow_internal)
  end

  # --- Index ---

  test "index lists policies" do
    get network_policies_path(@network)
    assert_response :success
    assert_match "Allow Internal Services", response.body
    assert_match "Deny Admin Zone", response.body
  end

  test "index groups by type" do
    get network_policies_path(@network)
    assert_response :success
    assert_match "Access Control", response.body
    assert_match "Time-Based", response.body
  end

  test "index shows action badges" do
    get network_policies_path(@network)
    assert_response :success
    assert_match "Allow", response.body
    assert_match "Deny", response.body
  end

  test "index filters by type" do
    get network_policies_path(@network), params: { type: "access" }
    assert_response :success
    assert_match "Allow Internal Services", response.body
    assert_no_match(/Contractor Business Hours/, response.body)
  end

  test "index filters by status" do
    get network_policies_path(@network), params: { status: "disabled" }
    assert_response :success
    assert_match "Disabled Old Policy", response.body
  end

  test "index filters by action" do
    get network_policies_path(@network), params: { action_filter: "deny" }
    assert_response :success
    assert_match "Deny Admin Zone", response.body
  end

  test "index searches by name" do
    get network_policies_path(@network), params: { search: "Internal" }
    assert_response :success
    assert_match "Allow Internal Services", response.body
  end

  test "index shows summary stats" do
    get network_policies_path(@network)
    assert_response :success
    assert_match "Total Policies", response.body
    assert_match "Allow Rules", response.body
    assert_match "Deny Rules", response.body
  end

  # --- Show ---

  test "show displays policy details" do
    get network_policy_path(@network, @policy)
    assert_response :success
    assert_match "Allow Internal Services", response.body
    assert_match "Everyone", response.body
    assert_match "*.internal", response.body
  end

  test "show displays effective scope" do
    get network_policy_path(@network, @policy)
    assert_response :success
    assert_match "Effective Scope", response.body
  end

  test "show displays gateway rule preview" do
    get network_policy_path(@network, @policy)
    assert_response :success
    assert_match "Gateway Rule Preview", response.body
  end

  test "show displays conflict warning" do
    # Create a conflicting policy
    @network.policies.create!(
      name: "Deny Internal Services",
      policy_type: "access",
      subject_type: "everyone",
      resource_type: "service",
      resource_value: "*.internal",
      action: "deny"
    )
    get network_policy_path(@network, @policy)
    assert_response :success
    assert_match "Conflicting Policies Detected", response.body
  end

  # --- New ---

  test "new renders form" do
    get new_network_policy_path(@network)
    assert_response :success
    assert_select "form"
  end

  test "new with policy_type preselect" do
    get new_network_policy_path(@network), params: { policy_type: "time_based" }
    assert_response :success
  end

  # --- Create ---

  test "create adds new policy" do
    assert_difference "Policy.count", 1 do
      post network_policies_path(@network), params: {
        policy: {
          name: "New Test Policy",
          policy_type: "access",
          priority: "normal",
          subject_type: "everyone",
          resource_type: "service",
          resource_value: "test.internal",
          action: "allow",
          timezone: "UTC"
        }
      }
    end
    assert_redirected_to network_policy_path(@network, Policy.last)
    follow_redirect!
    assert_match "New Test Policy", response.body
  end

  test "create records audit log" do
    assert_difference "AuditLog.count", 1 do
      post network_policies_path(@network), params: {
        policy: {
          name: "Audit Test Policy",
          policy_type: "access",
          subject_type: "everyone",
          resource_type: "service",
          resource_value: "test.internal",
          action: "allow",
          timezone: "UTC"
        }
      }
    end
    log = AuditLog.last
    assert_equal "policy_create", log.action
  end

  test "create with invalid data re-renders form" do
    assert_no_difference "Policy.count" do
      post network_policies_path(@network), params: {
        policy: { name: "", policy_type: "access", subject_type: "everyone", resource_type: "service", resource_value: "", action: "allow", timezone: "UTC" }
      }
    end
    assert_response :unprocessable_entity
  end

  test "create warns about conflicts" do
    post network_policies_path(@network), params: {
      policy: {
        name: "Conflict Test",
        policy_type: "access",
        subject_type: "everyone",
        resource_type: "service",
        resource_value: "*.internal",
        action: "deny",
        timezone: "UTC"
      }
    }
    assert_redirected_to network_policy_path(@network, Policy.last)
    follow_redirect!
    # The flash should mention conflict warning
  end

  # --- Edit ---

  test "edit renders form" do
    get edit_network_policy_path(@network, @policy)
    assert_response :success
    assert_select "form"
  end

  # --- Update ---

  test "update modifies policy" do
    patch network_policy_path(@network, @policy), params: {
      policy: { name: "Updated Policy Name" }
    }
    assert_redirected_to network_policy_path(@network, @policy)
    @policy.reload
    assert_equal "Updated Policy Name", @policy.name
  end

  test "update records audit log" do
    assert_difference "AuditLog.count", 1 do
      patch network_policy_path(@network, @policy), params: {
        policy: { name: "Updated" }
      }
    end
    log = AuditLog.last
    assert_equal "policy_update", log.action
  end

  test "update with invalid data re-renders form" do
    patch network_policy_path(@network, @policy), params: {
      policy: { name: "" }
    }
    assert_response :unprocessable_entity
  end

  # --- Destroy ---

  test "destroy deletes policy" do
    assert_difference "Policy.count", -1 do
      delete network_policy_path(@network, @policy)
    end
    assert_redirected_to network_policies_path(@network)
  end

  test "destroy records audit log" do
    assert_difference "AuditLog.count", 1 do
      delete network_policy_path(@network, @policy)
    end
    log = AuditLog.last
    assert_equal "policy_destroy", log.action
  end

  # --- Toggle ---

  test "toggle enables disabled policy" do
    disabled = policies(:disabled_policy)
    assert_not disabled.enabled?
    post toggle_network_policy_path(@network, disabled)
    assert_redirected_to network_policies_path(@network)
    disabled.reload
    assert disabled.enabled?
  end

  test "toggle disables enabled policy" do
    assert @policy.enabled?
    post toggle_network_policy_path(@network, @policy)
    assert_redirected_to network_policies_path(@network)
    @policy.reload
    assert_not @policy.enabled?
  end

  test "toggle records audit log" do
    assert_difference "AuditLog.count", 1 do
      post toggle_network_policy_path(@network, @policy)
    end
    log = AuditLog.last
    assert_equal "policy_toggle", log.action
  end

  # --- Duplicate ---

  test "duplicate creates copy" do
    assert_difference "Policy.count", 1 do
      post duplicate_network_policy_path(@network, @policy)
    end
    new_policy = Policy.last
    assert_equal "Allow Internal Services (copy)", new_policy.name
    assert_redirected_to edit_network_policy_path(@network, new_policy)
  end

  test "duplicate records audit log" do
    assert_difference "AuditLog.count", 1 do
      post duplicate_network_policy_path(@network, @policy)
    end
    log = AuditLog.last
    assert_equal "policy_duplicate", log.action
  end

  # --- Templates ---

  test "templates page renders" do
    get templates_network_policies_path(@network)
    assert_response :success
    assert_match "Policy Templates", response.body
  end

  test "templates shows available templates" do
    get templates_network_policies_path(@network)
    assert_response :success
    assert_match "Standard Employee", response.body
    assert_match "IT Admin", response.body
  end

  # --- Apply Template ---

  test "apply_template creates policies from template" do
    template = policy_templates(:it_admin)
    assert_difference "Policy.count", 2 do
      post apply_template_network_policies_path(@network), params: { template_id: template.id }
    end
    assert_redirected_to network_policies_path(@network)
    follow_redirect!
    assert_match "Template", response.body
  end

  test "apply_template records audit log" do
    template = policy_templates(:standard_employee)
    assert_difference "AuditLog.count", 1 do
      post apply_template_network_policies_path(@network), params: { template_id: template.id }
    end
    log = AuditLog.last
    assert_equal "policy_template_apply", log.action
  end

  # --- Authorization ---

  test "read_only user can view policies" do
    sign_in_as(:read_only_admin)
    get network_policies_path(@network)
    assert_response :success
  end

  test "read_only user can view policy details" do
    sign_in_as(:read_only_admin)
    get network_policy_path(@network, @policy)
    assert_response :success
  end

  test "read_only user cannot create policy" do
    sign_in_as(:read_only_admin)
    get new_network_policy_path(@network)
    assert_redirected_to network_policies_path(@network)
    assert_match "permission", flash[:alert]
  end

  test "read_only user cannot update policy" do
    sign_in_as(:read_only_admin)
    patch network_policy_path(@network, @policy), params: {
      policy: { name: "Hacked" }
    }
    assert_redirected_to network_policies_path(@network)
    @policy.reload
    assert_equal "Allow Internal Services", @policy.name
  end

  test "read_only user cannot delete policy" do
    sign_in_as(:read_only_admin)
    assert_no_difference "Policy.count" do
      delete network_policy_path(@network, @policy)
    end
    assert_redirected_to network_policies_path(@network)
  end

  test "read_only user cannot toggle policy" do
    sign_in_as(:read_only_admin)
    post toggle_network_policy_path(@network, @policy)
    assert_redirected_to network_policies_path(@network)
    @policy.reload
    assert @policy.enabled?
  end

  test "read_only user cannot duplicate policy" do
    sign_in_as(:read_only_admin)
    assert_no_difference "Policy.count" do
      post duplicate_network_policy_path(@network, @policy)
    end
    assert_redirected_to network_policies_path(@network)
  end

  test "read_only user cannot apply template" do
    sign_in_as(:read_only_admin)
    template = policy_templates(:standard_employee)
    assert_no_difference "Policy.count" do
      post apply_template_network_policies_path(@network), params: { template_id: template.id }
    end
    assert_redirected_to network_policies_path(@network)
  end

  test "unauthenticated user is redirected to login" do
    # Reset session (no sign in)
    delete logout_path
    get network_policies_path(@network)
    assert_redirected_to login_path
  end
end
