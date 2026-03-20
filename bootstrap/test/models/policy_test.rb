# frozen_string_literal: true

require "test_helper"

class PolicyTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
    @policy = policies(:allow_internal)
  end

  # --- Validations ---

  test "valid policy" do
    assert @policy.valid?
  end

  test "requires name" do
    @policy.name = nil
    assert_not @policy.valid?
    assert_includes @policy.errors[:name], "can't be blank"
  end

  test "requires policy_type" do
    @policy.policy_type = nil
    assert_not @policy.valid?
  end

  test "validates policy_type inclusion" do
    @policy.policy_type = "invalid"
    assert_not @policy.valid?
    assert_includes @policy.errors[:policy_type], "is not included in the list"
  end

  test "validates priority inclusion" do
    @policy.priority = "extreme"
    assert_not @policy.valid?
  end

  test "requires subject_type" do
    @policy.subject_type = nil
    assert_not @policy.valid?
  end

  test "validates subject_type inclusion" do
    @policy.subject_type = "device"
    assert_not @policy.valid?
  end

  test "requires subject_value for non-everyone types" do
    @policy.subject_type = "user"
    @policy.subject_value = nil
    assert_not @policy.valid?
    assert_includes @policy.errors[:subject_value], "can't be blank"
  end

  test "does not require subject_value for everyone" do
    @policy.subject_type = "everyone"
    @policy.subject_value = nil
    assert @policy.valid?
  end

  test "requires resource_type" do
    @policy.resource_type = nil
    assert_not @policy.valid?
  end

  test "requires resource_value" do
    @policy.resource_value = nil
    assert_not @policy.valid?
  end

  test "validates action inclusion" do
    @policy.action = "maybe"
    assert_not @policy.valid?
  end

  test "validates CIDR notation for ip_range" do
    policy = @network.policies.new(
      name: "Bad CIDR",
      policy_type: "network_segment",
      subject_type: "everyone",
      resource_type: "ip_range",
      resource_value: "not-a-cidr",
      action: "allow"
    )
    assert_not policy.valid?
    assert policy.errors[:resource_value].any?
  end

  test "accepts valid CIDR notation" do
    policy = @network.policies.new(
      name: "Good CIDR",
      policy_type: "network_segment",
      subject_type: "everyone",
      resource_type: "ip_range",
      resource_value: "10.42.0.0/16",
      action: "allow"
    )
    assert policy.valid?
  end

  test "rejects invalid CIDR prefix" do
    policy = @network.policies.new(
      name: "Bad prefix",
      policy_type: "network_segment",
      subject_type: "everyone",
      resource_type: "ip_range",
      resource_value: "10.42.0.0/33",
      action: "allow"
    )
    assert_not policy.valid?
  end

  test "validates time_schedule format" do
    @policy.time_schedule = "every day 9-5"
    assert_not @policy.valid?
    assert @policy.errors[:time_schedule].any?
  end

  test "accepts valid time_schedule" do
    @policy.time_schedule = "MON-FRI 09:00-17:00"
    assert @policy.valid?
  end

  test "validates subject role value" do
    policy = @network.policies.new(
      name: "Bad Role",
      policy_type: "access",
      subject_type: "role",
      subject_value: "superuser",
      resource_type: "service",
      resource_value: "*",
      action: "allow"
    )
    assert_not policy.valid?
    assert policy.errors[:subject_value].any?
  end

  # --- Scopes ---

  test "enabled scope" do
    enabled = @network.policies.enabled
    assert enabled.all?(&:enabled?)
    assert_not enabled.include?(policies(:disabled_policy))
  end

  test "disabled scope" do
    disabled = @network.policies.disabled
    assert disabled.all? { |p| !p.enabled? }
    assert disabled.include?(policies(:disabled_policy))
  end

  test "allow_rules scope" do
    allow_rules = @network.policies.allow_rules
    assert allow_rules.all?(&:allow?)
  end

  test "deny_rules scope" do
    deny_rules = @network.policies.deny_rules
    assert deny_rules.all?(&:deny?)
    assert deny_rules.include?(policies(:deny_admin_zone))
  end

  test "by_type scope" do
    access = @network.policies.by_type("access")
    assert access.all? { |p| p.policy_type == "access" }
  end

  test "not_expired scope" do
    not_expired = @network.policies.not_expired
    assert_not not_expired.include?(policies(:expired_policy))
  end

  test "expired scope" do
    expired = @network.policies.expired
    assert expired.include?(policies(:expired_policy))
  end

  test "search scope by name" do
    results = @network.policies.search("Internal")
    assert results.include?(policies(:allow_internal))
  end

  test "search scope by resource" do
    results = @network.policies.search("contractor")
    assert results.include?(policies(:time_based_contractor))
  end

  # --- Instance methods ---

  test "priority_weight returns correct values" do
    assert_equal 100, policies(:deny_admin_zone).priority_weight
    assert_equal 50, policies(:allow_internal).priority_weight
    assert_equal 10, policies(:disabled_policy).priority_weight
  end

  test "allow? returns true for allow policies" do
    assert @policy.allow?
    assert_not @policy.deny?
  end

  test "deny? returns true for deny policies" do
    deny = policies(:deny_admin_zone)
    assert deny.deny?
    assert_not deny.allow?
  end

  test "expired? returns true for expired policies" do
    assert policies(:expired_policy).expired?
    assert_not @policy.expired?
  end

  test "active? returns true for enabled non-expired" do
    assert @policy.active?
    assert_not policies(:disabled_policy).active?
    assert_not policies(:expired_policy).active?
  end

  test "subject_display for everyone" do
    assert_equal "Everyone", @policy.subject_display
  end

  test "subject_display for role" do
    assert_equal "Role: user", policies(:deny_admin_zone).subject_display
  end

  test "subject_display for group" do
    assert_equal "Group: engineering", policies(:time_based_contractor).subject_display
  end

  test "resource_display for service" do
    assert_equal "Service: *.internal", @policy.resource_display
  end

  test "resource_display for ip_range" do
    assert_equal "IP Range: 10.42.0.0/16", policies(:network_segment_policy).resource_display
  end

  test "priority_emoji" do
    assert_equal "🔴", policies(:deny_admin_zone).priority_emoji
    assert_equal "🟡", @policy.priority_emoji
    assert_equal "🟢", policies(:disabled_policy).priority_emoji
  end

  # --- to_gateway_rule ---

  test "to_gateway_rule returns correct hash" do
    rule = @policy.to_gateway_rule
    assert_equal({ type: "everyone", value: nil }, rule[:subject])
    assert_equal({ type: "service", value: "*.internal" }, rule[:resource])
    assert_equal "allow", rule[:action]
    assert_nil rule[:schedule]
    assert_equal 50, rule[:priority]
  end

  test "to_gateway_rule includes schedule" do
    rule = policies(:time_based_contractor).to_gateway_rule
    assert_equal "MON-FRI 09:00-17:00", rule[:schedule]
  end

  # --- Conflict detection ---

  test "conflicting_policies detects conflicts" do
    # Create a conflicting policy (same subject/resource, different action)
    conflict = @network.policies.create!(
      name: "Deny Internal Services",
      policy_type: "access",
      subject_type: "everyone",
      resource_type: "service",
      resource_value: "*.internal",
      action: "deny"
    )

    assert @policy.has_conflicts?
    assert @policy.conflicting_policies.include?(conflict)
  end

  test "no conflicts for unique policies" do
    assert_not policies(:deny_admin_zone).has_conflicts?
  end

  # --- Duplicate ---

  test "duplicate creates copy with new name" do
    dup = @policy.duplicate!
    assert_equal "Allow Internal Services (copy)", dup.name
    assert_equal @policy.policy_type, dup.policy_type
    assert_equal @policy.action, dup.action
    assert_equal @policy.network_id, dup.network_id
    assert dup.persisted?
  end

  # --- Effective users ---

  test "effective_users for everyone" do
    users = @policy.effective_users
    assert users.include?(ztlp_users(:alice))
    assert users.include?(ztlp_users(:bob))
  end

  test "effective_users for role" do
    users = policies(:deny_admin_zone).effective_users
    assert users.include?(ztlp_users(:bob))
    assert_not users.include?(ztlp_users(:alice))  # alice is admin, not user
  end

  test "effective_users for group" do
    users = policies(:time_based_contractor).effective_users
    assert users.include?(ztlp_users(:alice))
    assert users.include?(ztlp_users(:bob))
  end

  test "effective_users for user" do
    policy = @network.policies.create!(
      name: "Bob Only",
      policy_type: "access",
      subject_type: "user",
      subject_value: "bob",
      resource_type: "service",
      resource_value: "test.internal",
      action: "allow"
    )
    users = policy.effective_users
    assert_equal 1, users.count
    assert users.include?(ztlp_users(:bob))
  end
end
