# frozen_string_literal: true

require "test_helper"

class PolicyTemplateTest < ActiveSupport::TestCase
  setup do
    @template = policy_templates(:standard_employee)
  end

  test "valid template" do
    assert @template.valid?
  end

  test "requires name" do
    @template.name = nil
    assert_not @template.valid?
  end

  test "requires category" do
    @template.category = nil
    assert_not @template.valid?
  end

  test "validates category inclusion" do
    @template.category = "unknown"
    assert_not @template.valid?
  end

  test "requires rules_json" do
    @template.rules_json = nil
    assert_not @template.valid?
  end

  test "validates rules_json is valid JSON" do
    @template.rules_json = "not json"
    assert_not @template.valid?
    assert @template.errors[:rules_json].any?
  end

  test "validates rules_json is an array" do
    @template.rules_json = '{"key": "value"}'
    assert_not @template.valid?
    assert @template.errors[:rules_json].any?
  end

  test "rules returns parsed JSON array" do
    rules = @template.rules
    assert_kind_of Array, rules
    assert rules.first.is_a?(Hash)
    assert_equal "Employee — Internal Services", rules.first["name"]
  end

  test "rules returns empty array for bad JSON" do
    @template.rules_json = "bad"
    assert_equal [], @template.rules
  end

  test "rules= sets JSON" do
    @template.rules = [{ "name" => "Test" }]
    assert_equal '[{"name":"Test"}]', @template.rules_json
  end

  test "category_emoji" do
    assert_equal "👤", @template.category_emoji
    assert_equal "🛡️", policy_templates(:it_admin).category_emoji
  end

  test "category_color" do
    assert_equal "blue", @template.category_color
    assert_equal "red", policy_templates(:it_admin).category_color
  end

  test "apply_to_network creates policies" do
    network = networks(:office)
    assert_difference "Policy.count", 1 do
      created = @template.apply_to_network!(network)
      assert_equal 1, created.count
      policy = created.first
      assert_equal "Employee — Internal Services", policy.name
      assert_equal "access", policy.policy_type
      assert_equal "role", policy.subject_type
      assert_equal "user", policy.subject_value
      assert_equal "*.internal", policy.resource_value
      assert_equal "allow", policy.action
    end
  end

  test "apply_to_network creates multiple policies" do
    network = networks(:office)
    template = policy_templates(:it_admin)
    assert_difference "Policy.count", 2 do
      created = template.apply_to_network!(network)
      assert_equal 2, created.count
    end
  end

  test "seed_built_in creates templates" do
    PolicyTemplate.where(built_in: true).destroy_all
    assert_difference "PolicyTemplate.count", 5 do
      PolicyTemplate.seed_built_in!
    end
    assert_equal 5, PolicyTemplate.built_in.count
  end

  test "seed_built_in is idempotent" do
    PolicyTemplate.seed_built_in!
    count = PolicyTemplate.count
    PolicyTemplate.seed_built_in!
    assert_equal count, PolicyTemplate.count
  end

  test "built_in scope" do
    assert policy_templates(:standard_employee).built_in?
  end
end
