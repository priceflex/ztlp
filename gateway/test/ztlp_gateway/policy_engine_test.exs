defmodule ZtlpGateway.PolicyEngineTest do
  use ExUnit.Case

  alias ZtlpGateway.PolicyEngine

  # PolicyEngine is started by the application supervisor.
  # We use put_rule/delete_rule to set up test-specific rules.

  setup do
    # Clear any leftover rules from other tests
    for {svc, _} <- PolicyEngine.rules() do
      PolicyEngine.delete_rule(svc)
    end

    :ok
  end

  describe "authorize?/2" do
    test "allow :all permits any identity" do
      PolicyEngine.put_rule("web", :all)
      assert PolicyEngine.authorize?("node1.example.ztlp", "web")
      assert PolicyEngine.authorize?("random.other.ztlp", "web")
      assert PolicyEngine.authorize?("anything", "web")
    end

    test "exact match permits specific identity" do
      PolicyEngine.put_rule("ssh", ["admin.example.ztlp"])
      assert PolicyEngine.authorize?("admin.example.ztlp", "ssh")
      refute PolicyEngine.authorize?("user.example.ztlp", "ssh")
    end

    test "wildcard *.zone matches subnames" do
      PolicyEngine.put_rule("db", ["*.ops.ztlp"])
      assert PolicyEngine.authorize?("node1.ops.ztlp", "db")
      assert PolicyEngine.authorize?("deep.sub.ops.ztlp", "db")
      refute PolicyEngine.authorize?("ops.ztlp", "db")
      refute PolicyEngine.authorize?("node1.dev.ztlp", "db")
    end

    test "multiple allowed identities" do
      PolicyEngine.put_rule("api", ["admin.ztlp", "*.services.ztlp"])
      assert PolicyEngine.authorize?("admin.ztlp", "api")
      assert PolicyEngine.authorize?("web.services.ztlp", "api")
      refute PolicyEngine.authorize?("random.ztlp", "api")
    end

    test "unknown service denied (zero trust)" do
      refute PolicyEngine.authorize?("node1.ztlp", "unknown_service")
    end

    test "empty allow list denies everyone" do
      PolicyEngine.put_rule("locked", [])
      refute PolicyEngine.authorize?("admin.ztlp", "locked")
    end
  end

  describe "rule management" do
    test "put_rule and delete_rule" do
      PolicyEngine.put_rule("temp", :all)
      assert PolicyEngine.authorize?("anyone", "temp")

      PolicyEngine.delete_rule("temp")
      refute PolicyEngine.authorize?("anyone", "temp")
    end

    test "rules/0 lists current rules" do
      PolicyEngine.put_rule("svc1", :all)
      PolicyEngine.put_rule("svc2", ["node.ztlp"])

      rules = PolicyEngine.rules()
      assert {"svc1", :all} in rules
      assert {"svc2", ["node.ztlp"]} in rules
    end

    test "overwrite existing rule" do
      PolicyEngine.put_rule("web", :all)
      assert PolicyEngine.authorize?("anyone", "web")

      PolicyEngine.put_rule("web", ["admin.ztlp"])
      refute PolicyEngine.authorize?("anyone", "web")
      assert PolicyEngine.authorize?("admin.ztlp", "web")
    end
  end
end
