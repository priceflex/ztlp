defmodule ZtlpGateway.GroupPolicyTest do
  @moduledoc """
  Tests for group-based and role-based policy evaluation in the ZTLP Gateway.

  Phase 2 of the ZTLP Identity & Groups feature — tests cover:
  - Group membership matching via `group:` prefix
  - Role matching via `role:` prefix
  - Combined group/role/wildcard/exact match policies
  - Custom group and role resolvers
  - Default deny behavior
  - Policy rule lifecycle with group patterns
  - Edge cases (unknown groups, empty groups, nil resolvers)
  """

  use ExUnit.Case

  alias ZtlpGateway.PolicyEngine

  setup do
    # Clear any leftover rules from other tests
    for {svc, _} <- PolicyEngine.rules() do
      PolicyEngine.delete_rule(svc)
    end

    :ok
  end

  # ── Helpers ────────────────────────────────────────────────────────

  # Stub group resolver: returns true if user is in the mock membership map
  defp mock_group_resolver(membership_map) do
    fn group_name, identity ->
      members = Map.get(membership_map, group_name, [])
      identity in members
    end
  end

  # Stub role resolver: returns role from a mock user → role map
  defp mock_role_resolver(role_map) do
    fn identity ->
      Map.get(role_map, identity)
    end
  end

  # ── Group Membership Matching ──────────────────────────────────────

  describe "group: pattern matching" do
    test "grants access when identity is a group member" do
      PolicyEngine.put_rule("admin-panel", ["group:admins@techrockstars.ztlp"])

      resolver = mock_group_resolver(%{
        "admins@techrockstars.ztlp" => ["steve@techrockstars.ztlp", "alice@techrockstars.ztlp"]
      })

      assert PolicyEngine.authorize?(
        "steve@techrockstars.ztlp", "admin-panel",
        group_resolver: resolver
      )

      assert PolicyEngine.authorize?(
        "alice@techrockstars.ztlp", "admin-panel",
        group_resolver: resolver
      )
    end

    test "denies access when identity is NOT a group member" do
      PolicyEngine.put_rule("admin-panel", ["group:admins@techrockstars.ztlp"])

      resolver = mock_group_resolver(%{
        "admins@techrockstars.ztlp" => ["steve@techrockstars.ztlp"]
      })

      refute PolicyEngine.authorize?(
        "bob@techrockstars.ztlp", "admin-panel",
        group_resolver: resolver
      )
    end

    test "denies access when group doesn't exist" do
      PolicyEngine.put_rule("secret", ["group:nonexistent@zone.ztlp"])

      resolver = mock_group_resolver(%{})

      refute PolicyEngine.authorize?(
        "steve@zone.ztlp", "secret",
        group_resolver: resolver
      )
    end

    test "denies access when group is empty" do
      PolicyEngine.put_rule("locked", ["group:empty@zone.ztlp"])

      resolver = mock_group_resolver(%{"empty@zone.ztlp" => []})

      refute PolicyEngine.authorize?(
        "anyone@zone.ztlp", "locked",
        group_resolver: resolver
      )
    end

    test "multiple group patterns — member of any grants access" do
      PolicyEngine.put_rule("services", [
        "group:admins@zone.ztlp",
        "group:techs@zone.ztlp"
      ])

      resolver = mock_group_resolver(%{
        "admins@zone.ztlp" => ["alice@zone.ztlp"],
        "techs@zone.ztlp" => ["bob@zone.ztlp"]
      })

      assert PolicyEngine.authorize?("alice@zone.ztlp", "services", group_resolver: resolver)
      assert PolicyEngine.authorize?("bob@zone.ztlp", "services", group_resolver: resolver)
      refute PolicyEngine.authorize?("carol@zone.ztlp", "services", group_resolver: resolver)
    end

    test "group pattern combined with exact match" do
      PolicyEngine.put_rule("mixed", [
        "group:admins@zone.ztlp",
        "special.zone.ztlp"
      ])

      resolver = mock_group_resolver(%{
        "admins@zone.ztlp" => ["alice@zone.ztlp"]
      })

      assert PolicyEngine.authorize?("alice@zone.ztlp", "mixed", group_resolver: resolver)
      assert PolicyEngine.authorize?("special.zone.ztlp", "mixed", group_resolver: resolver)
      refute PolicyEngine.authorize?("random@zone.ztlp", "mixed", group_resolver: resolver)
    end

    test "group pattern combined with wildcard" do
      PolicyEngine.put_rule("combo", [
        "group:admins@zone.ztlp",
        "*.ops.ztlp"
      ])

      resolver = mock_group_resolver(%{
        "admins@zone.ztlp" => ["alice@zone.ztlp"]
      })

      # Group member
      assert PolicyEngine.authorize?("alice@zone.ztlp", "combo", group_resolver: resolver)
      # Wildcard match
      assert PolicyEngine.authorize?("node1.ops.ztlp", "combo", group_resolver: resolver)
      # Neither
      refute PolicyEngine.authorize?("bob@zone.ztlp", "combo", group_resolver: resolver)
    end
  end

  # ── Role Matching ──────────────────────────────────────────────────

  describe "role: pattern matching" do
    test "grants access when identity has the specified role" do
      PolicyEngine.put_rule("admin-tools", ["role:admin"])

      resolver = mock_role_resolver(%{
        "steve@zone.ztlp" => "admin",
        "alice@zone.ztlp" => "tech"
      })

      assert PolicyEngine.authorize?("steve@zone.ztlp", "admin-tools", role_resolver: resolver)
      refute PolicyEngine.authorize?("alice@zone.ztlp", "admin-tools", role_resolver: resolver)
    end

    test "denies access when user role doesn't match" do
      PolicyEngine.put_rule("admin-only", ["role:admin"])

      resolver = mock_role_resolver(%{
        "bob@zone.ztlp" => "user"
      })

      refute PolicyEngine.authorize?("bob@zone.ztlp", "admin-only", role_resolver: resolver)
    end

    test "denies access when user has no role" do
      PolicyEngine.put_rule("restricted", ["role:admin"])

      resolver = mock_role_resolver(%{})

      refute PolicyEngine.authorize?("nobody@zone.ztlp", "restricted", role_resolver: resolver)
    end

    test "multiple role patterns" do
      PolicyEngine.put_rule("tech-tools", ["role:admin", "role:tech"])

      resolver = mock_role_resolver(%{
        "steve@zone.ztlp" => "admin",
        "alice@zone.ztlp" => "tech",
        "bob@zone.ztlp" => "user"
      })

      assert PolicyEngine.authorize?("steve@zone.ztlp", "tech-tools", role_resolver: resolver)
      assert PolicyEngine.authorize?("alice@zone.ztlp", "tech-tools", role_resolver: resolver)
      refute PolicyEngine.authorize?("bob@zone.ztlp", "tech-tools", role_resolver: resolver)
    end

    test "role combined with group" do
      PolicyEngine.put_rule("all-access", [
        "role:admin",
        "group:techs@zone.ztlp"
      ])

      group_resolver = mock_group_resolver(%{
        "techs@zone.ztlp" => ["bob@zone.ztlp"]
      })

      role_resolver = mock_role_resolver(%{
        "steve@zone.ztlp" => "admin",
        "bob@zone.ztlp" => "tech"
      })

      opts = [group_resolver: group_resolver, role_resolver: role_resolver]

      # Admin by role
      assert PolicyEngine.authorize?("steve@zone.ztlp", "all-access", opts)
      # Tech by group membership
      assert PolicyEngine.authorize?("bob@zone.ztlp", "all-access", opts)
      # Neither
      refute PolicyEngine.authorize?("carol@zone.ztlp", "all-access", opts)
    end
  end

  # ── Backward Compatibility ─────────────────────────────────────────

  describe "backward compatibility with existing patterns" do
    test "allow :all still works" do
      PolicyEngine.put_rule("public", :all)
      assert PolicyEngine.authorize?("anyone@zone.ztlp", "public")
    end

    test "exact match still works without options" do
      PolicyEngine.put_rule("ssh", ["admin.zone.ztlp"])
      assert PolicyEngine.authorize?("admin.zone.ztlp", "ssh")
      refute PolicyEngine.authorize?("user.zone.ztlp", "ssh")
    end

    test "wildcard still works without options" do
      PolicyEngine.put_rule("db", ["*.ops.ztlp"])
      assert PolicyEngine.authorize?("node1.ops.ztlp", "db")
      refute PolicyEngine.authorize?("node1.dev.ztlp", "db")
    end

    test "unknown service is still denied" do
      refute PolicyEngine.authorize?("node1.ztlp", "unknown_service")
    end

    test "empty allow list still denies everyone" do
      PolicyEngine.put_rule("locked", [])
      refute PolicyEngine.authorize?("admin.ztlp", "locked")
    end

    test "authorize?/2 (2-arg) still works as before" do
      PolicyEngine.put_rule("web", :all)
      assert PolicyEngine.authorize?("anyone", "web")
    end
  end

  # ── Rule Management with Group Patterns ────────────────────────────

  describe "rule management with group/role patterns" do
    test "put_rule with group pattern" do
      PolicyEngine.put_rule("svc", ["group:admins@zone.ztlp"])
      rules = PolicyEngine.rules()
      assert {"svc", ["group:admins@zone.ztlp"]} in rules
    end

    test "put_rule with role pattern" do
      PolicyEngine.put_rule("svc", ["role:admin"])
      rules = PolicyEngine.rules()
      assert {"svc", ["role:admin"]} in rules
    end

    test "put_rule with mixed patterns" do
      patterns = ["group:admins@zone.ztlp", "role:tech", "*.ops.ztlp", "special.ztlp"]
      PolicyEngine.put_rule("complex", patterns)
      rules = PolicyEngine.rules()
      assert {"complex", patterns} in rules
    end

    test "overwrite rule with group pattern" do
      PolicyEngine.put_rule("svc", ["node.ztlp"])
      PolicyEngine.put_rule("svc", ["group:admins@zone.ztlp"])
      rules = PolicyEngine.rules()
      assert {"svc", ["group:admins@zone.ztlp"]} in rules
    end

    test "delete rule with group pattern" do
      PolicyEngine.put_rule("svc", ["group:admins@zone.ztlp"])
      PolicyEngine.delete_rule("svc")

      resolver = mock_group_resolver(%{
        "admins@zone.ztlp" => ["steve@zone.ztlp"]
      })

      refute PolicyEngine.authorize?("steve@zone.ztlp", "svc", group_resolver: resolver)
    end
  end

  # ── Complex Multi-Pattern Policies (YAML-like config) ──────────────

  describe "YAML-like policy configuration" do
    test "admin access to all services via group" do
      # Simulates:
      # policies:
      #   - match: group: "admins@techrockstars.ztlp"
      #     action: allow
      #     services: ["*"]
      PolicyEngine.put_rule("*", ["group:admins@techrockstars.ztlp"])

      resolver = mock_group_resolver(%{
        "admins@techrockstars.ztlp" => ["steve@techrockstars.ztlp"]
      })

      assert PolicyEngine.authorize?(
        "steve@techrockstars.ztlp", "*",
        group_resolver: resolver
      )
    end

    test "techs can access client networks via group + wildcard" do
      # Simulates:
      # policies:
      #   - match: group: "techs@techrockstars.ztlp"
      #     services: ["*.clients.techrockstars.ztlp"]
      PolicyEngine.put_rule("vpn.clients.techrockstars.ztlp", [
        "group:techs@techrockstars.ztlp"
      ])

      resolver = mock_group_resolver(%{
        "techs@techrockstars.ztlp" => ["alice@techrockstars.ztlp"]
      })

      assert PolicyEngine.authorize?(
        "alice@techrockstars.ztlp", "vpn.clients.techrockstars.ztlp",
        group_resolver: resolver
      )

      refute PolicyEngine.authorize?(
        "random@techrockstars.ztlp", "vpn.clients.techrockstars.ztlp",
        group_resolver: resolver
      )
    end

    test "default deny for non-matching identities" do
      PolicyEngine.put_rule("secure", ["group:admins@zone.ztlp", "role:admin"])

      group_resolver = mock_group_resolver(%{"admins@zone.ztlp" => []})
      role_resolver = mock_role_resolver(%{})

      opts = [group_resolver: group_resolver, role_resolver: role_resolver]

      refute PolicyEngine.authorize?("stranger@zone.ztlp", "secure", opts)
    end
  end

  # ── Edge Cases ─────────────────────────────────────────────────────

  describe "edge cases" do
    test "group: with empty group name" do
      PolicyEngine.put_rule("svc", ["group:"])

      resolver = mock_group_resolver(%{"" => ["steve@zone.ztlp"]})
      assert PolicyEngine.authorize?("steve@zone.ztlp", "svc", group_resolver: resolver)
    end

    test "role: with empty role" do
      PolicyEngine.put_rule("svc", ["role:"])

      resolver = mock_role_resolver(%{"steve@zone.ztlp" => ""})
      assert PolicyEngine.authorize?("steve@zone.ztlp", "svc", role_resolver: resolver)
    end

    test "identity that looks like a group pattern — exact match wins" do
      PolicyEngine.put_rule("svc", ["group:admins@zone.ztlp"])

      # If someone's identity literally equals the pattern string, the exact
      # match fires first. This is fine — it's a degenerate case.
      resolver = mock_group_resolver(%{})
      assert PolicyEngine.authorize?("group:admins@zone.ztlp", "svc", group_resolver: resolver)
    end

    test "resolver that raises is handled gracefully for group" do
      PolicyEngine.put_rule("svc", ["group:admins@zone.ztlp"])

      # Use a resolver that raises
      bad_resolver = fn _group, _identity -> raise "boom" end

      # Should not crash, should return false
      refute PolicyEngine.authorize?("steve@zone.ztlp", "svc", group_resolver: bad_resolver)
    end

    test "resolver that raises is handled gracefully for role" do
      PolicyEngine.put_rule("svc", ["role:admin"])

      bad_resolver = fn _identity -> raise "boom" end

      refute PolicyEngine.authorize?("steve@zone.ztlp", "svc", role_resolver: bad_resolver)
    end
  end

  # ── Integration: multiple services with different patterns ─────────

  describe "multi-service policy" do
    test "different services with different group/role/wildcard policies" do
      PolicyEngine.put_rule("admin-panel", ["group:admins@zone.ztlp"])
      PolicyEngine.put_rule("tech-tools", ["role:tech", "role:admin"])
      PolicyEngine.put_rule("public-api", :all)
      PolicyEngine.put_rule("ssh", ["*.ops.ztlp"])

      group_resolver = mock_group_resolver(%{
        "admins@zone.ztlp" => ["steve@zone.ztlp"]
      })

      role_resolver = mock_role_resolver(%{
        "steve@zone.ztlp" => "admin",
        "alice@zone.ztlp" => "tech",
        "bob@zone.ztlp" => "user"
      })

      opts = [group_resolver: group_resolver, role_resolver: role_resolver]

      # steve is admin and in admins group
      assert PolicyEngine.authorize?("steve@zone.ztlp", "admin-panel", opts)
      assert PolicyEngine.authorize?("steve@zone.ztlp", "tech-tools", opts)
      assert PolicyEngine.authorize?("steve@zone.ztlp", "public-api", opts)
      refute PolicyEngine.authorize?("steve@zone.ztlp", "ssh", opts)

      # alice is tech
      refute PolicyEngine.authorize?("alice@zone.ztlp", "admin-panel", opts)
      assert PolicyEngine.authorize?("alice@zone.ztlp", "tech-tools", opts)
      assert PolicyEngine.authorize?("alice@zone.ztlp", "public-api", opts)

      # bob is just a user
      refute PolicyEngine.authorize?("bob@zone.ztlp", "admin-panel", opts)
      refute PolicyEngine.authorize?("bob@zone.ztlp", "tech-tools", opts)
      assert PolicyEngine.authorize?("bob@zone.ztlp", "public-api", opts)

      # ops node matches wildcard
      assert PolicyEngine.authorize?("node1.ops.ztlp", "ssh", opts)
    end
  end
end
