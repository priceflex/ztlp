# frozen_string_literal: true

# Slice 9b: Ztlp::AccessEvaluator must MIRROR THE GATEWAY, not the spec prose
# (STATUS 2026-10-23 01:55Z review rule). Ground truth:
#
# proto/src/policy.rs (read-only, priceflex/ztlp HEAD):
#   - matches_pattern: "*" matches everything; "*.suffix" matches identities
#     ending in ".suffix" (or == suffix); otherwise EXACT match. The client
#     identity on a Rust gateway is the DEVICE ns name.
#   - matches_pattern_async: only "group:" and "role:" resolve device->owner
#     (group: membership of the owner, or the identity directly; role: the
#     owner's USER record role). Plain user/device literals match EXACTLY
#     against the identity string — a user literal therefore NEVER matches a
#     device identity on rust_listen gateways.
#   - The Rust gateway does not evaluate assurance: the app's min_assurance
#     is enforced by the PANEL (the mandatory gate) only, so the evaluator
#     reports it as enforced: false on rust_listen gateways (still shown).
#   - Default deny when no pattern matches (policy.rs authorize: absent
#     service / no matching pattern -> false).
require "test_helper"

class AccessEvaluatorTest < ActiveSupport::TestCase
  def setup
    @zone = Zone.primary
    @gw_rust = @zone.gateways.create!(name: "edge", kind: "rust_listen")
    @gw_elixir = @zone.gateways.create!(name: "web", kind: "elixir")
    @app = @gw_rust.applications.create!(name: "panel", min_assurance: 3, backend: "10.0.0.5:8443")
    @app_off = @gw_elixir.applications.create!(name: "panel", min_assurance: 3, backend: "10.0.0.5:8443", enabled: false)

    @owner = @zone.users.create!(username: "alice", role: "tech", status: "active")
    @bob = @zone.users.create!(username: "bob", role: "user", status: "active")
    @disabled_owner = @zone.users.create!(username: "carol", role: "user", status: "disabled")
    @dev = @zone.devices.create!(name: "alice-laptop", user: @owner, key_source: "tpm",
                                 assurance: 3, status: "enrolled")
    @low = @zone.devices.create!(name: "bob-laptop", user: @bob, key_source: "file",
                                 assurance: 2, status: "enrolled")
    @pending = @zone.devices.create!(name: "new-box", user: @owner, key_source: "file",
                                     assurance: 1, status: "pending")
    @revoked = @zone.devices.create!(name: "old-box", user: @owner, key_source: "tpm",
                                     assurance: 3, status: "revoked")
    @ungrouped = @zone.users.create!(username: "dave", role: "user", status: "active")
    @dave_dev = @zone.devices.create!(name: "dave-box", user: @ungrouped, key_source: "tpm",
                                      assurance: 3, status: "enrolled")
    @techs = @zone.groups.create!(name: "techs")
    @techs.group_memberships.create!(user: @owner)
  end

  def ev(device, app, ns_client: nil)
    Ztlp::AccessEvaluator.evaluate(device, app, ns_client: ns_client)
  end

  test "any rule allows an enrolled device whose owner is a member of the rule's group" do
    @app.policy_rules.create!(subject_type: "any")
    out = ev(@dev, @app)
    assert_equal "allow", out[:decision]
    assert_equal 1, out[:trace].size
    assert_equal "any", out[:trace][0][:rule]
  end

  test "no rules at all: default deny" do
    out = ev(@dev, @app)
    assert_equal "deny", out[:decision]
    assert_match(/default deny/i, out[:reason])
    assert_empty out[:trace]
  end

  test "revoked device: deny before any rule is walked" do
    @app.policy_rules.create!(subject_type: "any")
    out = ev(@revoked, @app)
    assert_equal "deny", out[:decision]
    assert_match(/revoked/i, out[:reason])
  end

  test "pending device: deny before any rule is walked" do
    @app.policy_rules.create!(subject_type: "any")
    out = ev(@pending, @app)
    assert_equal "deny", out[:decision]
    assert_match(/pending/i, out[:reason])
  end

  test "disabled owner: deny before any rule is walked" do
    @app.policy_rules.create!(subject_type: "any")
    carol_dev = @zone.devices.create!(name: "carol-box", user: @disabled_owner, key_source: "tpm",
                                      assurance: 3, status: "enrolled")
    out = ev(carol_dev, @app)
    assert_equal "deny", out[:decision]
    assert_match(/disabled/i, out[:reason])
  end

  # The gateway has no owner pre-check: "*" and exact device literals match an ownerless
  # device; only group:/role: consult the owner (policy.rs matches_pattern_async).
  test "unassigned device: '*' still allows it, group/role cannot match it" do
    anon = @zone.devices.create!(name: "orphan", key_source: "file", assurance: 3, status: "enrolled")
    @app.policy_rules.create!(subject_type: "group", subject_id: @techs.id, position: 0)
    out = ev(anon, @app)
    assert_equal "deny", out[:decision]
    assert_match(/no owner/i, out[:trace].last[:why])
    @app.policy_rules.create!(subject_type: "any", position: 1)
    assert_equal "allow", ev(anon, @app)[:decision]
  end

  test "application disabled: deny" do
    out = ev(@dev, @app_off)
    assert_equal "deny", out[:decision]
    assert_match(/disabled/i, out[:reason])
  end

  test "device rule: exact ns_name match only" do
    @app.policy_rules.create!(subject_type: "device", subject_id: @dev.id)
    assert_equal "allow", ev(@dev, @app)[:decision]

    out = ev(@dave_dev, @app)
    assert_equal "deny", out[:decision]
    assert_equal "deny", out[:trace].last[:result]
  end

  test "user rule: user literal never matches a device identity on rust_listen (gateway semantics)" do
    @app.policy_rules.create!(subject_type: "user", subject_id: @owner.id)
    out = ev(@dev, @app)
    assert_equal "deny", out[:decision]
    assert_match(/user rules don/i, out[:reason])
    assert_equal "deny", out[:trace].last[:result]
  end

  test "role rule matches the owner's role" do
    @app.policy_rules.create!(subject_type: "role", subject_value: "tech")
    out = ev(@dev, @app)
    assert_equal "allow", out[:decision]
    assert_equal "allow", out[:trace].last[:result]

    out2 = ev(@dave_dev, @app)
    assert_equal "deny", out2[:decision]
  end

  test "group rule matches a member owner, not a non-member owner" do
    @app.policy_rules.create!(subject_type: "group", subject_id: @techs.id)
    assert_equal "allow", ev(@dev, @app)[:decision]

    out = ev(@dave_dev, @app)
    assert_equal "deny", out[:decision]
    assert_equal "deny", out[:trace].last[:result]
  end

  test "group rule with a deleted group row: deny with a named reason (stale rule)" do
    @rule = @app.policy_rules.create!(subject_type: "group", subject_id: @techs.id)
    @techs.destroy!
    out = ev(@dev, @app)
    assert_equal "deny", out[:decision]
    assert_match(/no longer exists/i, out[:reason])
  end

  # Elixir gateway (gateway/lib/ztlp_gateway/policy_engine.ex): identity = the device name the
  # client key resolves to; group: asks is_group_member?(group, identity) and role: asks
  # user_role(identity) -- NO device->owner step. GROUP members are user names, so neither can
  # match a device there. Only "*" (:all) and exact device names work.
  test "elixir: group and role rules never match a device (no owner resolution)" do
    @app_off.update!(enabled: true)
    @app_off.policy_rules.create!(subject_type: "group", subject_id: @techs.id, position: 0)
    @app_off.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 1)
    out = ev(@dev, @app_off)
    assert_equal "deny", out[:decision]
    assert out[:trace].all? { |t| t[:result] == "deny" && t[:why].match?(/elixir/i) }, out[:trace].inspect
  end

  test "elixir: '*' and exact device rules allow" do
    @app_off.update!(enabled: true)
    @app_off.policy_rules.create!(subject_type: "device", subject_id: @dev.id)
    assert_equal "allow", ev(@dev, @app_off)[:decision]
    assert_equal "deny", ev(@dave_dev, @app_off)[:decision]
  end

  # G6: no per-service min_assurance on the Rust gateway; on Elixir it is per-route config the panel
  # does not render. So the decision is the GATEWAY's and the floor is a warning, never a deny.
  test "min_assurance below the floor: gateway decision stands, flagged as not enforced" do
    @app.policy_rules.create!(subject_type: "any")
    out = ev(@low, @app) # assurance 2 < min 3
    assert_equal "allow", out[:decision], "the Rust gateway would let it in; the panel must say so"
    assert_equal false, out[:assurance_enforced]
    assert_match(/not enforced/i, out[:warnings].join(" "))
    assert_match(/below.*minimum/i, out[:warnings].join(" "))
  end

  test "min_assurance met: no warning" do
    @app.policy_rules.create!(subject_type: "any")
    out = ev(@dev, @app)
    assert_equal "allow", out[:decision]
    assert_empty out[:warnings]
  end

  test "wildcard suffix rules mirror matches_pattern exactly" do
    @app.policy_rules.create!(subject_type: "any") # ensure one rule exists
    # Simulate the literal surface directly: the evaluator exposes the
    # pattern matcher for the UI's honest notes.
    assert Ztlp::AccessEvaluator.literal_matches?("*.ztlp", "alice-laptop.trs.ztlp")
    assert Ztlp::AccessEvaluator.literal_matches?("alice-laptop.trs.ztlp", "alice-laptop.trs.ztlp")
    refute Ztlp::AccessEvaluator.literal_matches?("alice-laptop.trs.ztlp", "bob-laptop.trs.ztlp")
    assert Ztlp::AccessEvaluator.literal_matches?("*", "anything")
  end

  test "trace records every rule in order with rule/result/why" do
    @app.policy_rules.create!(subject_type: "group", subject_id: @techs.id, position: 0)
    @app.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 1)
    out = ev(@dave_dev, @app)
    assert_equal "deny", out[:decision]
    assert_equal 2, out[:trace].size
    assert_equal %w[group role], out[:trace].map { |t| t[:rule] }
    assert out[:trace].all? { |t| t[:result] == "deny" }
    out2 = ev(@dev, @app)
    assert_equal "allow", out2[:decision]
  end

  # The NS-resolved group path: members come from the NS GROUP record via
  # the admin API (NcClient.list), exactly like the gateway resolver.
  test "group rule resolves membership from the NS group record when a seam client is injected" do
    fake = Class.new do
      def self.list(_port, _secret, type: nil, zone: nil)
        [ { name: "techs.groups.test.ztlp", type: "group", data: { "members" => [ "alice.users.test.ztlp" ] } } ]
      end
    end
    rule = @app.policy_rules.create!(subject_type: "group", subject_id: @techs.id)
    assert_equal "techs.groups.test.ztlp", rule.reload.subject_value
    out = ev(@dev, @app, ns_client: fake)
    assert_equal "allow", out[:decision]

    # dave is not a member in the NS record: deny
    out2 = ev(@dave_dev, @app, ns_client: fake)
    assert_equal "deny", out2[:decision]
  end
end
