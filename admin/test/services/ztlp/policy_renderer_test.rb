# frozen_string_literal: true

# Slice 9a: Ztlp::PolicyRenderer goldens. The renderer is the panel's view of
# the gateway allow-list: one rendered document per gateway, with exactly the
# rules the gateway sees. Golden tests pin the wire-facing text so a change to
# the rule syntax (spec: group:<ns> | role:<v> | <ns> | *) is a test failure.
#
# NS name namespaces (Slice 3 models): users -> <username>.users.<zone>,
# groups -> <name>.groups.<zone>, devices -> <name>.<zone>.
require "test_helper"

class PolicyRendererTest < ActiveSupport::TestCase
  setup do
    @zone = Zone.primary
    @gw = @zone.gateways.create!(name: "web", kind: "rust_listen")
    @app1 = @gw.applications.create!(name: "comms", enabled: true, min_assurance: 3,
                                    backend: "10.0.0.5:8080", protocol: "http")
    @app2 = @gw.applications.create!(name: "vault", enabled: false)
    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "tech", status: "active")
    @eng = @zone.groups.create!(name: "eng")
    @dev = @zone.devices.create!(name: "alice-mac")
  end

  test "render returns nil for a gateway with no applications" do
    empty = @zone.gateways.create!(name: "quiet", kind: "rust_listen")
    assert_nil Ztlp::PolicyRenderer.render(empty)
  end

  test "rust_listen renders TOML with default deny and one services block per enabled application" do
    out = Ztlp::PolicyRenderer.render(@gw)
    assert_includes out, 'default = "deny"'
    assert_includes out, "ztlp = \"comms.test.ztlp\""
    assert_includes out, '"http://10.0.0.5:8080"'
    # the disabled application is NOT in the allow-list
    refute_includes out, "vault"
  end

  test "rust_listen renders every rule in the application's order" do
    @app1.policy_rules.create!(subject_type: "any")
    @app1.policy_rules.create!(subject_type: "group", subject_id: @eng.id, position: 1)
    @app1.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 2)
    out = Ztlp::PolicyRenderer.render(@gw)
    idx_any = out.index("allow = [")
    assert idx_any, "no allow list rendered"
    allow_block = out[idx_any..]
    assert_includes allow_block, "\"*\""
    assert_includes allow_block, "\"group:eng.groups.#{@zone.name}\""
    assert_includes allow_block, "\"role:tech\""
  end

  test "a rule whose group was deleted still renders its pinned subject_value (stale but honest)" do
    ghost = @zone.groups.create!(name: "ghost")
    @app1.policy_rules.create!(subject_type: "group", subject_id: ghost.id)
    ghost.destroy! # subject_entity is gone; the rule's subject_value was pinned at create
    out = Ztlp::PolicyRenderer.render(@gw)
    assert_includes out, "\"group:ghost.groups.#{@zone.name}\""
  end

  test "elixir kind renders YAML with the same rule set" do
    @gw.update!(kind: "elixir")
    @app1.policy_rules.create!(subject_type: "user", subject_id: @alice.id)
    @app1.policy_rules.create!(subject_type: "device", subject_id: @dev.id, position: 1)
    out = Ztlp::PolicyRenderer.render(@gw)
    assert_includes out, "default: deny"
    assert_includes out, "ztlp: comms.#{@zone.name}"
    assert_includes out, "- alice.users.#{@zone.name}"
    assert_includes out, "- alice-mac.#{@zone.name}"
  end
end
