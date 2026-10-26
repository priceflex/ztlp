# frozen_string_literal: true

# Slice 9a remainder (apps_for_group seam, TDD): the groups directory needs to
# know which services reference a group via a `group:` policy rule, so a
# group is never deleted out from under a live rule.
#
# `Ztlp::PolicyRenderer.apps_for_group(gateway, group)` returns the gateway's
# services that carry a `group:` rule with subject_value == group.ns_name:
#   * only `group:` rules count (user/device/role/any rules never reference a
#     group);
#   * the match is on the Pinned subject_value (the ns_name string the rule
#     rendered at create time), not the DB id — so it also finds rules whose
#     group row would have been deleted (the renderer is stale-but-honest);
#   * a service still counts while DISABLED — its rule is stored and
#     re-appears if the app is re-enabled;
#   * rules on another gateway's services never leak across;
#   * a service with only a role rule (or no rules) is excluded.
require "test_helper"

class PolicyRendererAppsForGroupTest < ActiveSupport::TestCase
  setup do
    @zone = Zone.primary
    @gw_rust = @zone.gateways.create!(name: "gw1", kind: "rust_listen")
    @gw_elixir = @zone.gateways.create!(name: "gw2", kind: "elixir")

    @eng = @zone.groups.create!(name: "eng")
    @hr = @zone.groups.create!(name: "hr")

    @api = @gw_rust.services.create!(name: "api", backend: "127.0.0.1:8080")
    @dash = @gw_rust.services.create!(name: "dash")
    @ext = @gw_rust.services.create!(name: "ext", enabled: false)
    @other_gw_app = @gw_elixir.services.create!(name: "api")

    PolicyRule.create!(service: @api, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    PolicyRule.create!(service: @dash, subject_type: "group", subject_id: @hr.id,
                       subject_value: @hr.ns_name, position: 1)
    PolicyRule.create!(service: @ext, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    PolicyRule.create!(service: @other_gw_app, subject_type: "group", subject_id: @eng.id,
                       subject_value: @eng.ns_name, position: 1)
    PolicyRule.create!(service: @dash, subject_type: "role", subject_value: "tech", position: 2)
  end

  test "apps_for_group finds the enabled services with a group rule for the group" do
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_rust, @eng)
    assert_equal [ @api, @ext ], apps
  end

  test "apps_for_group counts a disabled service (its rule is stored)" do
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_rust, @eng)
    assert_includes apps.map(&:name), "ext"
  end

  test "apps_for_group excludes services whose rules reference a different group" do
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_rust, @hr)
    assert_equal [ "dash" ], apps.map(&:name)
  end

  test "apps_for_group excludes services with only non-group rules" do
    @dash.policy_rules.where(subject_type: "group").delete_all
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_rust, @hr)
    assert_empty apps
  end

  test "apps_for_group never leaks another gateway's services" do
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_elixir, @eng)
    assert_equal [ "api" ], apps.map(&:name)
    assert_same_gateway = apps.all? { |a| a.gateway_id == @gw_elixir.id }
    assert assert_same_gateway, "expected only gw2 services"
  end

  test "apps_for_group matches on the pinned ns_name, not the DB id" do
    # A rule whose group row is gone keeps its subject_value and is still found.
    rule = PolicyRule.create!(service: @api, subject_type: "group", subject_id: nil,
                              subject_value: "gone.groups.test.ztlp", position: 3)
    apps = Ztlp::PolicyRenderer.apps_for_group(@gw_rust, Group.new(ns_name: "gone.groups.test.ztlp"))
    assert_includes apps, @api
    rule.destroy
  end

  test "apps_for_group is empty when no rule references the group" do
    nobody = @zone.groups.create!(name: "nobody")
    assert_empty Ztlp::PolicyRenderer.apps_for_group(@gw_rust, nobody)
  end
end
