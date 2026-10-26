# frozen_string_literal: true

require_relative "../test_helper"

# Slice 11a: Overview (root) with tally + Setup checklist + infra panel, and
# POST /setup/acknowledge_breakglass (super_admin only).
#
# TDD: these tests are written against the spec (docs/admin-panel/BUILD_LOOP.md
# Slice 11) before any controller/route exists — RED expected.
class OverviewSetupTest < ActionDispatch::IntegrationTest
  def setup
    @zone = Zone.primary
    @steve, @steve_seed = make_admin(role: "super_admin", username: "steve")
    @readonly, @readonly_seed = make_admin(role: "read_only", username: "readonly11")
  end

  def sign_in(admin, seed) = sign_in_as(admin, seed)


  # --- Overview: tally strip --------------------------------------------

  test "overview shows a tally of users, devices, groups and services" do
    @zone.users.create!(username: "alice", display_name: "Alice", kind: "person", role: "user", status: "active")
    @zone.devices.create!(name: "alice-mbp", ns_name: "alice-mbp.test.ztlp", node_id_hex: "aa" * 32,
                         noise_pubkey_hex: "bb" * 32, status: "enrolled")
    @zone.groups.create!(name: "ops", ns_name: "ops.groups.test.ztlp")
    gw = @zone.gateways.create!(name: "gw1", ns_name: "gw1.test.ztlp", kind: "rust_listen", status: "online")
    gw.services.create!(name: "blitz", backend: "http://10.0.0.1:8091")

    sign_in(@steve, @steve_seed)
    get root_path
    assert_response :success
    assert_includes response.body, "Overview"
    tally = response.body.scan(/tally-item/).size
    assert_operator tally, :>=, 4, "tally strip must cover users/devices/groups/services"
    assert_match %r{1</div>\s*<div class="tally-l">Users}, response.body
    assert_match %r{1</div>\s*<div class="tally-l">Devices}, response.body
    assert_match %r{1</div>\s*<div class="tally-l">Groups}, response.body
    assert_match %r{1</div>\s*<div class="tally-l">Services}, response.body
  end

  # --- Setup checklist: visibility matrix --------------------------------
  #
  # NOTE: the shared setup creates TWO admins (steve + readonly11), so the
  # "Add a second administrator" item is already done by the time any test in
  # this class runs. The test that wants to see it outstanding must drop the
  # second admin first (below).

  def make_zone_fully_done
    SystemSetting["breakglass_acknowledged_at"] = Time.current.iso8601
    @zone.update!(authority_seed_ct: "ab" * 32)
    @zone.update!(ns_admin_api_secret_ct: "s3cret")
  end

  test "checklist shows the outstanding items and hides done ones" do
    # Drop the second admin created by setup so "Add a second administrator"
    # is genuinely outstanding again (setup's readonly11 would otherwise mark
    # it done).
    @readonly.destroy!
    sign_in(@steve, @steve_seed)
    get root_path
    assert_response :success
    assert_includes response.body, "Setup checklist"
    assert_includes response.body, "Add a second administrator"
    assert_includes response.body, "acknowledge"
    assert_includes response.body, "authority"
    assert_includes response.body, "NS admin API secret"
  end

  test "checklist is hidden when every item is done" do
    make_zone_fully_done
    sign_in(@steve, @steve_seed)
    get root_path
    assert_response :success
    assert_not_includes response.body, "Setup checklist"
  end

  # spec Slice 11: the checklist only shows what is still missing (an all-done
  # zone has NO panel at all), plus the standing info line. So a done item is
  # pinned by ABSENCE; the info line is always present.
  test "second-administrator item is absent once two admins exist" do
    Admin.create!(username: "second", display_name: "Second",
                  pubkey_hex: Ztlp::Ed25519.generate.last, role: "admin")
    sign_in(@steve, @steve_seed)
    get root_path
    assert_not_includes response.body, "Add a second administrator"
    assert_includes response.body, "ZTLP_MIN_ASSURANCE", "the info line stays in the checklist"
  end

  # --- Break-glass acknowledge --------------------------------------------

  test "super admin can acknowledge break-glass; audit row written" do
    sign_in(@steve, @steve_seed)
    post setup_acknowledge_breakglass_path
    assert_redirected_to root_path
    assert_in_delta Time.current.to_f, Time.zone.parse(SystemSetting["breakglass_acknowledged_at"]).to_f, 5
    assert_equal @steve.id.to_s, SystemSetting["breakglass_acknowledged_by"]
    row = AuditLog.where(action: "system.breakglass_acknowledged").last
    assert row, "audit row system.breakglass_acknowledged expected"
    assert_equal "ok", row.status
    assert_equal @steve.id, row.admin_id
  end

  test "read_only admin cannot acknowledge break-glass (403, no timestamp)" do
    sign_in(@readonly, @readonly_seed)
    post setup_acknowledge_breakglass_path
    assert_response :forbidden
    assert_nil SystemSetting["breakglass_acknowledged_at"]
  end

  # Spec Slice 11: Admin.active.count >= 2 -- a disabled second admin is not a second key.
  test "a disabled second administrator does not satisfy the checklist" do
    @readonly.update!(disabled_at: Time.current) # 2 admins exist, only 1 active
    sign_in(@steve, @steve_seed)
    get root_path
    assert_select ".checklist-label", text: "Add a second administrator"
  end

  # The operator must be able to run (and check now) the exact command, not reconstruct it in a lockout.
  test "break-glass item shows the exact copyable reset_claim command" do
    sign_in(@steve, @steve_seed)
    get root_path
    cmd = "docker exec ztlp-admin-web /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim"
    assert_select "pre.code-box", text: cmd
    assert_select "button[data-act=copy][data-copy=?]", cmd
  end
end
