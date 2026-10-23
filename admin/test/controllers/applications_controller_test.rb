# frozen_string_literal: true

# Slice 9b sub-slice 2: Applications index + show/drawer (read side).
#
# GET /apps              index  one row per application (across the zone's
#                               gateways): name, ztlp name <name>.<zone>,
#                               gateway, backend, protocol, min assurance
#                               (rust_listen: "(not enforced by Rust
#                               gateways)"), rules count, enabled badge.
# GET /apps/:id          show   normal page or drawer fragment (X-Drawer: 1,
#                               same contract as users/groups show): about
#                               (description, backend, protocol, min
#                               assurance note), rules table with subject
#                               type/value, "Rendered policy" code block
#                               (PolicyRenderer output for the app's
#                               gateway) + restart note, empty state when
#                               the gateway has no enabled applications.
#
# Read-only slice: no Publisher calls. Mutations (new/create, edit/update,
# rule add/remove, enable/disable) are later 9b sub-slices.
require "test_helper"

class ApplicationsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")

    @app = @gw.applications.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2,
                                    description: "Blitz terminal")
    @app.policy_rules.create!(subject_type: "any", position: 0)
    @app.policy_rules.create!(subject_type: "group", subject_value: "eng.groups.test.ztlp",
                              subject_id: nil, position: 1)

    @off = @gw.applications.create!(name: "vault", enabled: false, backend: "10.42.42.200:3000")
    @elix = @gw_elixir.applications.create!(name: "dash", backend: "dash:3000")
  end

  # -------------------------------------------------------------- index

  test "index lists every application with ztlp name, gateway, backend, min assurance and rules count" do
    get applications_path
    assert_response :success
    body = response.body

    assert_includes body, "comms-blitz"
    assert_includes body, "comms-blitz.test.ztlp"
    assert_includes body, "gw1"
    assert_includes body, "10.42.42.112:5200"
    assert_includes body, "http"
    assert_includes body, "vault"
    assert_includes body, "dash"

    # rust_listen min assurance carries the not-enforced note
    assert_includes body, "(not enforced by Rust gateways)"

    # rules counts: comms-blitz 2, vault 0, dash 0
    blitz_row = Nokogiri::HTML.fragment(body).css("tr").find { |t| t.text.include?("comms-blitz") }
    assert_equal "2", blitz_row.at_css("td.row-rules").text
    vault_row = Nokogiri::HTML.fragment(body).css("tr").find { |t| t.text.include?("vault") }
    assert_equal "0", vault_row.at_css("td.row-rules").text
  end

  test "index shows enabled/disabled badges" do
    get applications_path
    body = response.body
    assert_includes body, "enabled"
    assert_includes body, "disabled"
  end

  test "index rows are drawer-linked" do
    get applications_path
    assert_select "tr[data-drawer=?]", application_path(@app)
  end

  test "index empty state" do
    Application.destroy_all
    get applications_path
    assert_response :success
    assert_includes response.body, "No applications yet"
  end

  # -------------------------------------------------------------- show

  test "show renders about, rules, rendered policy and the restart note" do
    get application_path(@app)
    assert_response :success
    body = response.body

    assert_includes body, "comms-blitz"
    assert_includes body, "comms-blitz.test.ztlp"
    assert_includes body, "Blitz terminal"
    assert_includes body, "10.42.42.112:5200"
    assert_includes body, "not enforced by Rust gateways"

    # rules table: both rules, in position order
    assert_includes body, "any"
    assert_includes body, "*"
    assert_includes body, "eng.groups.test.ztlp"

    # rendered policy = the gateway's TOML document from the renderer
    assert_select "pre.code code", text: /default = "deny"/ # decoded text, never raw markup
    assert_includes body, "Rule changes need a gateway restart"
    assert_includes body, "membership changes are live"
  end

  test "show drawer fragment renders under X-Drawer without layout" do
    get application_path(@app), headers: { "X-Drawer" => "1" }
    assert_response :success
    assert_includes response.body, "comms-blitz"
    assert_select "pre.code code", text: /default = "deny"/
    # drawer fragments do not carry the app layout chrome
    assert_not_includes response.body, '<div class="rail"'
  end

  test "show for an elixir gateway application renders the elixir env line" do
    get application_path(@elix)
    assert_response :success
    assert_includes response.body, "ZTLP_GATEWAY_POLICIES"
  end

  test "show for a disabled application shows the disabled badge" do
    get application_path(@off)
    assert_response :success
    assert_includes response.body, "disabled"
  end

  test "show empty rules state" do
    get application_path(@off)
    assert_response :success
    assert_includes response.body, "No rules yet"
  end

  # -------------------------------------------------------------- access

  test "unauthenticated request is redirected to sign in" do
    delete logout_path
    get applications_path
    assert_redirected_to login_path
  end

  test "the rendered policy is HTML-escaped (operator text is never markup)" do
    @gw.update_column(:name, "gw<b>x</b>")
    get application_path(@app)
    assert_response :success
    assert_select "pre.code b", false
    assert_includes response.body, "gw&lt;b&gt;x&lt;/b&gt;"
  end
end
