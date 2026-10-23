# frozen_string_literal: true

# Slice 9c sub-slice 1: the Policies page (read-only overview + Test access).
#
# GET /policies       index  every application (across the zone's gateways)
#                         with its rules (subject type, rendered literal)
#                         grouped under the application; per-application
#                         rendered policy code block with a copy button
#                         (data-act="copy", CSP-clean); "Test access" panel
#                         with device + application pickers (data-testid
#                         test-access-device / test-access-application) and
#                         a button that POSTs /policies/test (form with
#                         data-testid="test-access-form", no inline
#                         JS/script/style per the CSP rule).
#
# Read-only slice: no mutations, no Publisher calls. POST /policies/test +
# the decision rendering is sub-slice 2.
require "test_helper"

class PoliciesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "tech", status: "active")
    @eng = @zone.groups.create!(name: "eng", description: "Engineering")
    @eng.users << @alice
    @device = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "tpm",
                                    assurance: 3, status: "enrolled")
    @pending = @zone.devices.create!(name: "bob-pc", user: nil, status: "pending")

    @app = @gw.applications.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2)
    @app.policy_rules.create!(subject_type: "any", position: 0)
    @app.policy_rules.create!(subject_type: "group", subject_id: @eng.id,
                              subject_value: @eng.ns_name, position: 1)
    @off = @gw.applications.create!(name: "vault", enabled: false, backend: "10.42.42.200:3000")
    @elix = @gw_elixir.applications.create!(name: "dash", backend: "dash:3000")
  end

  test "index renders every application with its rules grouped under it" do
    get policies_path
    assert_response :success
    body = response.body

    assert_includes body, "comms-blitz"
    assert_includes body, "comms-blitz.test.ztlp"
    assert_includes body, "vault"
    assert_includes body, "dash"
    # rules render their subject type + literal
    assert_includes body, "any"
    assert_includes body, "group:eng.groups.test.ztlp"
    # disabled application is still listed (read-only overview)
    assert_includes body, "disabled"
  end

  test "index renders a rendered-policy code block per application with a copy button" do
    get policies_path
    assert_response :success
    body = response.body

    # the renderer's toml output is on the page, rendered HTML-escaped
    # (assertions here must pin the ESCAPED form — the raw text contains
    # no <script>, so escaping changes nothing semantically).
    assert_includes body, %(default = &quot;deny&quot;)
    assert_includes body, %(name = &quot;comms-blitz&quot;)
    assert_includes body, %(<pre class="code"><code>)
    # copy affordance is the CSP-clean data-act button (no inline script)
    assert_includes body, %(data-act="copy")
    assert_includes body, %(data-testid="policy-copy-comms-blitz")
  end

  test "index renders the test-access panel with device and application pickers" do
    get policies_path
    assert_response :success
    body = response.body

    assert_includes body, %(data-testid="test-access-device")
    assert_includes body, %(data-testid="test-access-application")
    assert_includes body, %(data-testid="test-access-form")
    assert_includes body, "alice-mbp"
    assert_includes body, "comms-blitz"
    # every device (incl. pending) and application (incl. disabled) is pickable
    assert_includes body, "bob-pc"
    assert_includes body, "vault"
  end

  test "index page has no inline script/style and no non-src scripts" do
    get policies_path
    assert_response :success
    assert_select "script:not([src])", false
  end

  test "read_only admin can view the page" do
    ro, ro_seed = make_admin(role: "read_only", username: "ro")
    sign_in_as(ro, ro_seed)
    get policies_path
    assert_response :success
  end
end
