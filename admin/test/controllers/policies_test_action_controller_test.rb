# frozen_string_literal: true

# Slice 9c sub-slice 2: POST /policies/test — the Test access widget's action.
#
# POST /policies/test {device_id, service_id}
#   - zone-scoped lookups (cross-zone/unknown ids -> 404, no leak)
#   - blank/missing params -> re-render the page with a flash, NO audit row
#   - runs Ztlp::AccessEvaluator.evaluate (device x service) and renders
#     the decision inline on the policies page: badge (allow/deny), reason,
#     per-rule trace table, warnings, the assurance-enforced note
#   - writes audit row policy.test (target = the service)
require "test_helper"

class PoliciesTestControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @other = Zone.create!(name: "other.zone", ns_addr: "127.0.0.1:23097")
    @other_gw = @other.gateways.create!(name: "gw-o", kind: "rust_listen", status: "planned")

    @alice = @zone.users.create!(username: "alice", display_name: "Alice Anderson",
                                 role: "tech", status: "active")
    @eng = @zone.groups.create!(name: "eng", description: "Engineering")
    @eng.users << @alice
    @device = @zone.devices.create!(name: "alice-mbp", user: @alice, node_id_hex: "ab" * 16,
                                    noise_pubkey_hex: "cd" * 32, key_source: "tpm",
                                    assurance: 3, status: "enrolled")
    @pending = @zone.devices.create!(name: "bob-pc", user: nil, status: "pending")

    @app = @gw.services.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2)
    @app.policy_rules.create!(subject_type: "group", subject_id: @eng.id,
                              subject_value: @eng.ns_name, position: 0)
    @open = @gw.services.create!(name: "open", backend: "10.0.0.1:80")
    @open.policy_rules.create!(subject_type: "any", position: 0)
    @off = @gw.services.create!(name: "vault", enabled: false, backend: "10.42.42.200:3000")
    @other_app = @other_gw.services.create!(name: "other-app", backend: "10.9.9.9:80")
  end

  test "POST test with device + service renders the allow decision inline" do
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id }
    assert_response :success
    body = response.body

    assert_includes body, %(data-testid="test-access-result")
    assert_includes body, "allow"
    assert_includes body, "Check access" # the form is still there after the check
    # trace: the any rule row with its result
    assert_includes body, "any"
    assert_includes body, %(data-testid="trace-rule-0")
  end

  test "POST test denies when the owner is disabled even if a group rule would allow" do
    @alice.update!(status: "disabled")
    post policies_test_path, params: { device_id: @device.id, service_id: @app.id }
    assert_response :success
    body = response.body

    assert_includes body, %(data-testid="test-access-result")
    assert_includes body, "deny"
    assert_includes body, "disabled"
  end

  test "POST test denies a pending device with the status reason" do
    post policies_test_path, params: { device_id: @pending.id, service_id: @open.id }
    assert_response :success
    body = response.body

    assert_includes body, "deny"
    assert_includes body, "pending"
    assert_includes body, %(data-testid="test-access-reason")
  end

  test "POST test denies a disabled service" do
    post policies_test_path, params: { device_id: @device.id, service_id: @off.id }
    assert_response :success
    body = response.body

    assert_includes body, "deny"
    assert_includes body, "disabled"
  end

  test "POST test renders the assurance warning when device assurance is below the minimum" do
    @open.update!(min_assurance: 4)
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id }
    assert_response :success
    body = response.body

    assert_includes body, %(data-testid="test-access-warnings")
    assert_includes body, "not enforced"
  end

  test "POST test with blank params re-renders the page with a flash and writes no audit row" do
    before = AuditLog.count
    post policies_test_path, params: { device_id: "", service_id: "" }
    assert_response :unprocessable_content

    assert_includes response.body, "Choose a device and a service"
    assert_select %(form[data-testid="test-access-form"])
    assert_equal before, AuditLog.count
  end

  test "POST test with an unknown device id returns 404" do
    post policies_test_path, params: { device_id: 99_999, service_id: @open.id }
    assert_response :not_found
  end

  test "POST test with a cross-zone service returns 404" do
    post policies_test_path, params: { device_id: @device.id, service_id: @other_app.id }
    assert_response :not_found
  end

  test "POST test writes an audit row policy.test targeting the service" do
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id }
    assert_response :success
    entry = AuditLog.where(action: "policy.test").last
    assert_equal "Service", entry.target_type
    assert_equal @open.id, entry.target_id
    assert_equal @admin.id, entry.admin_id
    assert_equal "alice-mbp", entry.details["device_name"]
    assert_equal "open", entry.details["service_name"]
    assert_equal "allow", entry.details["decision"]
  end

  test "POST test on the policies page keeps the test-access form rendered" do
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id }
    assert_response :success
    assert_select %(form[data-testid="test-access-form"])
    assert_select %(select[name="device_id"][data-testid="test-access-device"])
    assert_select %(select[name="service_id"][data-testid="test-access-service"])
  end

  test "POST test result page has no inline script" do
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id }
    assert_response :success
    assert_select "script:not([src])", false
  end

  # Slice 9c sub-slice 3: the directory.js widget posts JSON and gets the
  # decision back as JSON (no full-page re-render).
  test "POST test as JSON returns the decision JSON" do
    post policies_test_path, params: { device_id: @device.id, service_id: @open.id },
         as: :json
    assert_response :success
    assert_equal "application/json", response.media_type
    result = JSON.parse(response.body)
    assert_equal "allow", result["decision"]
    assert_kind_of Array, result["trace"]
    assert_equal "any", result["trace"].first["rule"]
  end

  test "POST test as JSON with a deny returns the deny decision" do
    post policies_test_path, params: { device_id: @pending.id, service_id: @open.id },
         as: :json
    assert_response :success
    result = JSON.parse(response.body)
    assert_equal "deny", result["decision"]
    assert_includes result["reason"], "pending"
  end

  test "POST test as JSON with blank params returns 422 JSON" do
    post policies_test_path, params: { device_id: "", service_id: "" }, as: :json
    assert_response :unprocessable_content
  end

  test "the policies page renders the test-access results box" do
    get policies_path
    assert_response :success
    assert_select %(div#test-access-results[data-testid="test-access-results"])
  end
end
