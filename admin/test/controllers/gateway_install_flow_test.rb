# frozen_string_literal: true

# Slice 5: show the install script once, check the gateway reached the name server.
#
# The script carries two secrets (zone relay secret, header secret), so:
#  - operators only (super_admin/admin), audited without the values, Cache-Control: no-store;
#  - viewable for 30 minutes after the first "Show install script"; after that, showing it again
#    means "Regenerate", which rotates the header secret (the app must get the new one too).
require "test_helper"

class GatewayInstallFlowTest < ActionDispatch::IntegrationTest
  RELAY = "relay-secret-NOT-hex_value"

  setup do
    @zone = Zone.primary
    @zone.update!(ns_addr: "203.0.113.10:23096", relay_addrs: [ "203.0.113.10:23095" ], relay_secret_ct: RELAY)
    @gw = @zone.gateways.create!(name: "www", kind: "rust_listen", status: "planned", inject_headers: true,
                                 header_secret_ct: "ab" * 32, policy_file: true)
    @svc = @gw.services.create!(name: "www", backend: "172.20.0.2:80", protocol: "http")
  end

  def as(role)
    admin, seed = make_admin(role: role, username: "#{role.tr('_', '-')}-1")
    sign_in_as(admin, seed)
  end

  test "the service page offers the install script and the checklist" do
    as("admin")
    get service_path(@svc)
    assert_select "form[action='#{install_script_service_path(@svc)}'] button", text: /Show install script/
    assert_select "form[action='#{check_gateway_service_path(@svc)}'] button", text: /Check now/
    assert_select "[data-install-checklist] li", minimum: 3
    assert_no_match(/#{RELAY}/, response.body)
    assert_no_match(/#{"ab" * 32}/, response.body)
  end

  test "showing the script returns it once with no-store, records when, audits without secrets" do
    as("admin")
    post install_script_service_path(@svc)
    assert_response :success
    assert_includes response.headers["Cache-Control"], "no-store"
    assert_includes response.body, RELAY
    assert_includes response.body, "ZTLP_GATEWAY_HEADER_SECRET=#{'ab' * 32}"
    assert_not_nil @gw.reload.install_shown_at
    log = AuditLog.find_by!(action: "gateway.install_shown")
    assert_not_includes log.details.to_json, RELAY
    assert_not_includes log.details.to_json, "ab" * 32
  end

  test "within 30 minutes it can be shown again with the same secret" do
    as("admin")
    post install_script_service_path(@svc)
    travel 10.minutes do
      post install_script_service_path(@svc)
      assert_response :success
      assert_includes response.body, "ab" * 32
    end
  end

  test "after 30 minutes it is refused unless regenerated, which rotates the header secret" do
    as("admin")
    post install_script_service_path(@svc)
    travel 31.minutes do
      post install_script_service_path(@svc)
      assert_redirected_to service_path(@svc)
      follow_redirect!
      assert_match(/Regenerate/, response.body)

      post install_script_service_path(@svc), params: { regenerate: "1" }
      assert_response :success
      new_secret = @gw.reload.header_secret_ct
      assert_not_equal "ab" * 32, new_secret
      assert_includes response.body, new_secret
      assert AuditLog.exists?(action: "gateway.install_regenerated")
      assert_match(/update the app/i, response.body)
    end
  end

  test "a missing relay secret explains what to do instead of a half-filled script" do
    @zone.update!(relay_secret_ct: nil)
    as("admin")
    post install_script_service_path(@svc)
    assert_redirected_to service_path(@svc)
    follow_redirect!
    assert_match(/relay secret is not set/, response.body)
    assert_nil @gw.reload.install_shown_at
  end

  test "helpdesk and read_only cannot see the script" do
    %w[helpdesk read_only].each do |role|
      reset!
      as(role)
      post install_script_service_path(@svc)
      assert_response :forbidden
    end
  end

  test "Check now marks the gateway online with what the name server says" do
    as("admin")
    record = { name: "www.#{@zone.name}", data: { "node_id" => "f2b7" * 8, "address" => "10.42.42.112:23097",
                                                    "addresses" => [ "10.42.42.112:23097" ] } }
    Ztlp::ServiceRegistrar.stubs(:lookup).returns(record)
    post check_gateway_service_path(@svc)
    assert_redirected_to service_path(@svc)
    @gw.reload
    assert_equal "online", @gw.status
    assert_equal "f2b7" * 8, @gw.node_id_hex
    assert_not_nil @gw.last_svc_seen_at
  end

  test "Check now leaves a planned gateway planned when it is not on the name server yet" do
    as("admin")
    Ztlp::ServiceRegistrar.stubs(:lookup).returns(nil)
    post check_gateway_service_path(@svc)
    assert_equal "planned", @gw.reload.status
    follow_redirect!
    assert_match(/not on the name server yet/, response.body)
  end

  test "an unreachable name server does not 500" do
    as("admin")
    Ztlp::ServiceRegistrar.stubs(:lookup).raises(Ztlp::NsClient::NsError.new(0x00, "timeout"))
    post check_gateway_service_path(@svc)
    assert_redirected_to service_path(@svc)
  end

  test "the status job checks every gateway; a gateway that disappears goes stale" do
    online = @zone.gateways.create!(name: "old", kind: "rust_listen", status: "online", last_svc_seen_at: 2.days.ago)
    Ztlp::ServiceRegistrar.stubs(:lookup).with { |fqdn, _z, **| fqdn == @gw.ns_name }.returns({ name: @gw.ns_name, data: { "node_id" => "aa" * 16 } })
    Ztlp::ServiceRegistrar.stubs(:lookup).with { |fqdn, _z, **| fqdn == online.ns_name }.returns(nil)
    GatewayStatusJob.perform_now
    assert_equal "online", @gw.reload.status
    assert_equal "stale", online.reload.status
  end
end
