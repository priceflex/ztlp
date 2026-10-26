# frozen_string_literal: true

# Slice 2 of PLAN-services-wizard-and-helpdesk.md: "Applications" became "Services".
# Old bookmarks keep working (301), the rail and the dashboard link to the real page
# (both used to point at /apps, which had no route).
require "test_helper"

class ServiceRenameTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary
    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @svc = @gw.services.create!(name: "blitz", backend: "127.0.0.1:5200", protocol: "http")
  end

  test "old /applications URLs redirect permanently to /services" do
    get "/applications"
    assert_response :moved_permanently
    assert_redirected_to "/services"

    get "/applications/#{@svc.id}"
    assert_response :moved_permanently
    assert_redirected_to "/services/#{@svc.id}"

    get "/applications/register"
    assert_redirected_to "/services/register"
  end

  test "the rail and the dashboard link to /services and say Services" do
    get root_path
    assert_select "a[href='/services']", minimum: 2
    assert_select "a[href='/apps']", false
    assert_select "nav a", text: /Applications/, count: 0
  end

  test "the services page and the gateway form render" do
    get services_path
    assert_response :success
    assert_select "h1", text: /Services/
    get new_gateway_path
    assert_response :success
    assert_equal "/gateways/new", new_gateway_path
  end

  test "a service keeps its rules under the new names" do
    rule = @svc.policy_rules.create!(subject_type: "any", position: 0)
    assert_equal @svc, rule.service
    assert_equal [ rule ], @svc.reload.policy_rules.to_a
  end

  test "old audit rows written against Application resolve to Service after the migration" do
    log = AuditLog.create!(action: "application.create", target_type: "Service", target_id: @svc.id)
    assert_equal @svc, Service.find(log.target_id)
  end
end
