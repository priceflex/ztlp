# frozen_string_literal: true

require "test_helper"

# Phase B of docs/admin-panel/PLAN-multizone-and-app-registration.md: register a service by
# its full name (www.chooseforce.ztlp). The panel finds the zone from the name, looks the service up
# on the NS (SVC record via the admin API), and creates the gateway + service in one step.
# READ-ONLY toward the NS: nothing is ever published by registering.
class ServiceRegistrationTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @home = Zone.primary
    @home.update!(ns_admin_api_secret_ct: "ab" * 32)
    @cf = Zone.create!(name: "cf.test", ns_addr: "203.0.113.9:23096")
    @svc = { name: "www.cf.test", type: "svc", created_at: Time.now.to_i - 3600, ttl: 86_400,
             data: { "address" => "10.42.42.112:23097", "addresses" => "10.42.42.112:23097,44.227.148.151:23095",
                     "node_id" => "f2" * 16, "registered_by" => "e8" * 32, "zone" => "cf.test" } }
    @blitz = { name: "blitz.#{@home.name}", type: "svc", created_at: Time.now.to_i - 60, ttl: 86_400,
               data: { "address" => "10.69.95.12:23097", "node_id" => "d0" * 16, "zone" => @home.name } }
    Ztlp::NsClient.stubs(:list).with { |_p, _s, **kw| kw[:type] == "svc" && kw[:zone] == "cf.test" }.returns([ @svc ])
    Ztlp::NsClient.stubs(:list).with { |_p, _s, **kw| kw[:type] == "svc" && kw[:zone] == @home.name }.returns([ @blitz ])
    Ztlp::Publisher.expects(:publish_user!).never
    Ztlp::Publisher.expects(:publish_device!).never
    Ztlp::Publisher.expects(:publish_group!).never
  end

  test "zone_for picks the longest configured zone suffix and never matches a partial label" do
    deep = Zone.create!(name: "a.cf.test", ns_addr: "203.0.113.9:23096")
    assert_equal @cf, Ztlp::ServiceRegistrar.zone_for("www.cf.test")
    assert_equal deep, Ztlp::ServiceRegistrar.zone_for("www.a.cf.test")
    assert_nil Ztlp::ServiceRegistrar.zone_for("www.evilcf.test")
    assert_nil Ztlp::ServiceRegistrar.zone_for("cf.test"), "the zone itself is not a service"
  end

  test "the register page lists services discovered on the NS that are not registered yet" do
    get "/services/register"
    assert_response :success
    assert_select "form[action=?][method=get] input[name=fqdn]", "/services/register"
    assert_select "[data-discovered]", text: /www\.cf\.test/
    assert_select "[data-discovered]", text: /blitz\.#{Regexp.escape(@home.name)}/
  end

  test "looking up a running service shows its gateway facts and a one-click register button" do
    get "/services/register", params: { fqdn: "www.cf.test" }
    assert_response :success
    assert_match "10.42.42.112:23097", response.body
    assert_match "f2" * 16, response.body
    assert_select "form[action=?][method=post] input[name=fqdn][value=?]", "/services/register", "www.cf.test"
  end

  test "registering a running service creates the gateway and the service in that zone" do
    post "/services/register", params: { fqdn: "www.cf.test" }
    gw = @cf.gateways.find_by!(name: "www")
    assert_equal "www.cf.test", gw.ns_name
    assert_equal "registered", gw.status
    assert_equal "f2" * 16, gw.node_id_hex
    assert_equal %w[10.42.42.112:23097 44.227.148.151:23095], gw.addresses
    app = gw.services.find_by!(name: "www")
    assert_equal "www.cf.test", app.ztlp_name
    assert_redirected_to "/services/#{app.id}"
    assert AuditLog.exists?(action: "service.register", target_id: app.id)
  end

  test "registering switches the admin to the service's zone so the result page shows it" do
    post "/services/register", params: { fqdn: "www.cf.test" }
    follow_redirect!
    assert_response :success
    assert_select ".brand-zone", "cf.test"
  end

  test "registering twice is idempotent" do
    post "/services/register", params: { fqdn: "www.cf.test" }
    assert_no_difference -> { Gateway.count + Service.count } do
      post "/services/register", params: { fqdn: "www.cf.test" }
    end
    assert_redirected_to "/services/#{Service.find_by!(name: 'www').id}"
  end

  test "a registered service no longer appears as discovered" do
    post "/services/register", params: { fqdn: "www.cf.test" }
    get "/services/register"
    assert_select "[data-discovered]", text: /www\.cf\.test/, count: 0
  end

  test "a service not on the NS: shows the exact gateway command, and registers as planned with a backend" do
    get "/services/register", params: { fqdn: "shop.cf.test" }
    assert_response :success
    assert_match(/not on the name server/i, response.body)
    assert_select "input[name=backend]"

    post "/services/register", params: { fqdn: "shop.cf.test", backend: "10.0.0.5:8080" }
    gw = @cf.gateways.find_by!(name: "shop")
    assert_equal "planned", gw.status
    app = gw.services.find_by!(name: "shop")
    assert_equal "10.0.0.5:8080", app.backend
    follow_redirect!
    # The printed command became the gateway install panel (slice 5): the script itself, with its
    # secrets, only appears in the POST response of "Show install script".
    assert_select "[data-install-panel]"
    assert_match "/opt/ztlp-gateway-shop-cf-test", response.body
    assert_match "the cf.test relay secret is not set in the panel", response.body
    assert_select "form[action='/services/#{app.id}/install_script']", false, "no script without the relay secret"
  end

  test "a name in no configured zone says so and offers Add zone (super admin)" do
    get "/services/register", params: { fqdn: "www.unknown.test" }
    assert_response :success
    assert_match(/no zone/i, response.body)
    assert_select "a[href=?]", "/zones/new"
  end

  test "multi-label service names are refused (the gateway name is one DNS label)" do
    post "/services/register", params: { fqdn: "a.b.cf.test" }
    assert_response :unprocessable_content
    assert_equal 0, @cf.gateways.count
  end

  test "a bad backend is refused and nothing is created" do
    post "/services/register", params: { fqdn: "shop.cf.test", backend: "10.0.0.5 ; rm -rf" }
    assert_response :unprocessable_content
    assert_equal 0, @cf.gateways.count
  end

  test "read_only admins can look but not register" do
    ro, ro_seed = make_admin(role: "read_only", username: "readonly-reg")
    delete logout_path
    sign_in_as(ro, ro_seed)
    get "/services/register", params: { fqdn: "www.cf.test" }
    assert_response :success
    post "/services/register", params: { fqdn: "www.cf.test" }
    assert_response :forbidden
  end

  test "the services index links to Register service" do
    get "/services"
    assert_select "a.btn[href=?]", "/services/register"
  end
end
