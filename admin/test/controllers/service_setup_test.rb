# frozen_string_literal: true

# Slice 4 of PLAN-services-wizard-and-helpdesk.md: the Add Service form.
#
# One page: the service's full name, the box it runs on, the backend, protocol, sign-in headers and
# a starting access rule; an Advanced section for every other `ztlp listen` parameter. Saving
# creates the gateway (planned), the service and the rule in one transaction, nothing is published
# anywhere and nothing runs on any box (the install script is slice 5).
require "test_helper"

class ServiceSetupTest < ActionDispatch::IntegrationTest
  setup do
    @zone = Zone.primary
    @zone.update!(ns_addr: "203.0.113.10:23096", relay_addrs: [ "203.0.113.10:23095" ])
    @staff = @zone.groups.create!(name: "staff")
    @alice = @zone.users.create!(username: "alice", display_name: "Alice", status: "active")
  end

  def as(role)
    admin, seed = make_admin(role: role, username: "#{role.tr('_', '-')}-1")
    sign_in_as(admin, seed)
  end

  def setup_params(**over)
    { fqdn: "www.#{@zone.name}", host_note: "ChooseForce box 10.42.42.112", backend: "172.20.0.2:80",
      protocol: "http", inject_headers: "1", access: "group", access_group_id: @staff.id }.merge(over)
  end

  test "the form shows every gateway parameter, advanced ones folded away" do
    as("admin")
    get new_service_path
    assert_response :success
    %w[fqdn host_note backend protocol inject_headers access access_group_id access_device_id access_role
       bind_port ns_server relay_addr max_sessions punch image_tag subject_map_text description].each do |f|
      assert_select "[name='setup[#{f}]']", { minimum: 1 }, "missing field #{f}"
    end
    assert_select "details summary", text: /Advanced/
    assert_select "a[href='#{new_service_path(existing: 1)}']", text: /existing gateway/
  end

  test "defaults: zone NS/relay, port 23097, 100 sessions, punching on, the pinned gateway image" do
    as("admin")
    get new_service_path
    assert_select "input[name='setup[bind_port]'][value='23097']"
    assert_select "input[name='setup[max_sessions]'][value='100']"
    assert_select "input[name='setup[punch]'][checked]"
    assert_select "input[name='setup[ns_server]'][placeholder='203.0.113.10:23096']"
    assert_select "input[name='setup[relay_addr]'][placeholder='203.0.113.10:23095']"
    assert_select "input[name='setup[image_tag]'][placeholder=?]", Gateway.default_image
  end

  test "creating a service creates its planned gateway, the service and the starting rule" do
    as("admin")
    assert_difference -> { Gateway.count } => 1, -> { Service.count } => 1, -> { PolicyRule.count } => 1 do
      post services_path, params: { setup: setup_params(bind_port: "23098", max_sessions: "50", punch: "0",
                                                        subject_map_text: "#{'ab' * 32}=steve\n") }
    end
    gw = @zone.gateways.find_by!(name: "www")
    svc = gw.services.find_by!(name: "www")
    assert_redirected_to service_path(svc)

    assert_equal "planned", gw.status
    assert_equal "rust_listen", gw.kind
    assert_equal "ChooseForce box 10.42.42.112", gw.host_note
    assert_equal 23_098, gw.bind_port
    assert_equal 50, gw.max_sessions
    assert_not gw.punch
    assert gw.inject_headers
    assert gw.policy_file, "a gateway created here runs with a policy file"
    assert_match(/\A\h{64}\z/, gw.header_secret_ct, "header secret generated (32 random bytes)")
    assert_equal [ "#{'ab' * 32}=steve" ], gw.subject_map

    assert_equal "172.20.0.2:80", svc.backend
    assert_equal "http", svc.protocol
    rule = svc.policy_rules.sole
    assert_equal [ "group", @staff.id ], [ rule.subject_type, rule.subject_id ]
    assert AuditLog.exists?(action: "service.setup", target_type: "Service", target_id: svc.id)
  end

  test "the header secret is never written to the audit log" do
    as("admin")
    post services_path, params: { setup: setup_params }
    secret = @zone.gateways.find_by!(name: "www").header_secret_ct
    assert AuditLog.all.none? { |l| l.details.to_json.include?(secret) }
  end

  test "access choices: nobody yet, everyone enrolled, a device, a role (no user rules: Rust gateways never match them)" do
    as("admin")
    post services_path, params: { setup: setup_params(fqdn: "a.#{@zone.name}", access: "none") }
    assert_empty Service.find_by!(name: "a").policy_rules
    post services_path, params: { setup: setup_params(fqdn: "b.#{@zone.name}", access: "any") }
    assert_equal "any", Service.find_by!(name: "b").policy_rules.sole.subject_type
    pc = @zone.devices.create!(name: "alice-pc", ns_name: "alice-pc.#{@zone.name}", status: "enrolled", user: @alice)
    post services_path, params: { setup: setup_params(fqdn: "c.#{@zone.name}", access: "device", access_device_id: pc.id) }
    assert_equal [ "device", pc.id ], Service.find_by!(name: "c").policy_rules.sole.then { |r| [ r.subject_type, r.subject_id ] }
    get new_service_path
    assert_select "input[name='setup[access]'][value='user']", false
    post services_path, params: { setup: setup_params(fqdn: "d.#{@zone.name}", access: "role", access_role: "tech") }
    assert_equal [ "role", "tech" ], Service.find_by!(name: "d").policy_rules.sole.then { |r| [ r.subject_type, r.subject_value ] }
  end

  test "tcp services carry no sign-in headers and no header secret" do
    as("admin")
    post services_path, params: { setup: setup_params(protocol: "tcp", inject_headers: "1") }
    gw = @zone.gateways.find_by!(name: "www")
    assert_not gw.inject_headers
    assert_nil gw.header_secret_ct
  end

  test "bad input re-renders with the values kept and nothing created" do
    as("admin")
    assert_no_difference [ "Gateway.count", "Service.count", "PolicyRule.count" ] do
      post services_path, params: { setup: setup_params(backend: "not a backend", bind_port: "99999") }
    end
    assert_response :unprocessable_content
    assert_select ".err", text: /host:port/
    assert_select ".err", text: /port/i
    assert_select "input[name='setup[host_note]'][value='ChooseForce box 10.42.42.112']"
  end

  test "names outside every zone, or more than one label deep, are refused" do
    as("admin")
    post services_path, params: { setup: setup_params(fqdn: "www.example.com") }
    assert_response :unprocessable_content
    assert_select ".err", text: /no zone/
    post services_path, params: { setup: setup_params(fqdn: "a.b.#{@zone.name}") }
    assert_select ".err", text: /one label/
  end

  test "an already-registered name points at the existing service instead of duplicating it" do
    as("admin")
    gw = @zone.gateways.create!(name: "www", kind: "rust_listen", status: "online")
    gw.services.create!(name: "www")
    assert_no_difference -> { Gateway.count } do
      post services_path, params: { setup: setup_params }
    end
    assert_select ".err", text: /already exists/
  end

  test "a malformed subject map line is refused" do
    as("admin")
    post services_path, params: { setup: setup_params(subject_map_text: "nothex=steve") }
    assert_response :unprocessable_content
    assert_select ".err", text: /subject map/i
  end

  test "the existing-gateway form is still there" do
    as("admin")
    gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "online")
    get new_service_path(existing: 1)
    assert_select "select[name='service[gateway_id]'] option[value='#{gw.id}']"
  end

  test "helpdesk cannot open or post the form" do
    as("helpdesk")
    get new_service_path
    assert_response :forbidden
    post services_path, params: { setup: setup_params }
    assert_response :forbidden
  end

  test "editing a service also edits its gateway's settings" do
    as("admin")
    post services_path, params: { setup: setup_params }
    svc = Service.find_by!(name: "www")
    patch service_path(svc), params: { service: { backend: "172.20.0.2:8080",
                                                  gateway_attributes: { id: svc.gateway.id, bind_port: "23099",
                                                                        host_note: "moved", punch: "0" } } }
    assert_redirected_to service_path(svc)
    svc.reload
    assert_equal "172.20.0.2:8080", svc.backend
    assert_equal 23_099, svc.gateway.bind_port
    assert_equal "moved", svc.gateway.host_note
    assert_not svc.gateway.punch
  end

  test "the services list has Add service" do
    as("admin")
    get services_path
    assert_select "a[href='#{new_service_path}']", text: /Add service/
  end

  test "the edit page carries the gateway settings" do
    as("admin")
    post services_path, params: { setup: setup_params }
    svc = Service.find_by!(name: "www")
    get edit_service_path(svc)
    %w[host_note bind_port max_sessions punch inject_headers policy_file ns_server relay_addr image_tag
       subject_map_text].each do |f|
      assert_select "[name='service[gateway_attributes][#{f}]']", { minimum: 1 }, "missing gateway field #{f}"
    end
  end

  test "turning sign-in headers on later generates the secret" do
    as("admin")
    post services_path, params: { setup: setup_params(inject_headers: "0") }
    svc = Service.find_by!(name: "www")
    assert_nil svc.gateway.header_secret_ct
    patch service_path(svc), params: { service: { gateway_attributes: { inject_headers: "1" } } }
    assert_match(/\A\h{64}\z/, svc.gateway.reload.header_secret_ct)
  end

  test "the service page shows the gateway settings and warns when there is no policy file" do
    as("admin")
    post services_path, params: { setup: setup_params(bind_port: "23098") }
    svc = Service.find_by!(name: "www")
    get service_path(svc)
    assert_select ".kv", text: /UDP port\s*23098/
    assert_select ".kv", text: /Sign-in headers\s*on \(audience www\)/
    assert_no_match(/runs without a policy file/, response.body)

    svc.gateway.update!(policy_file: false)
    get service_path(svc)
    assert_match(/runs without a policy file: every enrolled device/, response.body)
    svc.gateway.update!(policy_file: nil)
    get service_path(svc)
    assert_match(/not known whether this gateway runs with a policy file/, response.body)
  end
end
