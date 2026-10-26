# frozen_string_literal: true

# Slice 9b sub-slice 4: Policy-rule add/remove on the service show page.
#
# POST   /services/:id/rules      create   subject_type + optional subject_id /
#                                subject_value; position auto (count+1); audit
#                                rule.add; redirect back with notice (deploy
#                                hint). Invalid type, missing subject, or an
#                                unknown subject row (outside this zone)
#                                re-renders the show page with an error,
#                                nothing persisted.
# DELETE /services/:id/rules/:rid  remove   rule scoped to the service (and the
#                                zone via the service); audit rule.remove;
#                                redirect back with notice. Unknown rule ->
#                                404.
#
# Access: read_only admin gets 403 on both.
#
# Publishing: a rule change publishes NOTHING to the NS — the rendered policy
# is a gateway-side artifact the operator deploys at gateway restart (same
# contract as sub-slices 2/3).
require "test_helper"

class ServiceRulesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")
    @app = @gw.services.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2)

    @user = @zone.users.create!(username: "jane", display_name: "Jane", email: "",
                                role: "user", status: "active")
    @dev = @zone.devices.create!(name: "jane-mbp", status: "enrolled")
    @group = @zone.groups.create!(name: "techs", description: "Techs")
  end

  # -------------------------------------------------------------- add rules

  test "show page renders a rule form with every subject type" do
    get service_path(@app)
    assert_response :success
    body = response.body
    assert_includes body, "Add rule"
    assert_includes body, "subject_type"
    %w[group role user device any].each { |t| assert_includes body, ">#{t}<" }
  end

  # Ground truth (proto/src/policy.rs, gateway policy_engine.ex), see STATUS 2026-10-23 02:40Z.
  test "show page explains what each rule type can match on THIS gateway kind" do
    get service_path(@app) # rust_listen
    hint = css_select("[data-rule-hint]").text
    assert_match(/user rules never match/i, hint)
    assert_match(/group and role rules match through the device's owner/i, hint)
    refute_match(/group.{0,30}never match/i, response.body, "group rules DO work on rust_listen")

    elixir_app = @gw_elixir.services.create!(name: "portal", min_assurance: 1)
    get service_path(elixir_app)
    assert_match(/group, role and user rules never match a device/i, css_select("[data-rule-hint]").text)
  end

  test "add a group rule pins the group ns_name and renders the group literal" do
    post service_rules_path(@app), params: { subject_type: "group", subject_id: @group.id.to_s }
    assert_equal 1, @app.reload.policy_rules.count
    rule = @app.policy_rules.first
    assert_equal "group", rule.subject_type
    assert_equal @group.ns_name, rule.subject_value
    assert_equal "group:#{ @group.ns_name }", rule.render
    assert_equal 1, rule.position
    assert_audit("rule.add")
    follow_redirect!
    assert_includes response.body, rule.render
    assert_includes response.body, "Deploy the rendered policy"
  end

  test "add a role rule stores the role text as the subject" do
    post service_rules_path(@app), params: { subject_type: "role", subject_value: "tech" }
    rule = @app.policy_rules.first
    assert_equal "role", rule.subject_type
    assert_equal "tech", rule.subject_value
    assert_equal "role:tech", rule.render
    assert_audit("rule.add")
  end

  test "add a user rule pins the user ns_name" do
    post service_rules_path(@app), params: { subject_type: "user", subject_id: @user.id.to_s }
    rule = @app.policy_rules.first
    assert_equal @user.ns_name, rule.subject_value
    assert_equal @user.ns_name, rule.render
  end

  test "add a device rule pins the device ns_name" do
    post service_rules_path(@app), params: { subject_type: "device", subject_id: @dev.id.to_s }
    rule = @app.policy_rules.first
    assert_equal @dev.ns_name, rule.subject_value
    assert_equal @dev.ns_name, rule.render
  end

  test "add an any rule needs no subject" do
    post service_rules_path(@app), params: { subject_type: "any" }
    rule = @app.policy_rules.first
    assert_equal "any", rule.subject_type
    assert_equal "*", rule.render
    assert_audit("rule.add")
  end

  test "positions increment per service" do
    post service_rules_path(@app), params: { subject_type: "any" }
    post service_rules_path(@app), params: { subject_type: "role", subject_value: "tech" }
    positions = @app.policy_rules.order(:id).pluck(:position)
    assert_equal [ 1, 2 ], positions
  end

  test "add with an invalid subject type re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post service_rules_path(@app), params: { subject_type: "superuser", subject_value: "x" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "is unknown"
  end

  test "add a typed rule without a subject re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post service_rules_path(@app), params: { subject_type: "group" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "pick a subject"
  end

  test "add with a subject row that does not exist in this zone re-renders and persists nothing" do
    other_zone = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:9999")
    other_user = other_zone.users.create!(username: "mallory", display_name: "Mallory", email: "",
                                          role: "user", status: "active")
    assert_no_difference "PolicyRule.count" do
      post service_rules_path(@app), params: { subject_type: "user", subject_id: other_user.id.to_s }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "not found in this zone"
  end

  test "add with a blank role subject re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post service_rules_path(@app), params: { subject_type: "role", subject_value: "" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "pick a subject"
  end

  # -------------------------------------------------------------- remove rules

  test "remove a rule deletes only that rule and keeps the rest" do
    r1 = @app.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)
    r2 = @app.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 2)

    delete service_rule_path(@app, r1)
    # r1's literal is "*" (an any-rule); the row must carry the rule actually
    # removed (audit row is the latest rule.remove for this app).
    rule = AuditLog.where(action: "rule.remove").order(:id).last
    assert rule, "expected a rule.remove audit row, got: #{AuditLog.pluck(:action).inspect}"
    assert_equal "*", rule.details["rule"]
    assert_equal 1, @app.reload.policy_rules.count
    assert_equal "role", @app.policy_rules.first.subject_type
    follow_redirect!
    assert_includes response.body, "role:tech"
    assert_includes response.body, "Deploy the rendered policy"
  end

  test "removing a rule of another service 404s and leaves it" do
    other = @gw.services.create!(name: "other", backend: "10.0.0.5:80", min_assurance: 1)
    other_rule = other.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)

    assert_no_difference "PolicyRule.count" do
      delete service_rule_path(@app, other_rule)
    end
    assert_response :not_found
  end

  test "removing an unknown rule 404s" do
    delete service_rule_path(@app, 99_999)
    assert_response :not_found
  end

  # -------------------------------------------------------------- form wiring

  # The CSP is script-src 'self' / style-src 'self' with no nonce: a browser BLOCKS inline
  # <script> and style="" attributes. Tests cannot run the browser, so pin their absence.
  test "show page has no inline script or style attributes (blocked by the CSP)" do
    get service_path(@app)
    assert_select "script:not([src])", false
    assert_select "[style]", false
  end

  # Without JS the form must still be coherent: the initial type and the picker agree.
  test "rule form: initial type is group and the picker lists this zone's groups by id" do
    get service_path(@app)
    assert_select "form[action=?]", service_rules_path(@app) do
      assert_select "select[name=subject_type][data-rule-type] option[selected][value=group]"
      assert_select "select[name=subject_id][data-rule-pick] option[value=?]", @group.id.to_s, text: @group.name
      assert_select "select[name=subject_id] option[value=?]", @user.id.to_s, false
      assert_select "[data-rule-role-slot][hidden]"
    end
  end

  test "rule form: every option list rides as [label, id] pairs" do
    get service_path(@app)
    pick = css_select("select[data-rule-pick]").first
    assert_includes JSON.parse(pick["data-user-options"]), [ "Jane (jane)", @user.id ]
    assert_includes JSON.parse(pick["data-device-options"]), [ "jane-mbp", @dev.id ]
    assert_includes JSON.parse(pick["data-group-options"]), [ "techs", @group.id ]
  end

  test "a new rule after a removal never collides on position (unique index)" do
    r1 = @app.policy_rules.create!(subject_type: "any", position: 1)
    @app.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 2)
    r1.destroy!
    post service_rules_path(@app), params: { subject_type: "role", subject_value: "admin" }
    assert_redirected_to service_path(@app)
    assert_equal [ 2, 3 ], @app.reload.policy_rules.order(:position).pluck(:position)
  end

  test "a role rule must name a real role" do
    assert_no_difference -> { @app.policy_rules.count } do
      post service_rules_path(@app), params: { subject_type: "role", subject_value: "wizard" }
    end
    assert_response :unprocessable_content
  end

  # -------------------------------------------------------------- access control

  test "read_only admin gets 403 adding and removing rules" do
    ro, seed = make_admin(role: "read_only", username: "ro")
    sign_in_as(ro, seed)

    assert_no_difference "PolicyRule.count" do
      post service_rules_path(@app), params: { subject_type: "any" }
    end
    assert_response :forbidden

    rule = @app.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)
    assert_no_difference "PolicyRule.count" do
      delete service_rule_path(@app, rule)
    end
    assert_response :forbidden
  end

  private

  def get_and_body(path)
    get path
    assert_response :success
    response.body
  end

  # Nokogiri over the show page: return the doc and the rule form element.
  def parse_rule_form!(body)
    doc = Nokogiri::HTML(body)
    form = doc.at_css("form[action='#{ service_rules_path(@app) }']")
    raise "rule form not found" if form.nil?

    [ doc, form ]
  end

  def assert_audit(action)
    assert AuditLog.where(action: action).exists?
  end
end
