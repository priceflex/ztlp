# frozen_string_literal: true

# Slice 9b sub-slice 4: Policy-rule add/remove on the application show page.
#
# POST   /apps/:id/rules      create   subject_type + optional subject_id /
#                                subject_value; position auto (count+1); audit
#                                rule.add; redirect back with notice (deploy
#                                hint). Invalid type, missing subject, or an
#                                unknown subject row (outside this zone)
#                                re-renders the show page with an error,
#                                nothing persisted.
# DELETE /apps/:id/rules/:rid  remove   rule scoped to the application (and the
#                                zone via the application); audit rule.remove;
#                                redirect back with notice. Unknown rule ->
#                                404.
#
# Access: read_only admin gets 403 on both.
#
# Publishing: a rule change publishes NOTHING to the NS — the rendered policy
# is a gateway-side artifact the operator deploys at gateway restart (same
# contract as sub-slices 2/3).
require "test_helper"

class ApplicationRulesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @admin, @seed = make_admin
    sign_in_as(@admin, @seed)
    @zone = Zone.primary

    @gw = @zone.gateways.create!(name: "gw1", kind: "rust_listen", status: "planned")
    @gw_elixir = @zone.gateways.create!(name: "gw-e", kind: "elixir", status: "planned")
    @app = @gw.applications.create!(name: "comms-blitz", backend: "10.42.42.112:5200",
                                    protocol: "http", min_assurance: 2)

    @user = @zone.users.create!(username: "jane", display_name: "Jane", email: "",
                                role: "user", status: "active")
    @dev = @zone.devices.create!(name: "jane-mbp", status: "enrolled")
    @group = @zone.groups.create!(name: "techs", description: "Techs")
  end

  # -------------------------------------------------------------- add rules

  test "show page renders a rule form with every subject type" do
    get application_path(@app)
    assert_response :success
    body = response.body
    assert_includes body, "Add rule"
    assert_includes body, "subject_type"
    %w[group role user device any].each { |t| assert_includes body, ">#{t}<" }
  end

  test "show page explains the gateway semantics of each rule type" do
    # rust_listen page: the elixir note is NOT present (wrong gateway), but the
    # per-kind hint for rust_listen is.
    get application_path(@app)
    assert_response :success
    body = response.body
    assert_includes body, "user, device and group rules never match a device"
    refute_includes body, "On this elixir gateway"

    # elixir page: the elixir note IS present (table note + form hint).
    elixir_app = @gw_elixir.applications.create!(name: "portal", min_assurance: 1)
    get application_path(elixir_app)
    assert_response :success
    assert_includes response.body, "group, role and user rules never match a device"
  end

  test "add a group rule pins the group ns_name and renders the group literal" do
    post application_rules_path(@app), params: { subject_type: "group", subject_id: @group.id.to_s }
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
    post application_rules_path(@app), params: { subject_type: "role", subject_value: "tech" }
    rule = @app.policy_rules.first
    assert_equal "role", rule.subject_type
    assert_equal "tech", rule.subject_value
    assert_equal "role:tech", rule.render
    assert_audit("rule.add")
  end

  test "add a user rule pins the user ns_name" do
    post application_rules_path(@app), params: { subject_type: "user", subject_id: @user.id.to_s }
    rule = @app.policy_rules.first
    assert_equal @user.ns_name, rule.subject_value
    assert_equal @user.ns_name, rule.render
  end

  test "add a device rule pins the device ns_name" do
    post application_rules_path(@app), params: { subject_type: "device", subject_id: @dev.id.to_s }
    rule = @app.policy_rules.first
    assert_equal @dev.ns_name, rule.subject_value
    assert_equal @dev.ns_name, rule.render
  end

  test "add an any rule needs no subject" do
    post application_rules_path(@app), params: { subject_type: "any" }
    rule = @app.policy_rules.first
    assert_equal "any", rule.subject_type
    assert_equal "*", rule.render
    assert_audit("rule.add")
  end

  test "positions increment per application" do
    post application_rules_path(@app), params: { subject_type: "any" }
    post application_rules_path(@app), params: { subject_type: "role", subject_value: "tech" }
    positions = @app.policy_rules.order(:id).pluck(:position)
    assert_equal [ 1, 2 ], positions
  end

  test "add with an invalid subject type re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post application_rules_path(@app), params: { subject_type: "superuser", subject_value: "x" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "is unknown"
  end

  test "add a typed rule without a subject re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post application_rules_path(@app), params: { subject_type: "group" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "pick a subject"
  end

  test "add with a subject row that does not exist in this zone re-renders and persists nothing" do
    other_zone = Zone.create!(name: "other.ztlp", ns_addr: "127.0.0.1:9999")
    other_user = other_zone.users.create!(username: "mallory", display_name: "Mallory", email: "",
                                          role: "user", status: "active")
    assert_no_difference "PolicyRule.count" do
      post application_rules_path(@app), params: { subject_type: "user", subject_id: other_user.id.to_s }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "not found in this zone"
  end

  test "add with a blank role subject re-renders and persists nothing" do
    assert_no_difference "PolicyRule.count" do
      post application_rules_path(@app), params: { subject_type: "role", subject_value: "" }
    end
    assert_response :unprocessable_content
    assert_includes response.body, "pick a subject"
  end

  # -------------------------------------------------------------- remove rules

  test "remove a rule deletes only that rule and keeps the rest" do
    r1 = @app.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)
    r2 = @app.policy_rules.create!(subject_type: "role", subject_value: "tech", position: 2)

    delete application_rule_path(@app, r1)
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

  test "removing a rule of another application 404s and leaves it" do
    other = @gw.applications.create!(name: "other", backend: "10.0.0.5:80", min_assurance: 1)
    other_rule = other.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)

    assert_no_difference "PolicyRule.count" do
      delete application_rule_path(@app, other_rule)
    end
    assert_response :not_found
  end

  test "removing an unknown rule 404s" do
    delete application_rule_path(@app, 99_999)
    assert_response :not_found
  end

  # -------------------------------------------------------------- form wiring

  test "show page carries the rule form with zone-scoped subject options" do
    page = get_and_body(application_path(@app))
    doc, form = parse_rule_form!(page)

    # all five subject types are options
    assert_equal PolicyRule::SUBJECT_TYPES, form.css("select[name=subject_type] option").map { |o| o[:value] }

    # the pick select is seeded with the zone's users
    pick = form.at_css("span#rule-pick-slot select[name=subject_id]")
    raise "user pick missing" if pick.nil?
    assert_includes pick.css("option").map { |o| o[:value] }, @user.id.to_s

    # device and group option lists ride as data-attrs (JS swaps them in)
    device_opts = JSON.parse(pick.attr("data-device-options").to_s)
    group_opts = JSON.parse(pick.attr("data-group-options").to_s)
    assert_includes device_opts.map(&:first), @dev.name
    assert_includes group_opts.map(&:first), @group.name

    # initial state: role slot hidden, pick slot visible (user type).
    # Nokogiri returns "" for a valueless HTML5 attribute like `hidden`, so
    # check presence with `!nil?` — not `.present?` (empty string is falsy).
    assert pick[:hidden].nil?
    role_slot = form.at_css("span#rule-role-slot")
    raise "role slot missing" if role_slot.nil?
    assert role_slot[:hidden] != nil, "role slot should be hidden initially"

    # the swap script is present and names both slots + the type select
    script = doc.search("script").map(&:text).find { |s| s.include?("subject_type") }
    raise "swap script missing" if script.nil?
    %w[rule-pick-slot rule-role-slot optionsFor].each do |needle|
      assert_includes script, needle
    end
  end

  # -------------------------------------------------------------- access control

  test "read_only admin gets 403 adding and removing rules" do
    ro, seed = make_admin(role: "read_only", username: "ro")
    sign_in_as(ro, seed)

    assert_no_difference "PolicyRule.count" do
      post application_rules_path(@app), params: { subject_type: "any" }
    end
    assert_response :forbidden

    rule = @app.policy_rules.create!(subject_type: "any", subject_value: nil, position: 1)
    assert_no_difference "PolicyRule.count" do
      delete application_rule_path(@app, rule)
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
    form = doc.at_css("form[action='#{ application_rules_path(@app) }']")
    raise "rule form not found" if form.nil?

    [ doc, form ]
  end

  def assert_audit(action)
    assert AuditLog.where(action: action).exists?
  end
end
